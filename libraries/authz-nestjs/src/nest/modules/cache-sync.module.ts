import { Module, OnApplicationBootstrap, OnModuleDestroy, Injectable } from "@nestjs/common";
import { HttpRoleServiceClient } from "../../role-service-client/client";
import { DiskCache } from "../../cache-sync/disk";
import { KafkaCacheEventHandler } from "../../cache-sync/kafka";
import { CacheBootstrap } from "../../cache-sync/bootstrap";
import { PermissionCache } from "../../permission-cache/cache";
import { Metrics, METRIC } from "../../observability/metrics";
import { CreateAuthzOptions } from "../../bootstrap/create-authz";
import {
  AUTHZ_OPTIONS, AUTHZ_CACHE, AUTHZ_METRICS, AUTHZ_BOOTSTRAP,
} from "../authz-options";

/** Runs the startup state machine after the DI graph is built, and stops it on shutdown. */
@Injectable()
export class CacheSyncLifecycle implements OnApplicationBootstrap, OnModuleDestroy {
  private boot: CacheBootstrap | null = null;
  private opts: CreateAuthzOptions | null = null;

  static wire(instance: CacheSyncLifecycle, boot: CacheBootstrap | null, opts: CreateAuthzOptions): void {
    instance.boot = boot;
    instance.opts = opts;
  }

  async onApplicationBootstrap(): Promise<void> {
    if (!this.boot) return;
    await this.boot.start();
    this.boot.startSeedRetry();
    this.boot.startReconciler(this.opts?.reconcileIntervalMs ?? 300000);
  }
  async onModuleDestroy(): Promise<void> {
    this.boot?.stop();
  }
}

@Module({
  providers: [
    {
      provide: AUTHZ_BOOTSTRAP,
      useFactory: (opts: CreateAuthzOptions, cache: PermissionCache, metrics: Metrics): CacheBootstrap | null => {
        const enabled = Boolean(opts.userIssuer || opts.userJwksUri || opts.audience || opts.roleServiceUrl);
        if (!enabled) return null; // SERVICE-ONLY mode
        const events = opts.kafkaBrokers?.length
          ? new KafkaCacheEventHandler({
              brokers: opts.kafkaBrokers, updatesTopic: opts.roleUpdatesTopic,
              deleteTopic: opts.roleDeleteTopic, publishTopic: opts.publishRolesTopic,
              groupId: opts.kafkaGroupId, clientId: opts.kafkaClientId,
              logger: { warn: (m) => console.warn(m) },
              onSkippedEvent: () => metrics.inc(METRIC.roleEventSkipped),
            })
          : undefined;
        return new CacheBootstrap(
          cache,
          new HttpRoleServiceClient({
            baseUrl: opts.roleServiceUrl!,
            connectTimeoutMs: opts.roleServiceConnectTimeout ?? 5000,
            readTimeoutMs: opts.roleServiceReadTimeout ?? 5000,
          }),
          new DiskCache(opts.diskCachePath ?? "authorization-cache.json"),
          events,
          { metrics, logger: { warn: (m) => console.warn(m) } },
        );
      },
      inject: [AUTHZ_OPTIONS, AUTHZ_CACHE, AUTHZ_METRICS],
    },
    {
      provide: CacheSyncLifecycle,
      useFactory: (boot: CacheBootstrap | null, opts: CreateAuthzOptions): CacheSyncLifecycle => {
        const lifecycle = new CacheSyncLifecycle();
        CacheSyncLifecycle.wire(lifecycle, boot, opts);
        return lifecycle;
      },
      inject: [AUTHZ_BOOTSTRAP, AUTHZ_OPTIONS],
    },
  ],
  exports: [AUTHZ_BOOTSTRAP, CacheSyncLifecycle],
})
export class CacheSyncModule {}
