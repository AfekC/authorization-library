import { Module, OnApplicationBootstrap, OnModuleDestroy, Injectable } from "@nestjs/common";
import { HttpRoleServiceClient } from "../../role-service-client/client.js";
import { DiskCache } from "../../cache-sync/disk.js";
import { CacheBootstrap } from "../../cache-sync/bootstrap.js";
import { RoleEventsController } from "../../cache-sync/role-events.controller.js";
import { PermissionCache } from "../../permission-cache/cache.js";
import { Metrics } from "../../observability/metrics.js";
import { CreateAuthzOptions } from "../../bootstrap/create-authz.js";
import {
  AUTHZ_OPTIONS, AUTHZ_CACHE, AUTHZ_METRICS, AUTHZ_BOOTSTRAP,
} from "../authz-options.js";

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
  controllers: [RoleEventsController],
  providers: [
    {
      provide: AUTHZ_BOOTSTRAP,
      useFactory: (opts: CreateAuthzOptions, cache: PermissionCache, metrics: Metrics): CacheBootstrap | null => {
        const enabled = Boolean(opts.userIssuer || opts.userJwksUri || opts.audience || opts.roleServiceUrl);
        if (!enabled) return null; // SERVICE-ONLY mode
        return new CacheBootstrap(
          cache,
          new HttpRoleServiceClient({
            baseUrl: opts.roleServiceUrl!,
            connectTimeoutMs: opts.roleServiceConnectTimeout ?? 5000,
            readTimeoutMs: opts.roleServiceReadTimeout ?? 5000,
          }),
          new DiskCache(opts.diskCachePath ?? "authorization-cache.json"),
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
