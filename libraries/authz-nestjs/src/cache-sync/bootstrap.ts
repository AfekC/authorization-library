import { PermissionCache } from "../permission-cache/cache";
import { CacheEventHandler, RoleServiceClient } from "../spi";
import { Metrics, METRIC, GAUGE } from "../observability/metrics";
import { DiskCache } from "./disk";
import { applyRoleEvent } from "./events";

/** Log and metric a disk write failure; must not throw. */
function handleDiskWriteError(
  err: Error,
  deps: { metrics?: Metrics; logger?: { warn: (msg: string) => void } },
): void {
  deps.metrics?.inc(METRIC.diskCacheWriteFailures);
  deps.logger?.warn(`disk cache write failed: ${err.message}`);
}

/** Thrown at startup when there is no usable role state to serve. */
export class CacheBootstrapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CacheBootstrapError";
    Object.setPrototypeOf(this, CacheBootstrapError.prototype);
  }
}

export type CacheMode = "normal" | "seed";

export interface BootstrapResult {
  cache: PermissionCache;
  mode: CacheMode;
}

export interface CacheBootstrapDeps {
  metrics?: Metrics;
  logger?: { warn: (msg: string) => void };
}

/**
 * Startup state machine for the permission cache (architecture §8):
 *  - try Role Service -> atomic replace + write disk + (subscribe Kafka) -> normal
 *  - on failure -> seed from disk -> READY in seed mode -> reconciler retries
 * A periodic reconciler (startReconciler) promotes seed->normal and re-fetches
 * the full snapshot each cycle, catching any missed Kafka events.
 */
export class CacheBootstrap {
  private mode: CacheMode = "seed";
  private stopped = false;
  private reconcilerTimer: ReturnType<typeof setTimeout> | null = null;
  private lastSyncAt: Date | null = null;
  private kafkaConnected = false;
  /**
   * N6/L2: Single promise chain that serializes every apply (role-event upsert/delete)
   * and every forcedRefresh so they never interleave. An upsert enqueued after a
   * publish-roles trigger will always execute AFTER the refresh completes, and the
   * chain's `.catch()` swallows any rejection that escapes forcedRefresh's own guard.
   */
  private applyChain: Promise<void> = Promise.resolve();

  constructor(
    private readonly cache: PermissionCache,
    private readonly roleService: RoleServiceClient,
    private readonly disk: DiskCache,
    private readonly events?: CacheEventHandler,
    private readonly deps: CacheBootstrapDeps = {},
  ) {}

  mode_(): CacheMode {
    return this.mode;
  }

  roleServiceLastSync(): Date | null {
    return this.lastSyncAt;
  }

  isKafkaConnected(): boolean {
    return this.kafkaConnected;
  }

  /** Run startup sync; returns the cache + the mode it settled into. */
  async start(): Promise<BootstrapResult> {
    try {
      await this.fullSync();
      this.mode = "normal";
    } catch (roleServiceErr) {
      this.deps.logger?.warn(
        `authz startup snapshot fetch failed: ${roleServiceErr instanceof Error ? roleServiceErr.message : String(roleServiceErr)}`,
      );
      if (roleServiceErr instanceof Error) {
        console.warn(roleServiceErr.stack);
      }
      const seed = this.disk.read();
      if (!seed || Object.keys(seed.roles).length === 0) {
        throw new CacheBootstrapError(
          "authz startup failed: Role Service unreachable and disk cache is missing/empty",
        );
      }
      await this.cache.replaceAll(seed.roles);
      this.mode = "seed";
    }
    this.updateGauges();
    await this.subscribe();
    return { cache: this.cache, mode: this.mode };
  }

  /** Fetch the authoritative snapshot (bare role map), swap + persist. */
  private async fullSync(): Promise<void> {
    const roles = await this.roleService.fetchSnapshot();
    await this.cache.replaceAll(roles);
    const writeErr = this.disk.write(this.cache);
    if (writeErr) handleDiskWriteError(writeErr, this.deps);
    this.lastSyncAt = new Date();
  }

  private async subscribe(): Promise<void> {
    if (!this.events) return;
    // Fail-open at startup: a broker that is unreachable now must not abort
    // startup — the cache is already serving from the snapshot/seed, and the
    // reconciler heals any events missed while Kafka is down (§8.4). Mirrors
    // the Spring container, whose start() is non-blocking.
    try {
      await this.events.start(
        (event) => {
          // N6: Enqueue through the serial chain so apply and forcedRefresh
          // never interleave. An upsert that arrives while a refresh is in
          // flight will wait for the refresh to complete before being applied.
          this.applyChain = this.applyChain.then(async () => {
            const result = await applyRoleEvent(this.cache, event);
            if (result.applied) {
              const writeErr = this.disk.write(this.cache);
              if (writeErr) handleDiskWriteError(writeErr, this.deps);
              this.updateGauges();
            } else {
              this.deps.metrics?.inc(METRIC.roleEventSkipped);
              this.deps.logger?.warn(`role event skipped: ${result.reason}`);
            }
          }).catch((e) => {
            this.deps.logger?.warn(
              `role event apply failed: ${e instanceof Error ? e.message : String(e)}`,
            );
          });
        },
        () => {
          // N6/L2: Enqueue forcedRefresh through the same chain so it is
          // serialized against apply(). The outer .catch() provides an
          // additional safety net on top of forcedRefresh's internal guard.
          this.applyChain = this.applyChain.then(() => this.forcedRefresh()).catch((e) => {
            this.deps.logger?.warn(
              `forced refresh chain error: ${e instanceof Error ? e.message : String(e)}`,
            );
          });
        },
      );
      this.kafkaConnected = true;
    } catch (e) {
      this.kafkaConnected = false;
      this.deps.logger?.warn(
        `Kafka subscribe failed at startup; continuing without live events: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
  }

  /**
   * Forced full re-fetch (triggered by a `publish-roles` message). Re-fetches the
   * snapshot, replaces the cache, and rewrites disk. Fail-open: on error the
   * current cache is kept and `role_refresh_failures_total` is incremented.
   */
  async forcedRefresh(): Promise<void> {
    if (this.stopped) return;
    try {
      await this.fullSync();
      this.updateGauges();
    } catch (e) {
      this.deps.metrics?.inc(METRIC.roleRefreshFailures);
      this.deps.logger?.warn(
        `forced refresh failed: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
  }

  /**
   * Periodic reconciler (§8.3): each cycle re-fetches the full snapshot and
   * replaces the cache, promoting seed->normal once the Role Service is
   * reachable. Since the snapshot has no version, the unconditional re-fetch is
   * what catches any missed/out-of-order Kafka events. Safe to call after start.
   */
  startReconciler(intervalMs = 5000): void {
    const loop = async () => {
      while (!this.stopped) {
        // B11: Track the pending timer so stop() can clear it immediately,
        // mirroring Java's thread.interrupt() which wakes from sleep at once.
        await new Promise<void>((r) => {
          const t = setTimeout(r, intervalMs);
          this.reconcilerTimer = t;
          if (typeof t.unref === "function") t.unref();
        });
        this.reconcilerTimer = null;
        if (this.stopped) break;
        try {
          await this.fullSync();
          if (this.mode === "seed") this.mode = "normal";
          this.updateGauges();
        } catch {
          this.deps.metrics?.inc(METRIC.roleRefreshFailures);
          this.deps.logger?.warn('authz reconciler snapshot fetch failed; keeping current cache');
          // keep current cache; try again next cycle (fail-open)
        }
      }
    };
    void loop();
  }

  private updateGauges(): void {
    this.deps.metrics?.setGauge(GAUGE.cacheVersion, this.cache.version());
    this.deps.metrics?.setGauge(
      GAUGE.cacheAgeSeconds,
      Math.max(0, Math.floor((Date.now() - this.cache.lastUpdatedAt().getTime()) / 1000)),
    );
  }

  /** Stop the reconciler loop (e.g. on shutdown). */
  stop(): void {
    this.stopped = true;
    // B11: Clear the pending timer so the loop wakes immediately and exits,
    // rather than firing once more after the current interval elapses.
    // Mirrors Java's reconciler.interrupt() semantics.
    if (this.reconcilerTimer !== null) {
      clearTimeout(this.reconcilerTimer);
      this.reconcilerTimer = null;
    }
  }
}
