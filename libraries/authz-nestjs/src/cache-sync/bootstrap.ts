import { PermissionCache } from "../permission-cache/cache";
import { CacheEventHandler, RoleServiceClient } from "../spi";
import { Metrics, METRIC, GAUGE } from "../observability/metrics";
import { DiskCache } from "./disk";
import { applyRoleEvent } from "./events";

/** Seed-retry backoff sequence: 2s → 4s → 8s → 8s… */
const SEED_RETRY_DELAYS_MS = [2000, 4000, 8000, 8000];

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
 *  - on failure -> seed from disk -> READY in seed mode
 * Two background loops handle post-startup sync (§8.3):
 *  - startSeedRetry: retries the Role Service until seed->normal promotion, then stops.
 *  - startReconciler: periodic unconditional re-fetch; safety net for missed Kafka events.
 */
export class CacheBootstrap {
  private mode: CacheMode = "seed";
  private stopped = false;
  private seedRetryTimer: ReturnType<typeof setTimeout> | null = null;
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
      if (roleServiceErr instanceof Error && roleServiceErr.stack) {
        this.deps.logger?.warn(roleServiceErr.stack);
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
   * Seed-retry loop: retries the Role Service fetch with exponential backoff (2s, 4s, 8s,
   * 8s…) until the first successful sync promotes the cache from seed to normal, then
   * terminates. A no-op if the cache is already in normal mode.
   *
   * Errors here are expected while the Role Service is recovering and are logged
   * but do NOT increment `roleRefreshFailures` — that metric is reserved for
   * unexpected failures during normal operation (see startReconciler).
   */
  startSeedRetry(): void {
    if (this.mode !== "seed") {
      return; // already normal — no retry needed
    }
    const retry = async () => {
      let attempt = 0;
      while (!this.stopped && this.mode === "seed") {
        const delay = SEED_RETRY_DELAYS_MS[Math.min(attempt, SEED_RETRY_DELAYS_MS.length - 1)];
        attempt++;
        await new Promise<void>((r) => {
          const t = setTimeout(r, delay);
          this.seedRetryTimer = t;
          if (typeof t.unref === "function") t.unref();
        });
        this.seedRetryTimer = null;
        if (this.stopped || this.mode !== "seed") break;
        try {
          await this.fullSync();
          this.mode = "normal";
          this.updateGauges();
          this.deps.logger?.warn("authz seed retry succeeded — cache promoted to normal mode");
          break; // job done; periodic reconciler takes over
        } catch {
          this.deps.logger?.warn(
            `authz seed retry failed; will retry in ${delay}ms (attempt ${attempt})`,
          );
        }
      }
    };
    void retry();
  }

  /**
   * Periodic reconciler (§8.3): unconditional full re-fetch every `intervalMs` as a
   * safety net for missed or out-of-order Kafka events. Also promotes seed->normal if
   * it succeeds while still in seed mode (belt-and-suspenders alongside startSeedRetry).
   * On error, increments `roleRefreshFailures` and keeps the current cache (fail-open).
   */
  startReconciler(intervalMs = 300000): void {
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

  /** Stop the reconciler loop, the seed-retry loop, and disconnect the Kafka consumer (e.g. on shutdown). */
  stop(): void {
    this.stopped = true;
    // Clear the pending seed-retry timer so the loop exits immediately.
    if (this.seedRetryTimer !== null) {
      clearTimeout(this.seedRetryTimer);
      this.seedRetryTimer = null;
    }
    // B11: Clear the pending reconciler timer so the loop wakes immediately and exits,
    // rather than firing once more after the current interval elapses.
    // Mirrors Java's reconciler.interrupt() semantics.
    if (this.reconcilerTimer !== null) {
      clearTimeout(this.reconcilerTimer);
      this.reconcilerTimer = null;
    }
    // Disconnect the Kafka consumer so it does not leak on shutdown, matching
    // the Java CacheBootstrap.stop() which calls events.stop(). Fire-and-forget
    // (stop() is sync); KafkaCacheEventHandler.stop() is idempotent, so a later
    // await events.stop() by the caller is a safe no-op. Failures are logged.
    if (this.events) {
      void this.events.stop().catch((err) => {
        this.deps.logger?.warn(
          `Kafka consumer disconnect failed on stop: ${err instanceof Error ? err.message : String(err)}`,
        );
      });
    }
  }
}
