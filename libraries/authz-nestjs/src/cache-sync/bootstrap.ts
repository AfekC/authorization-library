import { PermissionCache } from "../permission-cache/cache.js";
import { RoleServiceClient, RoleUpsertEvent, RoleDeleteEvent } from "../spi/index.js";
import { Metrics, METRIC, GAUGE } from "../observability/metrics.js";
import { DiskCache } from "./disk.js";
import { applyUpsert, applyDelete, VersionStore } from "./events.js";
import type { NormalisedSnapshot } from "../role-service-client/client.js";

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
 *  - try Role Service -> atomic replace + write disk -> normal
 *  - on failure -> seed from disk -> READY in seed mode
 * Two background loops handle post-startup sync (§8.3):
 *  - startSeedRetry: retries the Role Service until seed->normal promotion, then stops.
 *  - startReconciler: periodic unconditional re-fetch; safety net for missed Kafka events.
 *
 * Role events arrive via the library's @EventPattern controller which calls
 * applyUpsert(), applyDelete(), and forceRefresh() directly (seam inversion).
 */
export class CacheBootstrap {
  private mode: CacheMode = "seed";
  private stopped = false;
  private seedRetryTimer: ReturnType<typeof setTimeout> | null = null;
  private reconcilerTimer: ReturnType<typeof setTimeout> | null = null;
  private lastSyncAt: Date | null = null;
  /**
   * N6/L2: Single promise chain that serializes every apply (role-event upsert/delete)
   * and every forcedRefresh so they never interleave. An upsert enqueued after a
   * publish-roles trigger will always execute AFTER the refresh completes, and the
   * chain's `.catch()` swallows any rejection that escapes forcedRefresh's own guard.
   */
  private applyChain: Promise<void> = Promise.resolve();
  /**
   * T24: Monotonic version store — tracks the highest applied version per roleId
   * across both Kafka events and full-snapshot seedings. Prevents out-of-order
   * Kafka events from regressing the cache.
   */
  private readonly versionStore = new VersionStore();

  constructor(
    private readonly cache: PermissionCache,
    private readonly roleService: RoleServiceClient,
    private readonly disk: DiskCache,
    private readonly deps: CacheBootstrapDeps = {},
  ) {}

  mode_(): CacheMode {
    return this.mode;
  }

  roleServiceLastSync(): Date | null {
    return this.lastSyncAt;
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
    return { cache: this.cache, mode: this.mode };
  }

  /** Fetch the authoritative snapshot (bare role map), swap + persist. */
  private async fullSync(): Promise<void> {
    // T24: prefer fetchNormalisedSnapshot() when the role service client supports it,
    // so per-role version numbers from the snapshot can seed the version store.
    // Fall back to fetchSnapshot() for clients that implement only the base SPI.
    let roles: Record<string, string[]>;
    let snapshotVersions: Map<string, number> | undefined;

    const client = this.roleService as unknown as { fetchNormalisedSnapshot?: () => Promise<NormalisedSnapshot> };
    if (typeof client.fetchNormalisedSnapshot === "function") {
      const normalised = await client.fetchNormalisedSnapshot();
      roles = normalised.roles;
      snapshotVersions = normalised.versions;
    } else {
      roles = await this.roleService.fetchSnapshot();
    }

    await this.cache.replaceAll(roles);

    // T24: seed the version store from the snapshot. A full sync is authoritative —
    // update stored versions for all roles that carried a version in this snapshot.
    if (snapshotVersions && snapshotVersions.size > 0) {
      for (const [roleId, version] of snapshotVersions) {
        this.versionStore.record(roleId, version);
      }
    } else if (!snapshotVersions) {
      // Non-versioned client — warn once per process lifetime.
      this.deps.logger?.warn(
        "authz: Role Service snapshot does not include version numbers; version guard disabled for snapshot entries (legacy Role Service)",
      );
    }

    const writeErr = this.disk.write(this.cache);
    if (writeErr) handleDiskWriteError(writeErr, this.deps);
    this.lastSyncAt = new Date();
    // record a successful refresh
    this.deps.metrics?.inc(METRIC.roleRefreshSuccess);
  }

  /**
   * Public: enqueue a typed upsert event onto the serial chain (N6/L2).
   * Called by the @EventPattern controller on `role-updates` messages.
   */
  applyUpsert(event: RoleUpsertEvent): void {
    this.applyChain = this.applyChain.then(async () => {
      const stop = this.deps.metrics?.startTimer(METRIC.roleEventProcessingDuration);
      const result = await applyUpsert(
        this.cache,
        event,
        this.versionStore,
        () =>
          this.deps.logger?.warn(
            "authz: Kafka role event is missing the version field; version guard disabled for this and future unversioned events (legacy Role Service)",
          ),
      );
      if (stop) stop();
      if (result.applied) {
        const writeErr = this.disk.write(this.cache);
        if (writeErr) handleDiskWriteError(writeErr, this.deps);
        this.updateGauges();
        this.deps.metrics?.inc(METRIC.roleEventsProcessed);
      } else {
        this.deps.metrics?.inc(METRIC.roleEventSkipped);
        this.deps.logger?.warn(`role event skipped: ${result.reason}`);
      }
    }).catch((e) => {
      this.deps.logger?.warn(
        `role event apply failed: ${e instanceof Error ? e.message : String(e)}`,
      );
    });
  }

  /**
   * Public: enqueue a typed delete event onto the serial chain (N6/L2).
   * Called by the @EventPattern controller on `role-delete` messages.
   */
  applyDelete(event: RoleDeleteEvent): void {
    this.applyChain = this.applyChain.then(async () => {
      const stop = this.deps.metrics?.startTimer(METRIC.roleEventProcessingDuration);
      const result = await applyDelete(this.cache, event, this.versionStore);
      if (stop) stop();
      if (result.applied) {
        const writeErr = this.disk.write(this.cache);
        if (writeErr) handleDiskWriteError(writeErr, this.deps);
        this.updateGauges();
        this.deps.metrics?.inc(METRIC.roleEventsProcessed);
      } else {
        this.deps.metrics?.inc(METRIC.roleEventSkipped);
        this.deps.logger?.warn(`role event skipped: ${result.reason}`);
      }
    }).catch((e) => {
      this.deps.logger?.warn(
        `role event apply failed: ${e instanceof Error ? e.message : String(e)}`,
      );
    });
  }

  /**
   * Public: enqueue a forced full re-fetch onto the serial chain (N6/L2).
   * Called by the @EventPattern controller on `publish-roles` messages.
   */
  forceRefresh(): void {
    // N6/L2: Enqueue forcedRefresh through the same chain so it is
    // serialized against apply(). The outer .catch() provides an
    // additional safety net on top of forcedRefresh's internal guard.
    this.applyChain = this.applyChain.then(() => this.forcedRefresh()).catch((e) => {
      this.deps.logger?.warn(
        `forced refresh chain error: ${e instanceof Error ? e.message : String(e)}`,
      );
    });
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
      this.deps.metrics?.inc(METRIC.roleRefreshSuccess);
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
          this.deps.metrics?.inc(METRIC.roleRefreshSuccess);
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
   * it succeeds while still in seed mode.
   */
  startReconciler(intervalMs = 300000): void {
    const loop = async () => {
      while (!this.stopped) {
        // B11: Track the pending timer so stop() can clear it immediately.
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
          this.deps.metrics?.inc(METRIC.roleRefreshSuccess);
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
    this.deps.metrics?.setGauge(
      GAUGE.cacheAgeSeconds,
      Math.max(0, Math.floor((Date.now() - this.cache.lastUpdatedAt().getTime()) / 1000)),
    );
  }

  /** Stop the reconciler loop and seed-retry loop (e.g. on shutdown). */
  stop(): void {
    this.stopped = true;
    // Clear the pending seed-retry timer so the loop exits immediately.
    if (this.seedRetryTimer !== null) {
      clearTimeout(this.seedRetryTimer);
      this.seedRetryTimer = null;
    }
    // B11: Clear the pending reconciler timer so the loop wakes immediately and exits,
    // rather than firing once more after the current interval elapses.
    if (this.reconcilerTimer !== null) {
      clearTimeout(this.reconcilerTimer);
      this.reconcilerTimer = null;
    }
  }
}
