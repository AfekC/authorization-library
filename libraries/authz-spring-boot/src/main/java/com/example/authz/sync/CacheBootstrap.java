package com.example.authz.sync;

import com.example.authz.cache.PermissionCache;
import com.example.authz.observability.Metrics;
import com.example.authz.spi.Spi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Startup state machine for the permission cache (architecture §8):
 *  - try Role Service -> atomic replace + disk write + subscribe Kafka -> NORMAL
 *  - on failure -> seed from disk -> READY in SEED mode
 * Two background loops handle post-startup sync (§8.3):
 *  - startSeedRetry: retries the Role Service until SEED->NORMAL promotion, then stops.
 *  - startReconciler: periodic unconditional re-fetch; safety net for missed Kafka events.
 */
public class CacheBootstrap {
    private static final Logger LOG = LoggerFactory.getLogger(CacheBootstrap.class);

    public enum Mode { NORMAL, SEED }

    private final PermissionCache cache;
    private final Spi.RoleServiceClient roleService;
    private final DiskCache disk;
    private final Spi.CacheEventHandler events; // nullable
    private final Metrics metrics;              // nullable

    private volatile Mode mode = Mode.SEED;
    private volatile Instant lastSyncAt;
    private volatile boolean kafkaConnected;
    private volatile boolean stopped;
    private Thread seedRetry;
    private Thread reconciler;
    /** Q6: guard that prevents a second concurrent startReconciler() from spawning a second thread. */
    private final AtomicBoolean reconcilerStarted = new AtomicBoolean(false);

    /** Seed-retry backoff sequence: 2s → 4s → 8s → 8s… */
    private static final long[] SEED_RETRY_DELAYS_MS = {2000, 4000, 8000, 8000};

    public CacheBootstrap(PermissionCache cache, Spi.RoleServiceClient roleService, DiskCache disk) {
        this(cache, roleService, disk, null, null);
    }

    public CacheBootstrap(PermissionCache cache, Spi.RoleServiceClient roleService, DiskCache disk,
                          Spi.CacheEventHandler events, Metrics metrics) {
        this.cache = cache;
        this.roleService = roleService;
        this.disk = disk;
        this.events = events;
        this.metrics = metrics;
    }

    public Mode mode() { return mode; }
    public Instant roleServiceLastSync() { return lastSyncAt; }
    public boolean isKafkaConnected() { return kafkaConnected; }

    /** Try Role Service; seed from disk if usable; otherwise fail fast. */
    public Mode start() {
        try {
            fullSync();
            mode = Mode.NORMAL;
        } catch (RuntimeException e) {
            LOG.warn("authz startup snapshot fetch failed; checking disk cache", e);
            DiskCache.Snapshot seed = disk.read();
            if (seed == null || seed.roles() == null || seed.roles().isEmpty()) {
                throw new CacheBootstrapException(
                        "authz startup failed: Role Service unreachable and disk cache is missing/empty");
            }
            cache.replaceAll(seed.roles());
            mode = Mode.SEED;
        }
        updateGauges();
        subscribe();
        return mode;
    }

    private void fullSync() {
        Map<String, List<String>> roles = roleService.fetchSnapshot();
        cache.replaceAll(roles);
        writeDiskQuietly();
        lastSyncAt = Instant.now();
    }

    /**
     * Persist the disk cache, treating any failure as non-fatal: a write error
     * after a successful Role Service fetch must not abort the sync or drop the
     * service into seed mode — the in-memory cache is already authoritative. The
     * failure is logged and counted (disk_cache_write_failures_total). Mirrors
     * the NestJS bootstrap, which surfaces the write error and keeps serving.
     */
    private void writeDiskQuietly() {
        try {
            disk.write(cache);
        } catch (RuntimeException e) {
            if (metrics != null) metrics.inc(Metrics.DISK_CACHE_WRITE_FAILURES);
            LOG.warn("disk cache write failed; continuing to serve from in-memory cache", e);
        }
    }

    private void subscribe() {
        if (events == null) return;
        // Fail-open at startup: a broker that is unreachable now must not abort
        // startup — the cache already serves from the snapshot/seed and the
        // reconciler heals any events missed while Kafka is down (§8.4).
        try {
            events.start(event -> {
                RoleEvents.ApplyResult result = RoleEvents.apply(cache, event);
                if (result.applied()) {
                    writeDiskQuietly();
                    updateGauges();
                } else {
                    if (metrics != null) metrics.inc(Metrics.ROLE_EVENT_SKIPPED);
                    LOG.warn("role event skipped: {}", result.reason());
                }
            }, this::forcedRefresh);
            kafkaConnected = true;
        } catch (RuntimeException e) {
            kafkaConnected = false;
            LOG.warn("Kafka subscribe failed at startup; continuing without live events", e);
        }
    }

    /**
     * Forced full re-fetch (triggered by a `publish-roles` message). Re-fetches
     * the snapshot, replaces the cache, and rewrites disk. Fail-open: on error
     * the current cache is kept and `role_refresh_failures_total` is incremented.
     */
    public void forcedRefresh() {
        if (stopped) return;
        try {
            fullSync();
            updateGauges();
        } catch (RuntimeException e) {
            if (metrics != null) metrics.inc(Metrics.ROLE_REFRESH_FAILURES);
            LOG.warn("forced refresh failed; keeping current cache", e);
        }
    }

    /**
     * Seed-retry loop: retries the Role Service fetch with exponential backoff (2s, 4s, 8s,
     * 8s…) until the first successful sync promotes the cache from SEED to NORMAL, then
     * terminates. A no-op if the cache is already in NORMAL mode.
     * <p>
     * Errors here are expected while the Role Service is recovering and are logged
     * but do <em>not</em> increment {@code role_refresh_failures_total} — that metric
     * is reserved for unexpected failures during normal operation (see
     * {@link #startReconciler}).
     */
    public void startSeedRetry() {
        if (mode != Mode.SEED) {
            LOG.debug("authz startSeedRetry: already in NORMAL mode — no-op");
            return;
        }
        seedRetry = new Thread(() -> {
            int attempt = 0;
            while (!stopped && mode == Mode.SEED) {
                long delay = SEED_RETRY_DELAYS_MS[Math.min(attempt, SEED_RETRY_DELAYS_MS.length - 1)];
                attempt++;
                try {
                    Thread.sleep(delay);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                if (stopped || mode != Mode.SEED) return;
                try {
                    fullSync();
                    mode = Mode.NORMAL;
                    updateGauges();
                    LOG.info("authz seed retry succeeded — cache promoted to NORMAL mode");
                    return; // job done; periodic reconciler takes over
                } catch (RuntimeException e) {
                    LOG.warn("authz seed retry failed; will retry in {}ms (attempt {})", delay, attempt);
                }
            }
        }, "authz-seed-retry");
        seedRetry.setDaemon(true);
        seedRetry.start();
    }

    /**
     * Periodic reconciler (§8.3): unconditional full re-fetch every {@code intervalMs}
     * as a safety net for missed or out-of-order Kafka events. Also promotes SEED→NORMAL
     * if it succeeds while still in seed mode (belt-and-suspenders alongside
     * {@link #startSeedRetry}). On error, increments {@code role_refresh_failures_total}
     * and keeps the current cache (fail-open).
     * <p>
     * Q6: guard against double-start — a second call without an intervening stop() is a no-op.
     */
    public void startReconciler(long intervalMs) {
        if (!reconcilerStarted.compareAndSet(false, true)) {
            LOG.debug("authz reconciler already running — ignoring duplicate startReconciler() call");
            return;
        }
        reconciler = new Thread(() -> {
            while (!stopped) {
                try {
                    Thread.sleep(intervalMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                if (stopped) return;
                try {
                    // Re-fetch the full snapshot each cycle (no version to compare);
                    // catches missed/out-of-order Kafka events.
                    fullSync();
                    if (mode == Mode.SEED) mode = Mode.NORMAL;
                    updateGauges();
                } catch (RuntimeException e) {
                    if (metrics != null) metrics.inc(Metrics.ROLE_REFRESH_FAILURES);
                    LOG.warn("authz reconciler snapshot fetch failed; keeping current cache", e);
                    // keep current cache; try again next cycle (fail-open)
                }
            }
        }, "authz-reconciler");
        reconciler.setDaemon(true);
        reconciler.start();
    }

    private void updateGauges() {
        if (metrics == null) return;
        metrics.setGauge(Metrics.CACHE_VERSION, cache.version());
        metrics.setGauge(Metrics.CACHE_AGE_SECONDS,
                Math.max(0, (System.currentTimeMillis() - cache.lastUpdatedAt().toEpochMilli()) / 1000));
    }

    public void stop() {
        stopped = true;
        reconcilerStarted.set(false); // allow restart on a fresh instance after stop()
        if (seedRetry != null) seedRetry.interrupt();
        if (reconciler != null) reconciler.interrupt();
        if (events != null) events.stop();
    }
}
