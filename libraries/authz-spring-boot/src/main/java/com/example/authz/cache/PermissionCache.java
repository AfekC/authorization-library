package com.example.authz.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

/**
 * In-memory role -> permissions store. Copy-on-replace: each update builds a
 * fresh immutable map and atomically swaps the active reference.
 *
 * <p><b>Concurrency model (C2/C6):</b> readers call {@link #snapshot()} /
 * {@link #permissionsForRole} without acquiring any lock — they always see the
 * last fully-published immutable {@code Map.copyOf} snapshot. Writers
 * ({@link #upsertRole}, {@link #deleteRole}, {@link #replaceAll}) acquire
 * {@code writeLock} so that only one mutation runs at a time. This prevents
 * the classic read-modify-write race where two concurrent Kafka threads each
 * read the same snapshot, build independent next-maps, and the second write
 * silently discards the first thread's change (C2). It also serialises the
 * reconciler's full {@link #replaceAll} against individual Kafka events so a
 * DELETE_ROLE cannot be overwritten by a concurrent snapshot replace (C6).
 *
 * <p><b>Residual behaviour (C6):</b> if a Kafka DELETE_ROLE is delivered
 * <em>after</em> the reconciler has already fetched its Role Service snapshot
 * but <em>before</em> it calls {@code replaceAll}, the next reconciler cycle
 * (default 5 s) will re-fetch and once again exclude the deleted role. The
 * maximum stale-auth window is therefore bounded by the reconciler interval,
 * not infinite. Under the lock, a Kafka event that arrives while
 * {@code replaceAll} holds the lock is queued and applied afterwards, so no
 * event is silently dropped.
 *
 * <p><b>Version-aware apply (T24):</b> each entity key tracks the last-applied
 * monotonic {@code version} (Long). Upsert/delete operations from Kafka events
 * supply an optional version; the cache applies the change only if the incoming
 * version is strictly greater than the stored one (idempotent, prevents
 * out-of-order regression). When a version is absent (older Role Service), the
 * operation is applied unconditionally and a one-time warning is logged.
 */
public final class PermissionCache {

    private static final Logger LOG = LoggerFactory.getLogger(PermissionCache.class);

    /** Guards all write paths; readers need no lock. */
    private final ReentrantLock writeLock = new ReentrantLock();
    private final AtomicReference<Map<String, Set<String>>> active = new AtomicReference<>();
    private volatile Instant lastUpdatedAt;

    /**
     * Last-applied version per role key (T24). Concurrent reads are lock-free;
     * writes happen under {@code writeLock}.
     */
    private final ConcurrentHashMap<String, Long> roleVersions = new ConcurrentHashMap<>();

    /** T24: one-time warning flag for missing-version events. */
    private final AtomicBoolean missingVersionWarnedOnce = new AtomicBoolean(false);

    public PermissionCache() {
        this(Map.of());
    }

    public PermissionCache(Map<String, ? extends Iterable<String>> initial) {
        this.active.set(build(initial));
        this.lastUpdatedAt = Instant.now();
    }

    private static Map<String, Set<String>> build(Map<String, ? extends Iterable<String>> roles) {
        Map<String, Set<String>> map = new HashMap<>();
        for (Map.Entry<String, ? extends Iterable<String>> e : roles.entrySet()) {
            Set<String> perms = new HashSet<>();
            e.getValue().forEach(perms::add);
            map.put(e.getKey(), Set.copyOf(perms));
        }
        return Map.copyOf(map);
    }

    /** Empty set for an unknown role — no implicit grants. Lock-free read. */
    public Set<String> permissionsForRole(String role) {
        if (role == null) return Set.of();
        return active.get().getOrDefault(role, Set.of());
    }

    public Instant lastUpdatedAt() { return lastUpdatedAt; }

    /**
     * Replace the whole map atomically (e.g. after a Role Service snapshot).
     * Acquires {@code writeLock} to serialise against concurrent Kafka events
     * (C6): a full-snapshot replace and an individual event cannot interleave.
     * Clears tracked versions so the next Kafka events start fresh (T24).
     */
    public void replaceAll(Map<String, ? extends Iterable<String>> roles) {
        writeLock.lock();
        try {
            active.set(build(roles));
            roleVersions.clear();
            this.lastUpdatedAt = Instant.now();
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Upsert a single role without a version (legacy / version-absent path).
     * Applied unconditionally; a one-time warning is logged if this is the first
     * version-absent event seen (T24 backward-compatibility).
     * Acquires {@code writeLock} so the read-modify-write is atomic (C2).
     */
    public void upsertRole(String role, Iterable<String> permissions) {
        warnMissingVersionOnce();
        writeLock.lock();
        try {
            applyUpsert(role, permissions);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Upsert a single role with a monotonic version (T24).
     * Applied only if {@code version > storedVersion}; stale/equal events are
     * silently ignored (idempotent). Acquires {@code writeLock} (C2).
     *
     * @return {@code true} if applied; {@code false} if skipped as stale/equal
     */
    public boolean upsertRole(String role, Iterable<String> permissions, long version) {
        writeLock.lock();
        try {
            Long stored = roleVersions.get(role);
            if (stored != null && version <= stored) {
                return false; // stale or duplicate — skip
            }
            applyUpsert(role, permissions);
            roleVersions.put(role, version);
            return true;
        } finally {
            writeLock.unlock();
        }
    }

    private void applyUpsert(String role, Iterable<String> permissions) {
        Map<String, Set<String>> next = new HashMap<>(active.get());
        Set<String> perms = new HashSet<>();
        permissions.forEach(perms::add);
        next.put(role, Set.copyOf(perms));
        active.set(Map.copyOf(next));
        this.lastUpdatedAt = Instant.now();
    }

    /**
     * Delete a single role without a version (legacy / version-absent path).
     * Applied unconditionally; one-time warning logged if version absent (T24).
     * Acquires {@code writeLock} (C2).
     */
    public void deleteRole(String role) {
        warnMissingVersionOnce();
        writeLock.lock();
        try {
            applyDelete(role);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Delete a single role with a monotonic version (T24).
     * Applied only if {@code version > storedVersion}. Acquires {@code writeLock} (C2).
     *
     * @return {@code true} if applied; {@code false} if skipped as stale/equal
     */
    public boolean deleteRole(String role, long version) {
        writeLock.lock();
        try {
            Long stored = roleVersions.get(role);
            if (stored != null && version <= stored) {
                return false; // stale or duplicate — skip
            }
            applyDelete(role);
            roleVersions.put(role, version);
            return true;
        } finally {
            writeLock.unlock();
        }
    }

    private void applyDelete(String role) {
        Map<String, Set<String>> next = new HashMap<>(active.get());
        next.remove(role);
        roleVersions.remove(role);
        active.set(Map.copyOf(next));
        this.lastUpdatedAt = Instant.now();
    }

    /** Lock-free snapshot for readers; the returned map is immutable. */
    public Map<String, Set<String>> snapshot() {
        return active.get();
    }

    /**
     * T24: Returns the last-applied version for a role key, or {@code null} if
     * no versioned event has been applied for that key yet. Lock-free read.
     */
    public Long roleVersion(String role) {
        return roleVersions.get(role);
    }

    /** T24: emit a one-time warning when a version-absent event is processed. */
    private void warnMissingVersionOnce() {
        if (missingVersionWarnedOnce.compareAndSet(false, true)) {
            LOG.warn("T24: received a role event without a 'version' field — falling back to " +
                     "always-apply behavior. This is expected for older Role Service deployments " +
                     "but may cause out-of-order Kafka events to regress the cache.");
        }
    }
}
