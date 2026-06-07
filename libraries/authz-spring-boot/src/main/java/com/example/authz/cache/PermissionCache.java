package com.example.authz.cache;

import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
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
 */
public final class PermissionCache {
    /** Guards all write paths; readers need no lock. */
    private final ReentrantLock writeLock = new ReentrantLock();
    private final AtomicReference<Map<String, Set<String>>> active = new AtomicReference<>();
    private volatile long version;
    private volatile Instant lastUpdatedAt;

    public PermissionCache() {
        this(Map.of());
    }

    public PermissionCache(Map<String, ? extends Iterable<String>> initial) {
        this.active.set(build(initial));
        this.version = 0;
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

    public long version() { return version; }

    public Instant lastUpdatedAt() { return lastUpdatedAt; }

    /**
     * Replace the whole map atomically (e.g. after a Role Service snapshot).
     * Acquires {@code writeLock} to serialise against concurrent Kafka events
     * (C6): a full-snapshot replace and an individual event cannot interleave.
     * Bumps an internal generation counter for observability.
     */
    public void replaceAll(Map<String, ? extends Iterable<String>> roles) {
        writeLock.lock();
        try {
            active.set(build(roles));
            this.version++;
            this.lastUpdatedAt = Instant.now();
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Upsert a single role. Acquires {@code writeLock} so the read-modify-write
     * is atomic with respect to other concurrent upserts/deletes (C2).
     */
    public void upsertRole(String role, Iterable<String> permissions) {
        writeLock.lock();
        try {
            Map<String, Set<String>> next = new HashMap<>(active.get());
            Set<String> perms = new HashSet<>();
            permissions.forEach(perms::add);
            next.put(role, Set.copyOf(perms));
            active.set(Map.copyOf(next));
            this.version++;
            this.lastUpdatedAt = Instant.now();
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Delete a single role. Acquires {@code writeLock} so the read-modify-write
     * is atomic with respect to other concurrent mutations (C2).
     */
    public void deleteRole(String role) {
        writeLock.lock();
        try {
            Map<String, Set<String>> next = new HashMap<>(active.get());
            next.remove(role);
            active.set(Map.copyOf(next));
            this.version++;
            this.lastUpdatedAt = Instant.now();
        } finally {
            writeLock.unlock();
        }
    }

    /** Lock-free snapshot for readers; the returned map is immutable. */
    public Map<String, Set<String>> snapshot() {
        return active.get();
    }
}
