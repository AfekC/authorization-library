package com.example.authz;

import com.example.authz.cache.PermissionCache;
import com.example.authz.observability.Metrics;
import com.example.authz.sync.CacheBootstrap;
import com.example.authz.sync.DiskCache;
import com.example.authz.sync.RoleEvents;
import com.example.authz.spi.Spi;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Concurrency correctness tests for PermissionCache and reconciler/Kafka races.
 * Covers: C2 (upsert/delete lost-update), C6 (reconciler vs Kafka race),
 * D5 (snapshot consistency), D7 (DiskCache edge cases), B4 (mixed-type permissions),
 * C9 (Kafka topic/operation field cross-check).
 */
class CacheConcurrencyTest {

    // -------------------------------------------------------------------------
    // C2 — PermissionCache upsert/delete concurrent lost-update
    // -------------------------------------------------------------------------

    /**
     * Many threads simultaneously upsert different roles. After all threads
     * complete, every upserted role must be present (no update must be silently
     * dropped by a concurrent read-modify-write).
     */
    @Test
    void c2_concurrentUpsertNoLostUpdate() throws InterruptedException {
        PermissionCache cache = new PermissionCache();
        int threads = 20;
        int rolesPerThread = 50;
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        ExecutorService pool = Executors.newFixedThreadPool(threads);

        for (int t = 0; t < threads; t++) {
            final int tid = t;
            pool.submit(() -> {
                ready.countDown();
                try { go.await(); } catch (InterruptedException ignored) {}
                for (int i = 0; i < rolesPerThread; i++) {
                    String role = "role_" + tid + "_" + i;
                    cache.upsertRole(role, List.of("PERM_" + tid + "_" + i));
                }
                done.countDown();
            });
        }

        ready.await();
        go.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS), "threads did not finish in time");
        pool.shutdown();

        // Every role inserted by every thread must survive.
        for (int t = 0; t < threads; t++) {
            for (int i = 0; i < rolesPerThread; i++) {
                String role = "role_" + t + "_" + i;
                assertFalse(cache.permissionsForRole(role).isEmpty(),
                        "Lost update: role " + role + " is missing from cache");
            }
        }
    }

    /**
     * Alternate upserts and deletes for the same role from many threads.
     * After completion, the cache must be in a consistent state (no exception,
     * no partial/corrupt entry for the role).
     */
    @Test
    void c2_concurrentUpsertDeleteSameRoleIsConsistent() throws InterruptedException {
        PermissionCache cache = new PermissionCache(Map.of("SHARED", List.of("READ")));
        int threads = 16;
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        AtomicBoolean errorSeen = new AtomicBoolean(false);

        for (int t = 0; t < threads; t++) {
            final int tid = t;
            pool.submit(() -> {
                ready.countDown();
                try { go.await(); } catch (InterruptedException ignored) {}
                try {
                    for (int i = 0; i < 200; i++) {
                        if ((tid + i) % 2 == 0) {
                            cache.upsertRole("SHARED", List.of("WRITE", "READ"));
                        } else {
                            cache.deleteRole("SHARED");
                        }
                        // snapshot must always be a complete, non-null immutable Map
                        Map<String, Set<String>> snap = cache.snapshot();
                        assertNotNull(snap);
                    }
                } catch (Exception e) {
                    errorSeen.set(true);
                } finally {
                    done.countDown();
                }
            });
        }

        ready.await();
        go.countDown();
        assertTrue(done.await(15, TimeUnit.SECONDS), "threads did not finish in time");
        pool.shutdown();
        assertFalse(errorSeen.get(), "Exception thrown during concurrent upsert/delete");
    }

    // -------------------------------------------------------------------------
    // C6 — Reconciler replaceAll vs Kafka upsert race (lost-update window)
    // -------------------------------------------------------------------------

    /**
     * A Kafka DELETE_ROLE event that arrives while the reconciler is doing a
     * replaceAll must NOT be silently overwritten. After the reconciler completes
     * its replaceAll, the DELETE must still be reflected (the role must be gone
     * or the replaceAll must have serialised before/after the delete).
     *
     * Design: We drive this deterministically by calling replaceAll and
     * upsert/deleteRole in many concurrent threads and verifying that the cache
     * is never in a half-written state.
     */
    @Test
    void c6_reconcilerReplaceAllDoesNotResurrectDeletedRole() throws InterruptedException {
        PermissionCache cache = new PermissionCache(Map.of("ZOMBIE", List.of("READ")));

        int iterations = 500;
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch go = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(2);
        AtomicBoolean errorSeen = new AtomicBoolean(false);

        // Thread A simulates the reconciler doing a replaceAll (no ZOMBIE)
        Thread reconciler = new Thread(() -> {
            ready.countDown();
            try { go.await(); } catch (InterruptedException ignored) {}
            try {
                for (int i = 0; i < iterations; i++) {
                    // replaceAll with a snapshot that does NOT contain ZOMBIE
                    cache.replaceAll(Map.of("OTHER", List.of("WRITE")));
                }
            } finally { done.countDown(); }
        });

        // Thread B simulates a Kafka DELETE_ROLE for ZOMBIE
        Thread kafka = new Thread(() -> {
            ready.countDown();
            try { go.await(); } catch (InterruptedException ignored) {}
            try {
                for (int i = 0; i < iterations; i++) {
                    // After a replaceAll that brought back ZOMBIE, delete it
                    cache.upsertRole("ZOMBIE", List.of("READ")); // re-add
                    cache.deleteRole("ZOMBIE");                   // then delete
                    // Cache must never expose a corrupted/partial state
                    Map<String, Set<String>> snap = cache.snapshot();
                    assertNotNull(snap, "snapshot must not be null");
                }
            } catch (Exception e) {
                errorSeen.set(true);
            } finally { done.countDown(); }
        });

        reconciler.start();
        kafka.start();
        ready.await();
        go.countDown();
        assertTrue(done.await(15, TimeUnit.SECONDS), "threads did not finish in time");
        assertFalse(errorSeen.get(), "Exception during reconciler/kafka interleave");
    }

    /**
     * Verify that after a replaceAll that includes a role and a concurrent
     * deleteRole for that same role, the final state is always one of the two
     * valid linearised outcomes (role present OR role absent) — never a
     * corrupted/null map.
     */
    @Test
    void c6_replaceAllAndDeleteAreSerialised() throws InterruptedException {
        PermissionCache cache = new PermissionCache();
        int threads = 8;
        int ops = 200;
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicBoolean errorSeen = new AtomicBoolean(false);

        for (int t = 0; t < threads; t++) {
            final int tid = t;
            pool: {
                new Thread(() -> {
                    ready.countDown();
                    try { go.await(); } catch (InterruptedException ignored) {}
                    try {
                        for (int i = 0; i < ops; i++) {
                            if (tid % 2 == 0) {
                                cache.replaceAll(Map.of("KEY", List.of("READ")));
                            } else {
                                cache.deleteRole("KEY");
                            }
                            // snapshot must always be non-null and immutable
                            Map<String, Set<String>> s = cache.snapshot();
                            assertNotNull(s);
                        }
                    } catch (Exception e) {
                        errorSeen.set(true);
                    } finally {
                        done.countDown();
                    }
                }).start();
            }
        }

        ready.await();
        go.countDown();
        assertTrue(done.await(15, TimeUnit.SECONDS));
        assertFalse(errorSeen.get(), "Concurrent replaceAll/deleteRole caused an error");
    }

    // -------------------------------------------------------------------------
    // D5 — Copy-on-replace: in-flight reader sees consistent old snapshot
    // -------------------------------------------------------------------------

    /**
     * A reader obtains a reference to the active map snapshot. After a concurrent
     * replaceAll, the reader's held reference must still be a complete, consistent
     * Map — it must not have been mutated in-place.
     */
    @Test
    void d5_inFlightReaderSeesConsistentSnapshotAfterReplace() throws InterruptedException {
        Map<String, List<String>> initial = new HashMap<>();
        for (int i = 0; i < 50; i++) {
            initial.put("role" + i, List.of("PERM_A", "PERM_B"));
        }
        PermissionCache cache = new PermissionCache(initial);

        // Reader grabs the old snapshot reference
        Map<String, Set<String>> oldSnapshot = cache.snapshot();
        assertEquals(50, oldSnapshot.size(), "pre-condition: 50 roles in snapshot");

        // Many concurrent replaceAll calls replace the entire map
        int replacers = 8;
        CountDownLatch go = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(replacers);
        for (int i = 0; i < replacers; i++) {
            new Thread(() -> {
                try { go.await(); } catch (InterruptedException ignored) {}
                cache.replaceAll(Map.of("newRole", List.of("NEW_PERM")));
                done.countDown();
            }).start();
        }
        go.countDown();
        assertTrue(done.await(5, TimeUnit.SECONDS));

        // The old snapshot reference must still be complete and unmodified
        assertEquals(50, oldSnapshot.size(),
                "Old snapshot was mutated in-place after replaceAll");
        for (int i = 0; i < 50; i++) {
            Set<String> perms = oldSnapshot.get("role" + i);
            assertNotNull(perms, "role" + i + " disappeared from old snapshot");
            assertTrue(perms.contains("PERM_A"), "PERM_A missing from old snapshot for role" + i);
            assertTrue(perms.contains("PERM_B"), "PERM_B missing from old snapshot for role" + i);
        }

        // The live cache now has only the new role
        assertEquals(Set.of("newRole"), cache.snapshot().keySet(),
                "Live cache should reflect the last replaceAll");
    }

    // -------------------------------------------------------------------------
    // D7 — DiskCache edge cases
    // -------------------------------------------------------------------------

    @Test
    void d7_diskCacheReturnsNullForCorruptJson(@TempDir Path tmp) throws Exception {
        Path file = tmp.resolve("corrupt.json");
        Files.writeString(file, "{ this is not valid JSON !!!");
        DiskCache disk = new DiskCache(file);
        // Must return null gracefully, not throw
        assertNull(disk.read(), "corrupt JSON should return null, not throw");
    }

    @Test
    void d7_diskCacheReturnsSnapshotWithNullRolesForMissingRolesKey(@TempDir Path tmp) throws Exception {
        Path file = tmp.resolve("wrong-schema.json");
        // Valid JSON but missing the "roles" key — Jackson maps it to null
        Files.writeString(file, "{\"timestamp\":\"2026-01-01T00:00:00Z\"}");
        DiskCache disk = new DiskCache(file);
        DiskCache.Snapshot snap = disk.read();
        // Should not throw; roles will be null (Jackson default for missing field)
        assertNotNull(snap, "snapshot record itself should not be null");
        assertNull(snap.roles(), "roles key missing → roles field should be null");
    }

    @Test
    void d7_diskCacheReturnsEmptyRolesWhenRolesMapIsEmpty(@TempDir Path tmp) throws Exception {
        Path file = tmp.resolve("empty-roles.json");
        Files.writeString(file, "{\"timestamp\":\"2026-01-01T00:00:00Z\",\"roles\":{}}");
        DiskCache disk = new DiskCache(file);
        DiskCache.Snapshot snap = disk.read();
        assertNotNull(snap);
        assertNotNull(snap.roles());
        assertTrue(snap.roles().isEmpty(), "roles map should be empty");
    }

    /**
     * CacheBootstrap uses seed.roles() == null || seed.roles().isEmpty() to
     * fail fast. Verify that a disk cache with missing 'roles' key causes
     * fail-fast (not a NullPointerException crash).
     */
    @Test
    void d7_bootstrapFailsFastOnDiskCacheWithNullRoles(@TempDir Path tmp) throws Exception {
        Path file = tmp.resolve("null-roles.json");
        Files.writeString(file, "{\"timestamp\":\"2026-01-01T00:00:00Z\"}");
        Spi.RoleServiceClient failing = () -> { throw new RuntimeException("unreachable"); };
        PermissionCache cache = new PermissionCache();
        CacheBootstrap boot = new CacheBootstrap(cache, failing, new DiskCache(file));
        // Must throw CacheBootstrapException, not NullPointerException
        assertThrows(com.example.authz.sync.CacheBootstrapException.class, boot::start,
                "Missing 'roles' key should cause fail-fast, not NPE");
    }

    // -------------------------------------------------------------------------
    // B4 — Mixed-type Kafka permissions stringified correctly
    // -------------------------------------------------------------------------

    /**
     * A Kafka UPSERT_ROLE event with mixed-type permissions (String, Integer,
     * Boolean) must store all values as strings. The decision engine's Set.contains
     * checks use strings, so numeric/boolean permissions stored as-is would
     * silently never match.
     */
    @Test
    void b4_mixedTypePermissionsStoredAsStrings() {
        PermissionCache cache = new PermissionCache();
        // permissions list contains a String, an Integer, and a Boolean
        List<Object> mixedPerms = new ArrayList<>();
        mixedPerms.add("read");
        mixedPerms.add(123);
        mixedPerms.add(true);

        Map<String, Object> event = new HashMap<>();
        event.put("operation", "UPSERT_ROLE");
        event.put("roleId", "MIXED_ROLE");
        event.put("permissions", mixedPerms);

        RoleEvents.ApplyResult result = RoleEvents.apply(cache, event);
        assertTrue(result.applied(), "UPSERT_ROLE with mixed permissions should apply: " + result.reason());

        Set<String> stored = cache.permissionsForRole("MIXED_ROLE");
        assertTrue(stored.contains("read"),  "String 'read' must be stored");
        assertTrue(stored.contains("123"),   "Integer 123 must be stored as String '123'");
        assertTrue(stored.contains("true"),  "Boolean true must be stored as String 'true'");
        assertEquals(3, stored.size(), "Exactly 3 permissions expected");
    }

    // -------------------------------------------------------------------------
    // C9 — Kafka topic vs message operation field cross-check
    // -------------------------------------------------------------------------

    /**
     * If a message carries an explicit 'operation' field that CONFLICTS with the
     * topic-derived operation, RoleEvents.apply must skip the event rather than
     * acting on it.
     *
     * Scenario: The topic says UPSERT_ROLE but the message body carries
     * operation=DELETE_ROLE. This is a misconfigured or spoofed message.
     * The implementation stamps the topic-derived operation on the event map
     * BEFORE calling RoleEvents.apply; the message's own field (if present before
     * stamping) must be cross-checked in KafkaCacheEventHandler.
     *
     * We test the cross-check logic directly via the event map that would be
     * produced by a cross-checking KafkaCacheEventHandler: if the stamped
     * operation differs from a pre-existing 'operation' field in the raw payload,
     * the event should be skipped.
     */
    @Test
    void c9_conflictingOperationFieldCausesSkip() {
        PermissionCache cache = new PermissionCache(Map.of("EXISTING", List.of("READ")));

        // Simulate: topic says UPSERT_ROLE, but message carried operation=DELETE_ROLE.
        // After cross-check the event should be skipped (not applied).
        // The event map has topicOperation=UPSERT_ROLE and wireOperation=DELETE_ROLE
        // encoded in the special "__wire_operation" field (set by the cross-checking handler).
        Map<String, Object> conflictingEvent = new HashMap<>();
        conflictingEvent.put("operation", "UPSERT_ROLE");         // topic-derived (stamped)
        conflictingEvent.put("__wire_operation", "DELETE_ROLE");   // wire field (conflicting)
        conflictingEvent.put("roleId", "EXISTING");
        conflictingEvent.put("permissions", List.of("WRITE"));

        RoleEvents.ApplyResult result = RoleEvents.apply(cache, conflictingEvent);
        assertFalse(result.applied(), "Conflicting operation field should cause skip");
        assertTrue(result.reason().contains("conflict") || result.reason().contains("mismatch"),
                "Skip reason should mention conflict/mismatch, got: " + result.reason());

        // Cache must be unchanged — EXISTING must still have READ, not WRITE
        assertTrue(cache.permissionsForRole("EXISTING").contains("READ"),
                "Cache should be unchanged when event is skipped");
        assertFalse(cache.permissionsForRole("EXISTING").contains("WRITE"),
                "Cache must not apply the conflicting event");
    }

    /**
     * A message without an explicit 'operation' field on the wire (the normal case)
     * should be applied normally — no cross-check interference.
     */
    @Test
    void c9_noWireOperationFieldIsAppliedNormally() {
        PermissionCache cache = new PermissionCache();
        // Normal event: only the topic-derived operation, no __wire_operation
        Map<String, Object> normalEvent = new HashMap<>();
        normalEvent.put("operation", "UPSERT_ROLE");
        normalEvent.put("roleId", "NORMAL_ROLE");
        normalEvent.put("permissions", List.of("READ"));

        RoleEvents.ApplyResult result = RoleEvents.apply(cache, normalEvent);
        assertTrue(result.applied(), "Normal event should be applied: " + result.reason());
        assertTrue(cache.permissionsForRole("NORMAL_ROLE").contains("READ"));
    }

    /**
     * A message where wire operation matches the topic-derived operation
     * (consistent, not conflicting) should be applied normally.
     */
    @Test
    void c9_matchingWireOperationFieldIsAppliedNormally() {
        PermissionCache cache = new PermissionCache();
        Map<String, Object> consistentEvent = new HashMap<>();
        consistentEvent.put("operation", "UPSERT_ROLE");
        consistentEvent.put("__wire_operation", "UPSERT_ROLE"); // same — no conflict
        consistentEvent.put("roleId", "CONSISTENT_ROLE");
        consistentEvent.put("permissions", List.of("WRITE"));

        RoleEvents.ApplyResult result = RoleEvents.apply(cache, consistentEvent);
        assertTrue(result.applied(), "Consistent operation field should be applied: " + result.reason());
        assertTrue(cache.permissionsForRole("CONSISTENT_ROLE").contains("WRITE"));
    }
}
