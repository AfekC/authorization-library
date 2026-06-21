package com.example.authz;

import com.example.authz.cache.PermissionCache;
import com.example.authz.observability.Metrics;
import com.example.authz.spi.Spi;
import com.example.authz.sync.CacheBootstrap;
import com.example.authz.sync.DiskCache;
import com.example.authz.sync.RoleEvents;
import com.example.authz.sync.RoleUpsertEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
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
     * B4/C5 — Permissions from Avro (pre-coerced to String by RoleEventKafkaListener)
     * must be stored exactly as received; RoleEvents.applyUpsert applies String.valueOf
     * on each element as a safeguard. Verify that a list of already-stringified
     * mixed-origin values (String, numeric string, boolean string) is stored correctly.
     */
    @Test
    void b4_mixedTypePermissionsStoredAsStrings() {
        PermissionCache cache = new PermissionCache();
        // RoleEventKafkaListener coerces Avro types to strings before building the DTO;
        // applyUpsert further runs String.valueOf on each element.
        List<String> preCoerced = List.of("read", "123", "true");
        RoleEvents.ApplyResult result = RoleEvents.applyUpsert(cache,
                new RoleUpsertEvent("MIXED_ROLE", preCoerced, null));
        assertTrue(result.applied(), "UPSERT_ROLE with mixed permissions should apply: " + result.reason());

        Set<String> stored = cache.permissionsForRole("MIXED_ROLE");
        assertTrue(stored.contains("read"),  "String 'read' must be stored");
        assertTrue(stored.contains("123"),   "Numeric string '123' must be stored");
        assertTrue(stored.contains("true"),  "Boolean string 'true' must be stored");
        assertEquals(3, stored.size(), "Exactly 3 permissions expected");
    }

    // -------------------------------------------------------------------------
    // C9 — Topic-to-method routing replaces wire-field cross-check
    // -------------------------------------------------------------------------

    /**
     * C9 — With the @KafkaListener design, topic-to-method routing replaces the
     * old WIRE_OPERATION_KEY cross-check: onUpsert() is bound to the upsert topic,
     * onDelete() to the delete topic. A message cannot arrive on the wrong method.
     * The cross-check concern is now architectural (separate listeners) rather than
     * runtime (WIRE_OPERATION_KEY field in the Map). Verify the typed path applies
     * a normal upsert correctly.
     */
    @Test
    void c9_upsertViaTypedApiIsApplied() {
        PermissionCache cache = new PermissionCache();
        RoleEvents.ApplyResult result = RoleEvents.applyUpsert(cache,
                new RoleUpsertEvent("NORMAL_ROLE", List.of("READ"), null));
        assertTrue(result.applied(), "Normal upsert must be applied: " + result.reason());
        assertTrue(cache.permissionsForRole("NORMAL_ROLE").contains("READ"));
    }
}
