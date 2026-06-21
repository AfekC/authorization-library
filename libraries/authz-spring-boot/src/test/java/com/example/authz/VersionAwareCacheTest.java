package com.example.authz;

import com.example.authz.cache.PermissionCache;
import com.example.authz.sync.RoleDeleteEvent;
import com.example.authz.sync.RoleEvents;
import com.example.authz.sync.RoleUpsertEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for T24 — version-aware cache application.
 *
 * Contract (mirrors NestJS agent):
 * - apply-iff-incoming-version-greater
 * - missing-version → apply + warn-once (backward compat)
 * - idempotent on equal/stale
 * - fail-closed: unknown role → empty perms → DENY
 */
class VersionAwareCacheTest {

    private PermissionCache cache;

    @BeforeEach
    void setUp() {
        cache = new PermissionCache();
    }

    // -------------------------------------------------------------------------
    // T24 — upsertRole with version
    // -------------------------------------------------------------------------

    @Test
    void upsertRole_withVersion_appliedOnFirstEvent() {
        boolean applied = cache.upsertRole("admin", List.of("READ", "WRITE"), 1L);
        assertTrue(applied, "first versioned event must be applied");
        assertEquals(Set.of("READ", "WRITE"), cache.permissionsForRole("admin"));
    }

    @Test
    void upsertRole_withVersion_appliedWhenNewerVersion() {
        cache.upsertRole("admin", List.of("READ"), 1L);
        boolean applied = cache.upsertRole("admin", List.of("READ", "WRITE"), 2L);
        assertTrue(applied, "newer version must be applied");
        assertEquals(Set.of("READ", "WRITE"), cache.permissionsForRole("admin"));
    }

    @Test
    void upsertRole_withVersion_skippedOnEqualVersion() {
        cache.upsertRole("admin", List.of("READ", "WRITE"), 5L);
        boolean applied = cache.upsertRole("admin", List.of("NONE"), 5L);
        assertFalse(applied, "equal version must be skipped (idempotent)");
        // Cache must retain the first application's permissions
        assertEquals(Set.of("READ", "WRITE"), cache.permissionsForRole("admin"));
    }

    @Test
    void upsertRole_withVersion_skippedOnStaleVersion() {
        cache.upsertRole("admin", List.of("READ", "WRITE"), 10L);
        boolean applied = cache.upsertRole("admin", List.of("NONE"), 9L);
        assertFalse(applied, "stale (lower) version must be skipped");
        assertEquals(Set.of("READ", "WRITE"), cache.permissionsForRole("admin"));
    }

    @Test
    void upsertRole_withVersion_tracksVersionPerKey() {
        cache.upsertRole("admin", List.of("READ"), 3L);
        cache.upsertRole("user", List.of("VIEW"), 1L);

        assertEquals(3L, cache.roleVersion("admin"));
        assertEquals(1L, cache.roleVersion("user"));
    }

    // -------------------------------------------------------------------------
    // T24 — deleteRole with version
    // -------------------------------------------------------------------------

    @Test
    void deleteRole_withVersion_appliedWhenNewerVersion() {
        cache.upsertRole("admin", List.of("READ"), 1L);
        boolean applied = cache.deleteRole("admin", 2L);
        assertTrue(applied, "delete with newer version must be applied");
        assertEquals(Set.of(), cache.permissionsForRole("admin"),
                "deleted role must return empty permissions (fail-closed)");
    }

    @Test
    void deleteRole_withVersion_skippedOnStaleVersion() {
        cache.upsertRole("admin", List.of("READ"), 5L);
        boolean applied = cache.deleteRole("admin", 3L);
        assertFalse(applied, "delete with stale version must be skipped");
        assertEquals(Set.of("READ"), cache.permissionsForRole("admin"),
                "role must remain in cache after stale delete is skipped");
    }

    @Test
    void deleteRole_withVersion_skippedOnEqualVersion() {
        cache.upsertRole("admin", List.of("READ"), 5L);
        boolean applied = cache.deleteRole("admin", 5L);
        assertFalse(applied, "delete with equal version must be skipped (idempotent)");
        assertEquals(Set.of("READ"), cache.permissionsForRole("admin"));
    }

    // -------------------------------------------------------------------------
    // T24 — backward compat: no version → always-apply
    // -------------------------------------------------------------------------

    @Test
    void upsertRole_withoutVersion_alwaysApplied() {
        cache.upsertRole("admin", List.of("READ"));
        assertEquals(Set.of("READ"), cache.permissionsForRole("admin"),
                "version-less upsert must still apply");
    }

    @Test
    void deleteRole_withoutVersion_alwaysApplied() {
        cache.upsertRole("admin", List.of("READ"));
        cache.deleteRole("admin");
        assertEquals(Set.of(), cache.permissionsForRole("admin"),
                "version-less delete must still apply");
    }

    // -------------------------------------------------------------------------
    // T24 — RoleEvents.apply with version field
    // -------------------------------------------------------------------------

    @Test
    void roleEvents_applyUpsert_withVersion_applied() {
        RoleEvents.ApplyResult result = RoleEvents.applyUpsert(cache,
                new RoleUpsertEvent("editor", List.of("EDIT"), 1L));
        assertTrue(result.applied(), "versioned UPSERT_ROLE must be applied");
        assertEquals(Set.of("EDIT"), cache.permissionsForRole("editor"));
    }

    @Test
    void roleEvents_applyUpsert_withVersion_skippedStale() {
        // First apply version=5
        RoleEvents.applyUpsert(cache, new RoleUpsertEvent("editor", List.of("EDIT"), 5L));

        // Stale event version=3 — must be skipped
        RoleEvents.ApplyResult result = RoleEvents.applyUpsert(cache,
                new RoleUpsertEvent("editor", List.of("NONE"), 3L));
        assertFalse(result.applied(), "stale versioned event must be skipped");
        assertEquals(RoleEvents.ApplyResult.SKIPPED_STALE, result.reason(),
                "reason must indicate stale version");
        // Permissions must remain from the first (higher-version) event
        assertEquals(Set.of("EDIT"), cache.permissionsForRole("editor"));
    }

    @Test
    void roleEvents_applyDelete_withVersion_skippedStale() {
        RoleEvents.applyUpsert(cache, new RoleUpsertEvent("editor", List.of("EDIT"), 10L));

        RoleEvents.ApplyResult result = RoleEvents.applyDelete(cache,
                new RoleDeleteEvent("editor", 7L));
        assertFalse(result.applied(), "stale delete must be skipped");
        assertEquals(Set.of("EDIT"), cache.permissionsForRole("editor"),
                "role must not be deleted by stale versioned delete");
    }

    @Test
    void roleEvents_applyDelete_withVersion_appliedWhenNewer() {
        RoleEvents.applyUpsert(cache, new RoleUpsertEvent("editor", List.of("EDIT"), 10L));

        RoleEvents.ApplyResult result = RoleEvents.applyDelete(cache,
                new RoleDeleteEvent("editor", 11L));
        assertTrue(result.applied(), "newer delete must be applied");
        assertEquals(Set.of(), cache.permissionsForRole("editor"),
                "deleted role must return empty permissions");
    }

    @Test
    void roleEvents_applyUpsert_withoutVersion_alwaysApplied() {
        // No version — backward compat path; must apply unconditionally
        RoleEvents.ApplyResult result = RoleEvents.applyUpsert(cache,
                new RoleUpsertEvent("viewer", List.of("VIEW"), null));
        assertTrue(result.applied(), "version-less event must always be applied");
        assertEquals(Set.of("VIEW"), cache.permissionsForRole("viewer"));
    }

    // -------------------------------------------------------------------------
    // T24 — extractVersion helper
    // -------------------------------------------------------------------------

    @Test
    void extractVersion_returnsNullWhenAbsent() {
        assertNull(RoleEvents.extractVersion(Map.of("roleId", "x")));
    }

    @Test
    void extractVersion_parsesLong() {
        assertEquals(42L, RoleEvents.extractVersion(Map.of("version", 42L)));
    }

    @Test
    void extractVersion_parsesInteger() {
        assertEquals(7L, RoleEvents.extractVersion(Map.of("version", 7)));
    }

    @Test
    void extractVersion_parsesStringNumber() {
        assertEquals(99L, RoleEvents.extractVersion(Map.of("version", "99")));
    }

    @Test
    void extractVersion_returnsNullForUnparseableString() {
        assertNull(RoleEvents.extractVersion(Map.of("version", "not-a-number")));
    }

    // -------------------------------------------------------------------------
    // T24 — replaceAll clears version state
    // -------------------------------------------------------------------------

    @Test
    void replaceAll_clearsVersionTracking() {
        // Start: apply version=10 event
        cache.upsertRole("admin", List.of("READ"), 10L);
        assertEquals(10L, cache.roleVersion("admin"), "pre-condition: version 10 stored");

        // replaceAll (reconciler full snapshot) must clear tracked versions
        cache.replaceAll(Map.of("admin", List.of("READ", "WRITE")));
        assertNull(cache.roleVersion("admin"), "after replaceAll, version tracking must be cleared");

        // After replaceAll, a version=1 event (which would normally be stale vs v=10)
        // must now be applied since version tracking was reset
        boolean applied = cache.upsertRole("admin", List.of("NONE"), 1L);
        assertTrue(applied, "after replaceAll, version=1 is accepted (tracking was reset)");
        assertEquals(1L, cache.roleVersion("admin"), "version=1 is now the stored version");
        assertEquals(Set.of("NONE"), cache.permissionsForRole("admin"),
                "permissions must reflect the post-replaceAll update");
    }

    // -------------------------------------------------------------------------
    // Fail-closed: unknown role → empty set → DENY
    // -------------------------------------------------------------------------

    @Test
    void unknownRole_returnsEmptyPermissions() {
        assertEquals(Set.of(), cache.permissionsForRole("nonexistent"),
                "unknown role must return empty permissions (fail-closed)");
    }

    @Test
    void nullRole_returnsEmptyPermissions() {
        assertEquals(Set.of(), cache.permissionsForRole(null),
                "null role must return empty permissions (fail-closed)");
    }

    // -------------------------------------------------------------------------
    // Out-of-order Kafka event simulation (T24 primary scenario)
    // -------------------------------------------------------------------------

    @Test
    void outOfOrderKafkaEvents_laterVersionWins() {
        // Simulate two Kafka events arriving out of order: version=3 arrives first, then version=2
        // The cache must retain version=3's permissions even after version=2 arrives
        cache.upsertRole("ops", List.of("DEPLOY"), 3L);
        cache.upsertRole("ops", List.of("VIEW_ONLY"), 2L); // stale — must be ignored

        assertEquals(Set.of("DEPLOY"), cache.permissionsForRole("ops"),
                "out-of-order stale event must not regress the cache");
    }

    @Test
    void idempotentRedelivery_sameVersionSkipped() {
        // Kafka exactly-once is not guaranteed; same event may be redelivered
        cache.upsertRole("ops", List.of("DEPLOY"), 5L);
        boolean secondApply = cache.upsertRole("ops", List.of("DEPLOY"), 5L);
        assertFalse(secondApply, "redelivered event with same version must be skipped (idempotent)");
    }
}
