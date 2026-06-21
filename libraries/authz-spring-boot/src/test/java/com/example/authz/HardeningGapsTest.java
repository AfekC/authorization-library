package com.example.authz;

import com.example.authz.autoconfigure.AuthzProperties;
import com.example.authz.cache.PermissionCache;
import com.example.authz.config.ConfigException;
import com.example.authz.observability.Metrics;
import com.example.authz.sync.CacheBootstrap;
import com.example.authz.sync.DiskCache;
import com.example.authz.sync.RoleDeleteEvent;
import com.example.authz.sync.RoleEvents;
import com.example.authz.sync.RoleUpsertEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Failing-first tests for hardening gaps Q4-java, Q5-java, Q6.
 *
 * Q4-java — URL properties are validated for well-formedness (http/https scheme required).
 * Q5-java — RoleEvents rejects blank roleId and blank permission entries.
 * Q6     — CacheBootstrap.startReconciler() is idempotent (double-start is a no-op).
 */
class HardeningGapsTest {

    // =========================================================================
    // Helpers
    // =========================================================================

    private static void validate(AuthzProperties props) {
        try {
            Class<?> clazz = Class.forName("com.example.authz.autoconfigure.AuthzCoreAutoConfiguration$ConfigValidator");
            Constructor<?> ctor = clazz.getDeclaredConstructor(AuthzProperties.class);
            ctor.setAccessible(true);
            ctor.newInstance(props);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) throw re;
            throw new RuntimeException(e.getCause());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** Builds a fully valid AuthzProperties with correct http/https URLs. */
    private static AuthzProperties validProps() {
        AuthzProperties p = new AuthzProperties();
        p.setUserIssuer("https://auth.example.com");
        p.setUserJwksUri("https://auth.example.com/.well-known/jwks.json");
        p.setServiceIssuer("https://sso.example.com");
        p.setServiceJwksUri("https://sso.example.com/.well-known/jwks.json");
        p.setRoleServiceUrl("http://role-service:8080");
        p.setAudience("my-service");
        return p;
    }

    // =========================================================================
    // Q4-java — URL well-formedness validation
    // =========================================================================

    @Test
    void q4_validPropertiesPassValidation() {
        // All valid http/https URLs => must not throw
        assertDoesNotThrow(() -> validate(validProps()),
                "Q4: fully valid properties must pass ConfigValidator");
    }

    @Test
    void q4_malformedUserJwksUriThrowsConfigException() {
        AuthzProperties p = validProps();
        p.setUserJwksUri("not-a-url");
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(p),
                "Q4: malformed userJwksUri must throw ConfigException");
        assertTrue(ex.getMessage().contains("user.jwks-uri"),
                "Q4: error must mention 'user.jwks-uri', got: " + ex.getMessage());
    }

    @Test
    void q4_malformedRoleServiceUrlThrowsConfigException() {
        AuthzProperties p = validProps();
        p.setRoleServiceUrl("not://valid");
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(p),
                "Q4: malformed roleServiceUrl must throw ConfigException");
        assertTrue(ex.getMessage().contains("role-service-url"),
                "Q4: error must mention 'role-service-url', got: " + ex.getMessage());
    }

    @Test
    void q4_malformedServiceJwksUriThrowsConfigException() {
        AuthzProperties p = validProps();
        p.setServiceJwksUri("ftp://not-http");
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(p),
                "Q4: non-http/https scheme on serviceJwksUri must throw ConfigException");
        assertTrue(ex.getMessage().contains("service-jwks-uri"),
                "Q4: error must mention 'service-jwks-uri', got: " + ex.getMessage());
    }

    @Test
    void q4_malformedUserIssuerThrowsConfigException() {
        AuthzProperties p = validProps();
        p.setUserIssuer("ht tp://broken url");
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(p),
                "Q4: malformed userIssuer must throw ConfigException");
        assertTrue(ex.getMessage().contains("user.issuer"),
                "Q4: error must mention 'user.issuer', got: " + ex.getMessage());
    }

    @Test
    void q4_malformedServiceIssuerThrowsConfigException() {
        AuthzProperties p = validProps();
        p.setServiceIssuer("not-a-url-at-all");
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(p),
                "Q4: malformed serviceIssuer must throw ConfigException");
        assertTrue(ex.getMessage().contains("service-issuer"),
                "Q4: error must mention 'service-issuer', got: " + ex.getMessage());
    }

    @Test
    void q4_ftpSchemeOnUserJwksUriThrowsConfigException() {
        AuthzProperties p = validProps();
        p.setUserJwksUri("ftp://auth.example.com/jwks.json");
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(p),
                "Q4: ftp scheme is not http/https and must be rejected");
        assertTrue(ex.getMessage().contains("user.jwks-uri"),
                "Q4: error must mention 'user.jwks-uri', got: " + ex.getMessage());
    }

    @Test
    void q4_typoUrlOnRoleServiceUrlThrowsConfigException() {
        AuthzProperties p = validProps();
        p.setRoleServiceUrl("htps://role-service:8080"); // typo: htps not https
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(p),
                "Q4: typo'd URL scheme 'htps' must be rejected");
        assertTrue(ex.getMessage().contains("role-service-url"),
                "Q4: error must mention 'role-service-url', got: " + ex.getMessage());
    }

    @Test
    void q4_tokenUrlIsValidatedWhenPresent() {
        AuthzProperties p = validProps();
        p.setTokenUrl("not-a-valid-url");
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(p),
                "Q4: malformed tokenUrl must throw ConfigException when set");
        assertTrue(ex.getMessage().contains("token-url"),
                "Q4: error must mention 'token-url', got: " + ex.getMessage());
    }

    @Test
    void q4_tokenUrlNullIsAccepted() {
        // tokenUrl is optional — null must not cause a validation failure
        AuthzProperties p = validProps();
        p.setTokenUrl(null);
        assertDoesNotThrow(() -> validate(p),
                "Q4: null tokenUrl is optional and must pass validation");
    }

    @Test
    void q4_tokenUrlValidHttpsIsAccepted() {
        AuthzProperties p = validProps();
        p.setTokenUrl("https://sso.example.com/oauth/token");
        assertDoesNotThrow(() -> validate(p),
                "Q4: valid https tokenUrl must pass validation");
    }

    // =========================================================================
    // Q5-java — RoleEvents validation: blank roleId and blank permissions
    // =========================================================================

    @Test
    void q5_blankRoleIdInUpsertIsSkipped() {
        PermissionCache cache = new PermissionCache();
        RoleEvents.ApplyResult result = RoleEvents.applyUpsert(cache,
                new RoleUpsertEvent("", List.of("READ"), null));
        assertFalse(result.applied(),
                "Q5: blank roleId in UPSERT_ROLE must be skipped");
        assertNotNull(result.reason(), "Q5: skip must include a reason");
    }

    @Test
    void q5_whitespaceOnlyRoleIdInUpsertIsSkipped() {
        PermissionCache cache = new PermissionCache();
        RoleEvents.ApplyResult result = RoleEvents.applyUpsert(cache,
                new RoleUpsertEvent("   ", List.of("READ"), null));
        assertFalse(result.applied(),
                "Q5: whitespace-only roleId in UPSERT_ROLE must be skipped");
    }

    @Test
    void q5_blankRoleIdInDeleteIsSkipped() {
        PermissionCache cache = new PermissionCache(Map.of("R", List.of("READ")));
        RoleEvents.ApplyResult result = RoleEvents.applyDelete(cache,
                new RoleDeleteEvent("", null));
        assertFalse(result.applied(),
                "Q5: blank roleId in DELETE_ROLE must be skipped");
        // Cache must be unchanged
        assertFalse(cache.permissionsForRole("R").isEmpty(),
                "Q5: cache must be unchanged when DELETE_ROLE with blank roleId is skipped");
    }

    @Test
    void q5_whitespaceOnlyRoleIdInDeleteIsSkipped() {
        PermissionCache cache = new PermissionCache(Map.of("R", List.of("READ")));
        RoleEvents.ApplyResult result = RoleEvents.applyDelete(cache,
                new RoleDeleteEvent("  ", null));
        assertFalse(result.applied(),
                "Q5: whitespace-only roleId in DELETE_ROLE must be skipped");
    }

    @Test
    void q5_blankPermissionEntryInUpsertIsSkipped() {
        PermissionCache cache = new PermissionCache();
        List<String> perms = new ArrayList<>();
        perms.add("READ");
        perms.add("");      // blank permission
        perms.add("WRITE");
        RoleEvents.ApplyResult result = RoleEvents.applyUpsert(cache,
                new RoleUpsertEvent("ROLE_A", perms, null));
        assertFalse(result.applied(),
                "Q5: blank permission entry in UPSERT_ROLE must cause the event to be skipped");
    }

    @Test
    void q5_whitespaceOnlyPermissionEntryIsSkipped() {
        PermissionCache cache = new PermissionCache();
        List<String> perms = new ArrayList<>();
        perms.add("READ");
        perms.add("   ");   // whitespace-only permission
        RoleEvents.ApplyResult result = RoleEvents.applyUpsert(cache,
                new RoleUpsertEvent("ROLE_B", perms, null));
        assertFalse(result.applied(),
                "Q5: whitespace-only permission string must cause skip");
    }

    @Test
    void q5_validUpsertWithNonBlankRoleIdAndPermissionsApplies() {
        PermissionCache cache = new PermissionCache();
        RoleEvents.ApplyResult result = RoleEvents.applyUpsert(cache,
                new RoleUpsertEvent("ADMIN", List.of("READ", "WRITE"), null));
        assertTrue(result.applied(),
                "Q5: valid UPSERT_ROLE must apply: " + result.reason());
        assertTrue(cache.permissionsForRole("ADMIN").contains("READ"));
        assertTrue(cache.permissionsForRole("ADMIN").contains("WRITE"));
    }

    @Test
    void q5_validDeleteWithNonBlankRoleIdApplies() {
        PermissionCache cache = new PermissionCache(Map.of("VIEWER", List.of("READ")));
        RoleEvents.ApplyResult result = RoleEvents.applyDelete(cache,
                new RoleDeleteEvent("VIEWER", null));
        assertTrue(result.applied(),
                "Q5: valid DELETE_ROLE must apply: " + result.reason());
        assertTrue(cache.permissionsForRole("VIEWER").isEmpty(),
                "Q5: role must be deleted from cache");
    }

    @Test
    void q5_blankRoleIdDoesNotInsertPhantomEntry() {
        // Key concern: "" role must not end up in the cache
        PermissionCache cache = new PermissionCache();
        RoleEvents.applyUpsert(cache, new RoleUpsertEvent("", List.of("ADMIN"), null)); // should skip
        assertTrue(cache.permissionsForRole("").isEmpty(),
                "Q5: blank roleId must not produce a phantom '' entry in the cache");
    }

    // =========================================================================
    // Q6 — CacheBootstrap.startReconciler() idempotent double-start guard
    // =========================================================================

    @Test
    void q6_doubleStartReconcilerIsNoOp(@TempDir Path tmp) throws Exception {
        PermissionCache cache = new PermissionCache();
        Metrics metrics = new Metrics();
        CacheBootstrap boot = new CacheBootstrap(
                cache,
                () -> Map.of("R", List.of("READ")),
                new DiskCache(tmp.resolve("q6a.json")),
                metrics);
        boot.start();

        // Call startReconciler twice — second call must be a no-op
        boot.startReconciler(500);
        boot.startReconciler(500); // second call

        // Allow one reconcile cycle to run
        Thread.sleep(600);
        boot.stop();

        // If two threads were started, we'd likely see duplicated
        // ROLE_REFRESH_FAILURES on failure or duplicated version increments.
        // The key assertion: no exception was thrown and stop() works cleanly.
        // We verify the invariant indirectly: the bootstrap is still functional.
        assertFalse(cache.snapshot().isEmpty(),
                "Q6: cache must have been populated after double startReconciler");
    }

    @Test
    void q6_doubleStartDoesNotSpawnTwoReconcilerThreads(@TempDir Path tmp) throws Exception {
        // Count how many times the reconciler body executes within one interval.
        // With one thread: exactly N ticks in T seconds.
        // With two threads: roughly 2×N ticks (they'd both run concurrently).
        java.util.concurrent.atomic.AtomicInteger ticks = new java.util.concurrent.atomic.AtomicInteger();
        PermissionCache cache = new PermissionCache();

        CacheBootstrap boot = new CacheBootstrap(
                cache,
                () -> { ticks.incrementAndGet(); return Map.of("R", List.of("READ")); },
                new DiskCache(tmp.resolve("q6b.json")),
                null);
        boot.start();
        // Reset counter after start() (start() calls fullSync once itself)
        ticks.set(0);

        // Short interval so we get a few ticks quickly
        long intervalMs = 100;
        boot.startReconciler(intervalMs);
        boot.startReconciler(intervalMs); // second call — must be no-op

        Thread.sleep(420); // ~4 intervals of 100ms
        boot.stop();

        int count = ticks.get();
        // With one reconciler thread: ~3-4 ticks in 420ms at 100ms interval.
        // With two threads: ~6-8 ticks.
        // We allow up to 6 as a generous single-thread upper bound (scheduling jitter).
        assertTrue(count <= 6,
                "Q6: double startReconciler must not spawn two concurrent reconciler threads; "
                        + "ticks=" + count + " (expected <=6 for single thread in ~420ms at 100ms interval)");
    }

    @Test
    void q6_stopAndRestartIsAllowed(@TempDir Path tmp) throws Exception {
        // stop() followed by a new startReconciler() must be allowed.
        PermissionCache cache = new PermissionCache();
        java.util.concurrent.atomic.AtomicBoolean ranAfterRestart = new java.util.concurrent.atomic.AtomicBoolean(false);

        CacheBootstrap boot = new CacheBootstrap(
                cache,
                () -> { ranAfterRestart.set(true); return Map.of("R", List.of("READ")); },
                new DiskCache(tmp.resolve("q6c.json")),
                null);
        boot.start();

        // Start, then stop, then start again
        boot.startReconciler(100);
        Thread.sleep(50);
        boot.stop();

        // Reset and create a fresh bootstrap (stop() sets stopped=true so we
        // need a new instance to test restart semantics — that is the expected
        // contract: stop() terminates the instance; a new CacheBootstrap is
        // the clean restart path).
        ranAfterRestart.set(false);
        CacheBootstrap boot2 = new CacheBootstrap(
                cache,
                () -> { ranAfterRestart.set(true); return Map.of("R", List.of("READ")); },
                new DiskCache(tmp.resolve("q6c.json")),
                null);
        boot2.start();
        boot2.startReconciler(100);

        long deadline = System.currentTimeMillis() + 1000;
        while (!ranAfterRestart.get() && System.currentTimeMillis() < deadline) {
            Thread.sleep(20);
        }
        boot2.stop();

        assertTrue(ranAfterRestart.get(),
                "Q6: after stop(), a new CacheBootstrap instance must be startable");
    }

    @Test
    void q6_reconcilerStopsAfterStopCall(@TempDir Path tmp) throws Exception {
        java.util.concurrent.atomic.AtomicInteger ticks = new java.util.concurrent.atomic.AtomicInteger();
        PermissionCache cache = new PermissionCache();

        CacheBootstrap boot = new CacheBootstrap(
                cache,
                () -> { ticks.incrementAndGet(); return Map.of("R", List.of("READ")); },
                new DiskCache(tmp.resolve("q6d.json")),
                null);
        boot.start();
        ticks.set(0);

        boot.startReconciler(100);
        Thread.sleep(250); // let it run a couple of ticks
        boot.stop();

        int countAtStop = ticks.get();
        Thread.sleep(300); // wait to see if more ticks accumulate
        int countAfterWait = ticks.get();

        assertEquals(countAtStop, countAfterWait,
                "Q6: reconciler must not run after stop() is called");
    }

    // =========================================================================
    // Q7 — CacheBootstrap.startSeedRetry() with exponential backoff
    // =========================================================================

    @Test
    void q7_startSeedRetryIsNoOpWhenAlreadyNormal(@TempDir Path tmp) {
        PermissionCache cache = new PermissionCache();
        CacheBootstrap boot = new CacheBootstrap(
                cache,
                () -> Map.of("R", List.of("READ")),
                new DiskCache(tmp.resolve("q7a.json")));
        boot.start(); // succeeds → NORMAL
        // Must not throw or start a thread
        boot.startSeedRetry();
        // Should still be able to stop cleanly
        boot.stop();
    }

    @Test
    void q7_startSeedRetryPromotesSeedToNormal(@TempDir Path tmp) throws Exception {
        DiskCache disk = new DiskCache(tmp.resolve("q7b.json"));
        disk.write(new PermissionCache(Map.of("SEED", List.of("READ"))));
        PermissionCache cache = new PermissionCache();
        boolean[] up = { false };
        CacheBootstrap boot = new CacheBootstrap(
                cache,
                () -> {
                    if (!up[0]) throw new RuntimeException("down (Q7)");
                    return Map.of("R", List.of("WRITE"));
                },
                disk);
        assertEquals(CacheBootstrap.Mode.SEED, boot.start());

        up[0] = true; // Role Service comes back
        boot.startSeedRetry();

        // First tick is after 2s backoff; wait for promotion
        long deadline = System.currentTimeMillis() + 5000;
        while (boot.mode() == CacheBootstrap.Mode.SEED && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }
        boot.stop();

        assertEquals(CacheBootstrap.Mode.NORMAL, boot.mode(),
                "Q7: startSeedRetry must promote SEED→NORMAL on success");
    }

    @Test
    void q7_startSeedRetryDoesNotIncrementRoleRefreshFailures(@TempDir Path tmp) throws Exception {
        Metrics metrics = new Metrics();
        PermissionCache cache = new PermissionCache();
        DiskCache disk = new DiskCache(tmp.resolve("q7c.json"));
        disk.write(new PermissionCache(Map.of("SEED", List.of("READ"))));

        CacheBootstrap boot = new CacheBootstrap(
                cache,
                () -> { throw new RuntimeException("still down (Q7)"); },
                disk, metrics);
        assertEquals(CacheBootstrap.Mode.SEED, boot.start());

        long before = metrics.get(Metrics.ROLE_REFRESH_FAILURES);
        boot.startSeedRetry();
        // Wait for first retry tick to fail (2s sleep + margin)
        Thread.sleep(2100);
        boot.stop();

        assertEquals(before, metrics.get(Metrics.ROLE_REFRESH_FAILURES),
                "Q7: startSeedRetry must NOT increment role_refresh_failures_total");
    }

    @Test
    void q7_startSeedRetryStopsAfterStopCall(@TempDir Path tmp) throws Exception {
        DiskCache disk = new DiskCache(tmp.resolve("q7d.json"));
        disk.write(new PermissionCache(Map.of("SEED", List.of("READ"))));
        java.util.concurrent.atomic.AtomicInteger callCount = new java.util.concurrent.atomic.AtomicInteger();
        PermissionCache cache = new PermissionCache();
        CacheBootstrap boot = new CacheBootstrap(
                cache,
                () -> { callCount.incrementAndGet(); throw new RuntimeException("down (Q7)"); },
                disk);
        assertEquals(CacheBootstrap.Mode.SEED, boot.start());

        boot.startSeedRetry();
        // Stop immediately while thread is still in its first sleep
        boot.stop();
        int countAfterStop = callCount.get();

        // Wait to see if any extra fullSync calls happen after stop
        Thread.sleep(500);
        int countAfterWait = callCount.get();

        assertEquals(countAfterStop, countAfterWait,
                "Q7: seed retry must not call fullSync after stop()");
    }
}
