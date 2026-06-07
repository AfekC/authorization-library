package com.example.authz;

import com.example.authz.cache.PermissionCache;
import com.example.authz.context.HeaderSanitizer;
import com.example.authz.context.Principals;
import com.example.authz.context.RequestContext;
import com.example.authz.context.RequestContextBuilder;
import com.example.authz.engine.AuthType;
import com.example.authz.observability.Metrics;
import com.example.authz.sync.CacheBootstrap;
import com.example.authz.sync.CacheBootstrapException;
import com.example.authz.sync.DiskCache;
import com.example.authz.sync.RoleEvents;
import com.example.authz.spi.Spi;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ModulesTest {

    @Test
    void sanitizerDropsIdentityHeadersKeepsTokens() {
        assertTrue(HeaderSanitizer.isUntrustedIdentityHeader("X-User-Id"));
        assertTrue(HeaderSanitizer.isUntrustedIdentityHeader("X-Role"));
        assertTrue(HeaderSanitizer.isUntrustedIdentityHeader("x-tenant"));
        assertFalse(HeaderSanitizer.isUntrustedIdentityHeader("Authorization"));
        assertFalse(HeaderSanitizer.isUntrustedIdentityHeader("X-Service-Token"));
        assertFalse(HeaderSanitizer.isUntrustedIdentityHeader("X-Correlation-Id"));
    }

    @Test
    void contextBuilderDerivesAuthType() {
        RequestContext both = RequestContextBuilder.build(
                new Principals.User("u1", "MANAGER", "t1", "j1"),
                new Principals.Service("scheduler", "c1"), "c-xyz", null);
        assertEquals(AuthType.USER_AND_SERVICE, both.authenticationType());
        assertEquals("u1", both.userId());
        assertEquals("c-xyz", both.correlationId());
        assertNotNull(both.requestId());

        RequestContext svc = RequestContextBuilder.build(
                null, new Principals.Service("batch", "c2"), null, null);
        assertEquals(AuthType.SERVICE, svc.authenticationType());
    }

    @Test
    void roleEventsApplyUpsertDeleteSkipUnknown() {
        PermissionCache cache = new PermissionCache(Map.of("MANAGER", List.of("READ_ORDER")));
        assertTrue(RoleEvents.apply(cache, Map.of(
                "operation", "UPSERT_ROLE", "roleId", "MANAGER",
                "permissions", List.of("READ_ORDER", "DELETE_ORDER"))).applied());
        assertTrue(cache.permissionsForRole("MANAGER").contains("DELETE_ORDER"));

        assertTrue(RoleEvents.apply(cache, Map.of("operation", "DELETE_ROLE", "roleId", "MANAGER")).applied());
        assertTrue(cache.permissionsForRole("MANAGER").isEmpty());

        assertFalse(RoleEvents.apply(cache, Map.of("operation", "FROBNICATE")).applied());
    }

    @Test
    void bootstrapNormalAndSeedModes(@org.junit.jupiter.api.io.TempDir Path tmp) {
        Spi.RoleServiceClient ok = () -> Map.of("VIEWER", List.of("READ_ORDER"));
        Spi.RoleServiceClient failing = () -> { throw new RuntimeException("unreachable"); };

        PermissionCache c1 = new PermissionCache();
        CacheBootstrap b1 = new CacheBootstrap(c1, ok, new DiskCache(tmp.resolve("n.json")));
        assertEquals(CacheBootstrap.Mode.NORMAL, b1.start());
        assertTrue(c1.permissionsForRole("VIEWER").contains("READ_ORDER"));

        DiskCache disk = new DiskCache(tmp.resolve("s.json"));
        disk.write(new PermissionCache(Map.of("MANAGER", List.of("DELETE_ORDER"))));
        PermissionCache c2 = new PermissionCache();
        CacheBootstrap b2 = new CacheBootstrap(c2, failing, disk);
        assertEquals(CacheBootstrap.Mode.SEED, b2.start());
        assertTrue(c2.permissionsForRole("MANAGER").contains("DELETE_ORDER"));
    }

    @Test
    void bootstrapFailsFastWhenRoleServiceDownAndDiskMissing(@org.junit.jupiter.api.io.TempDir Path tmp) {
        Spi.RoleServiceClient failing = () -> { throw new RuntimeException("unreachable"); };
        PermissionCache cache = new PermissionCache();
        CacheBootstrap boot = new CacheBootstrap(cache, failing, new DiskCache(tmp.resolve("missing.json")));
        assertThrows(CacheBootstrapException.class, boot::start);
    }

    @Test
    void bootstrapFailsFastWhenRoleServiceDownAndDiskEmpty(@org.junit.jupiter.api.io.TempDir Path tmp) {
        DiskCache disk = new DiskCache(tmp.resolve("empty.json"));
        disk.write(new PermissionCache()); // empty roles map
        Spi.RoleServiceClient failing = () -> { throw new RuntimeException("unreachable"); };
        PermissionCache cache = new PermissionCache();
        CacheBootstrap boot = new CacheBootstrap(cache, failing, disk);
        assertThrows(CacheBootstrapException.class, boot::start);
    }

    @Test
    void reconcilerPromotesSeedToNormal(@org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        DiskCache disk = new DiskCache(tmp.resolve("recon.json"));
        disk.write(new PermissionCache(Map.of("MANAGER", List.of("READ_ORDER"))));
        final boolean[] up = { false };
        Spi.RoleServiceClient flaky = () -> {
            if (!up[0]) throw new RuntimeException("down");
            return Map.of("MANAGER", List.of("READ_ORDER", "WRITE_ORDER"));
        };
        PermissionCache cache = new PermissionCache();
        CacheBootstrap boot = new CacheBootstrap(cache, flaky, disk);
        assertEquals(CacheBootstrap.Mode.SEED, boot.start());
        boot.startReconciler(20);
        up[0] = true;
        for (int i = 0; i < 50 && boot.mode() == CacheBootstrap.Mode.SEED; i++) Thread.sleep(20);
        boot.stop();
        assertEquals(CacheBootstrap.Mode.NORMAL, boot.mode());
        assertTrue(cache.permissionsForRole("MANAGER").contains("WRITE_ORDER"));
    }

    @Test
    void forcedRefreshReFetchesAndReplacesCache(@org.junit.jupiter.api.io.TempDir Path tmp) {
        @SuppressWarnings("unchecked")
        Map<String, List<String>>[] roles = new Map[]{ Map.of("VIEWER", List.of("READ_ORDER")) };
        Spi.RoleServiceClient client = () -> roles[0];
        PermissionCache cache = new PermissionCache();
        CacheBootstrap boot = new CacheBootstrap(cache, client, new DiskCache(tmp.resolve("r.json")));
        boot.start();
        assertFalse(cache.permissionsForRole("VIEWER").contains("WRITE_ORDER"));
        roles[0] = Map.of("VIEWER", List.of("READ_ORDER", "WRITE_ORDER"));
        boot.forcedRefresh();
        assertTrue(cache.permissionsForRole("VIEWER").contains("WRITE_ORDER"));
    }

    @Test
    void forcedRefreshIsFailOpenAndCountsFailure(@org.junit.jupiter.api.io.TempDir Path tmp) {
        boolean[] up = { true };
        Spi.RoleServiceClient client = () -> {
            if (!up[0]) throw new RuntimeException("down");
            return Map.of("VIEWER", List.of("READ_ORDER"));
        };
        Metrics metrics = new Metrics();
        PermissionCache cache = new PermissionCache();
        CacheBootstrap boot = new CacheBootstrap(cache, client, new DiskCache(tmp.resolve("rf.json")), null, metrics);
        boot.start();
        up[0] = false;
        boot.forcedRefresh();
        assertTrue(cache.permissionsForRole("VIEWER").contains("READ_ORDER")); // unchanged
        assertEquals(1, metrics.get(Metrics.ROLE_REFRESH_FAILURES));
    }

    @Test
    void diskCacheRoundTrip(@org.junit.jupiter.api.io.TempDir Path tmp) {
        Path file = tmp.resolve("rt.json");
        DiskCache disk = new DiskCache(file);
        disk.write(new PermissionCache(Map.of("VIEWER", List.of("READ_ORDER"))));
        assertTrue(Files.exists(file));
        DiskCache.Snapshot snap = disk.read();
        assertEquals(List.of("READ_ORDER"), snap.roles().get("VIEWER"));
    }
}
