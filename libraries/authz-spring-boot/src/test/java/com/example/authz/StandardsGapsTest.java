package com.example.authz;

import com.example.authz.cache.PermissionCache;
import com.example.authz.config.ConfigException;
import com.example.authz.config.RuleCompiler;
import com.example.authz.observability.Metrics;
import com.example.authz.outbound.ClientCredentialsServiceIdentityProvider;
import com.example.authz.spi.Spi;
import com.example.authz.sync.CacheBootstrap;
import com.example.authz.sync.DiskCache;
import com.example.authz.sync.HttpRoleServiceClient;
import com.example.authz.web.NimbusJwksTokenValidator;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for standards-audit gap fixes (general best-practice alignment):
 *   J6  — RuleCompiler rejects blank permission / allowedService entries (fail-fast config)
 *   J2  — DiskCache.write() is atomic; disk write failure is non-fatal in CacheBootstrap
 *   J10 — HttpRoleServiceClient rejects malformed Role Service snapshots
 *   J1  — NimbusJwksTokenValidator applies an explicit JWKS fetch timeout
 *   J5  — ClientCredentials token-endpoint timeout is applied to acquisition
 */
class StandardsGapsTest {

    // ---- Shared local HTTP stub (serves any path) ---------------------------

    private HttpServer stubServer;
    private final AtomicReference<byte[]> responseBody = new AtomicReference<>();
    private final AtomicReference<Integer> responseStatus = new AtomicReference<>(200);
    private final AtomicReference<Long> sleepMs = new AtomicReference<>(0L);
    private int stubPort;

    @BeforeEach
    void startStub() throws IOException {
        stubServer = HttpServer.create(new InetSocketAddress(0), 0);
        stubServer.createContext("/", exchange -> {
            long delay = sleepMs.get();
            if (delay > 0) {
                try { Thread.sleep(delay); } catch (InterruptedException ignored) {}
            }
            byte[] body = responseBody.get();
            if (body == null) body = new byte[0];
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(responseStatus.get(), body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });
        stubServer.start();
        stubPort = stubServer.getAddress().getPort();
    }

    @AfterEach
    void stopStub() {
        if (stubServer != null) stubServer.stop(0);
        sleepMs.set(0L);
        responseStatus.set(200);
        responseBody.set(null);
    }

    private String stubUrl() {
        return "http://localhost:" + stubPort;
    }

    private void serveJson(String json) {
        responseBody.set(json.getBytes(StandardCharsets.UTF_8));
        responseStatus.set(200);
    }

    private static Map<String, Object> rule(String path, List<String> methods, String permKey, Object permVal) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("path", path);
        m.put("methods", methods);
        m.put(permKey, permVal);
        return m;
    }

    // =========================================================================
    // J6 — RuleCompiler rejects blank entries
    // =========================================================================

    @Test
    void j6_blankPermissionIsRejected() {
        List<Map<String, Object>> rules =
                List.of(rule("/a", List.of("GET"), "permissions", List.of("READ", "", "WRITE")));
        ConfigException ex = assertThrows(ConfigException.class, () -> RuleCompiler.compile(rules));
        assertTrue(ex.getMessage().contains("blank"), "message should mention the blank entry: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("permissions"));
    }

    @Test
    void j6_blankAllowedServiceIsRejected() {
        List<Map<String, Object>> rules =
                List.of(rule("/a", List.of("GET"), "allowedServices", List.of("svc-a", "   ")));
        ConfigException ex = assertThrows(ConfigException.class, () -> RuleCompiler.compile(rules));
        assertTrue(ex.getMessage().contains("allowedServices"));
    }

    @Test
    void j6_validRuleStillCompiles() {
        List<Map<String, Object>> rules =
                List.of(rule("/a", List.of("GET"), "permissions", List.of("READ", "WRITE")));
        assertEquals(1, RuleCompiler.compile(rules).size());
    }

    // =========================================================================
    // J2 — atomic disk write + non-fatal write failure
    // =========================================================================

    @Test
    void j2_atomicWriteLeavesNoTempFileOnSuccess(@TempDir Path tmp) throws IOException {
        Path target = tmp.resolve("cache.json");
        new DiskCache(target).write(new PermissionCache(Map.of("ADMIN", List.of("READ"))));
        assertTrue(Files.exists(target));
        try (Stream<Path> entries = Files.list(tmp)) {
            long tmpCount = entries.filter(p -> p.getFileName().toString().endsWith(".tmp")).count();
            assertEquals(0, tmpCount, "no temp files should remain after a successful atomic write");
        }
    }

    @Test
    void j2_writeFailureCreatesNoPartialTargetFile(@TempDir Path tmp) {
        // Parent directory does not exist -> the temp write fails before any move,
        // so the target file is never created (no partial/empty file).
        Path target = tmp.resolve("missing-subdir").resolve("cache.json");
        assertThrows(RuntimeException.class,
                () -> new DiskCache(target).write(new PermissionCache(Map.of("A", List.of("R")))));
        assertFalse(Files.exists(target));
    }

    @Test
    void j2_diskWriteFailureIsNonFatalAndCounted(@TempDir Path tmp) {
        PermissionCache cache = new PermissionCache();
        Metrics metrics = new Metrics();
        Spi.RoleServiceClient role = () -> Map.of("ADMIN", List.of("READ"));
        // DiskCache pointed at a missing dir -> write() throws; bootstrap must
        // treat it as non-fatal (NORMAL mode, not SEED) and count the failure.
        DiskCache failingDisk = new DiskCache(tmp.resolve("missing-subdir").resolve("c.json"));

        CacheBootstrap boot = new CacheBootstrap(cache, role, failingDisk, metrics);
        CacheBootstrap.Mode mode = boot.start();

        assertEquals(CacheBootstrap.Mode.NORMAL, mode,
                "a disk write failure after a successful fetch must not drop to SEED mode");
        assertEquals(1L, metrics.get(Metrics.DISK_CACHE_WRITE_FAILURES));
        assertTrue(cache.permissionsForRole("ADMIN").contains("READ"));
    }

    // =========================================================================
    // J10 — Role Service snapshot validation
    // =========================================================================

    @Test
    void j10_blankRoleIdIsRejected() {
        serveJson("{\"\":[\"READ\"]}");
        HttpRoleServiceClient client = new HttpRoleServiceClient(stubUrl(), 2000, 2000);
        assertThrows(RuntimeException.class, client::fetchSnapshot);
    }

    @Test
    void j10_nullPermissionsListIsRejected() {
        serveJson("{\"ADMIN\":null}");
        HttpRoleServiceClient client = new HttpRoleServiceClient(stubUrl(), 2000, 2000);
        assertThrows(RuntimeException.class, client::fetchSnapshot);
    }

    @Test
    void j10_blankPermissionEntryIsRejected() {
        serveJson("{\"ADMIN\":[\"READ\",\"\"]}");
        HttpRoleServiceClient client = new HttpRoleServiceClient(stubUrl(), 2000, 2000);
        assertThrows(RuntimeException.class, client::fetchSnapshot);
    }

    @Test
    void j10_validSnapshotIsAccepted() {
        serveJson("{\"ADMIN\":[\"READ\",\"WRITE\"],\"VIEWER\":[\"READ\"]}");
        HttpRoleServiceClient client = new HttpRoleServiceClient(stubUrl(), 2000, 2000);
        Map<String, List<String>> snapshot = client.fetchSnapshot();
        assertEquals(List.of("READ", "WRITE"), snapshot.get("ADMIN"));
        assertEquals(List.of("READ"), snapshot.get("VIEWER"));
    }

    // =========================================================================
    // J1 — JWKS fetch timeout is applied (slow JWKS must not hang validation)
    // =========================================================================

    @Test
    void j1_jwksTimeoutIsApplied() {
        sleepMs.set(10_000L);      // JWKS endpoint would block for 10s
        serveJson("{\"keys\":[]}");
        NimbusJwksTokenValidator validator = new NimbusJwksTokenValidator(
                "https://issuer.test", stubUrl() + "/jwks",
                "https://svc-issuer.test", stubUrl() + "/jwks",
                "api://aud", "token_use", "service",
                5,        // clock skew seconds
                200);     // jwksTimeoutMs — much smaller than the 10s server delay

        String token = fakeJwt();
        // With the timeout applied, validation fails fast (~200ms). Without it,
        // the call would block for the full 10s server delay and blow the bound.
        assertTimeoutPreemptively(Duration.ofSeconds(5),
                () -> assertThrows(RuntimeException.class, () -> validator.validateUserToken(token)));
    }

    // =========================================================================
    // J5 — token-endpoint timeout is applied to actual acquisition
    // =========================================================================

    @Test
    void j5_tokenEndpointTimeoutIsApplied() {
        sleepMs.set(10_000L);      // token endpoint would block for 10s
        serveJson("{\"access_token\":\"x\",\"token_type\":\"bearer\",\"expires_in\":3600}");
        ClientCredentialsServiceIdentityProvider provider =
                new ClientCredentialsServiceIdentityProvider(
                        stubUrl() + "/token", "client", "secret",
                        Duration.ofSeconds(60),
                        2,     // attempts
                        10,    // base backoff ms
                        200);  // token endpoint timeout ms

        // 2 attempts * ~200ms timeout + small backoff << 6s. Without the timeout
        // the first attempt alone would block for 10s and blow the bound.
        assertTimeoutPreemptively(Duration.ofSeconds(6),
                () -> assertThrows(RuntimeException.class, provider::getServiceToken));
    }

    /** A structurally valid EdDSA JWT (fake signature) so the decoder proceeds to fetch JWKS. */
    private static String fakeJwt() {
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        String header = enc.encodeToString(
                "{\"alg\":\"EdDSA\",\"kid\":\"test-key\"}".getBytes(StandardCharsets.UTF_8));
        String payload = enc.encodeToString(
                "{\"sub\":\"alice\",\"iss\":\"https://issuer.test\"}".getBytes(StandardCharsets.UTF_8));
        String sig = enc.encodeToString("not-a-real-signature".getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + "." + sig;
    }
}
