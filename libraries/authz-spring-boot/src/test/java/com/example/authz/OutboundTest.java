package com.example.authz;

import com.example.authz.context.Principals;
import com.example.authz.context.RequestContext;
import com.example.authz.context.RequestContextBuilder;
import com.example.authz.outbound.ClientCredentialsServiceIdentityProvider;
import com.example.authz.outbound.OutboundHeaders;
import com.example.authz.outbound.OutboundPropagationInterceptor;
import com.example.authz.spi.Spi;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import com.example.authz.web.AuthzRequestContext;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class OutboundTest {

    private HttpServer server;
    private int port;
    private final AtomicInteger hits = new AtomicInteger();

    /** A stub token endpoint that returns the i-th programmed response per request. */
    private record Response(int status, String body) {}

    private void startTokenServer(List<Response> responses) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/token", exchange -> {
            int i = hits.getAndIncrement();
            Response r = responses.get(Math.min(i, responses.size() - 1));
            byte[] body = r.body().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(r.status(), body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });
        server.start();
        port = server.getAddress().getPort();
    }

    @AfterEach
    void tearDown() {
        if (server != null) server.stop(0);
        RequestContextHolder.resetRequestAttributes();
    }

    private String tokenUrl() {
        return "http://127.0.0.1:" + port + "/token";
    }

    private static String tokenJson(String token) {
        return "{\"access_token\":\"" + token + "\",\"token_type\":\"Bearer\",\"expires_in\":600}";
    }

    // ---- existing tests (unchanged behaviour) --------------------------------

    @Test
    void serviceTokenIsCachedAcrossCalls() throws IOException {
        startTokenServer(List.of(new Response(200, tokenJson("token-1"))));
        var provider = new ClientCredentialsServiceIdentityProvider(
                tokenUrl(), "c", "s", Duration.ofSeconds(60), 3, 1);

        assertEquals("token-1", provider.getServiceToken());
        assertEquals("token-1", provider.getServiceToken()); // served from cache
        assertEquals(1, hits.get());
    }

    @Test
    void serviceTokenRefreshesWhenNearExpiry() throws IOException {
        startTokenServer(List.of(new Response(200, tokenJson("token-1")), new Response(200, tokenJson("token-2"))));
        // Clock skew larger than the 600s token lifetime => always considered near-expiry.
        var provider = new ClientCredentialsServiceIdentityProvider(
                tokenUrl(), "c", "s", Duration.ofSeconds(10_000), 3, 1);

        assertEquals("token-1", provider.getServiceToken());
        assertEquals("token-2", provider.getServiceToken());
        assertEquals(2, hits.get());
    }

    @Test
    void serviceTokenRetriesWithBackoffThenSucceeds() throws IOException {
        startTokenServer(List.of(
                new Response(500, "{}"), new Response(500, "{}"), new Response(200, tokenJson("ok"))));
        AtomicInteger errors = new AtomicInteger();
        var provider = new ClientCredentialsServiceIdentityProvider(
                tokenUrl(), "c", "s", Duration.ofSeconds(60), 3, 1)
                .onError(e -> errors.incrementAndGet());

        assertEquals("ok", provider.getServiceToken());
        assertEquals(3, hits.get());
        assertEquals(2, errors.get()); // two failed attempts before success
    }

    @Test
    void serviceTokenThrowsAfterExhaustingRetries() throws IOException {
        startTokenServer(List.of(new Response(500, "{}")));
        var provider = new ClientCredentialsServiceIdentityProvider(
                tokenUrl(), "c", "s", Duration.ofSeconds(60), 2, 1);

        assertThrows(RuntimeException.class, provider::getServiceToken);
    }

    @Test
    void outboundHeadersPropagateJwtServiceTokenAndTraceIds() {
        RequestContext ctx = RequestContextBuilder.build(
                new Principals.User("u1", "MANAGER"), null, "corr-1", "req-1");
        Spi.ServiceIdentityProvider provider = () -> "svc-token";

        Map<String, String> h = OutboundHeaders.build(ctx, "user-jwt", provider);
        assertEquals("Bearer user-jwt", h.get("Authorization"));
        assertEquals("svc-token", h.get("X-Service-Token"));
        assertEquals("corr-1", h.get("X-Correlation-Id"));
        assertEquals("req-1", h.get("X-Request-Id"));

        // No user JWT (service-to-service) -> no Authorization header.
        Map<String, String> h2 = OutboundHeaders.build(ctx, null, provider);
        assertFalse(h2.containsKey("Authorization"));
        assertEquals("svc-token", h2.get("X-Service-Token"));
    }

    // ---- G8: service token acquisition / validation unit tests --------------

    /**
     * G8 — success path: a reachable SSO returns a token that the provider surfaces.
     */
    @Test
    void g8_providerSuccessPathReturnsToken() throws IOException {
        startTokenServer(List.of(new Response(200, tokenJson("my-token"))));
        var provider = new ClientCredentialsServiceIdentityProvider(
                tokenUrl(), "client-id", "client-secret", Duration.ofSeconds(60), 3, 1);

        String token = provider.getServiceToken();
        assertEquals("my-token", token);
    }

    /**
     * G8 — retry-then-fail path: after exhausting all attempts the provider throws
     * and the error callback is invoked for every failed attempt.
     */
    @Test
    void g8_providerExhaustsRetriesAndThrows() throws IOException {
        startTokenServer(List.of(new Response(500, "{}")));
        AtomicInteger errorCount = new AtomicInteger();
        var provider = new ClientCredentialsServiceIdentityProvider(
                tokenUrl(), "c", "s", Duration.ofSeconds(60), 3, 1)
                .onError(e -> errorCount.incrementAndGet());

        assertThrows(RuntimeException.class, provider::getServiceToken);
        // maxAttempts=3: one onRetry per intermediate failure (2) + one onError at give-up
        assertTrue(errorCount.get() >= 1, "error callback must fire at least once");
    }

    /**
     * G4 — fail-open in OutboundHeaders: when the provider throws, X-Service-Token is
     * OMITTED but the user JWT and correlation ids are still present.
     */
    @Test
    void g4_outboundHeadersFailOpenWhenProviderThrows() {
        RequestContext ctx = RequestContextBuilder.build(
                new Principals.User("u1", "MANAGER"), null, "corr-x", "req-x");
        Spi.ServiceIdentityProvider throwingProvider = () -> {
            throw new RuntimeException("SSO unreachable");
        };

        Map<String, String> headers = OutboundHeaders.build(ctx, "user-jwt", throwingProvider);

        // User JWT and correlation ids still propagated.
        assertEquals("Bearer user-jwt", headers.get("Authorization"));
        assertEquals("corr-x", headers.get("X-Correlation-Id"));
        assertEquals("req-x", headers.get("X-Request-Id"));
        // X-Service-Token must be absent — fail-open, not fail-hard.
        assertFalse(headers.containsKey("X-Service-Token"),
                "X-Service-Token must be omitted when provider throws (fail-open)");
    }

    /**
     * F4/G5 — conditional X-Service-Token: when no provider is configured (null),
     * X-Service-Token is absent; user JWT and correlation ids are still propagated.
     */
    @Test
    void f4_outboundHeadersOmitsServiceTokenWhenNoProvider() {
        RequestContext ctx = RequestContextBuilder.build(
                new Principals.User("u2", "VIEWER"), null, "corr-y", "req-y");

        Map<String, String> headers = OutboundHeaders.build(ctx, "jwt-value", null);

        assertEquals("Bearer jwt-value", headers.get("Authorization"));
        assertEquals("corr-y", headers.get("X-Correlation-Id"));
        assertEquals("req-y", headers.get("X-Request-Id"));
        assertFalse(headers.containsKey("X-Service-Token"),
                "X-Service-Token must be absent when no provider is configured");
    }

    /**
     * G14 — null provider in interceptor: user JWT and correlation ids are propagated
     * even when serviceIdentity is null (no client-id configured).
     */
    @Test
    void g14_interceptorWithNullProviderPropagatesJwtAndTraceIds() throws Exception {
        RequestContext ctx = RequestContextBuilder.build(
                new Principals.User("u3", "ADMIN"), null, "corr-z", "req-z");
        MockHttpServletRequest httpReq = new MockHttpServletRequest();
        httpReq.setAttribute(AuthzRequestContext.CONTEXT_ATTR, ctx);
        httpReq.setAttribute(AuthzRequestContext.USER_JWT_ATTR, "jwt-z");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(httpReq));

        // null provider — no client-id configured (gap G14)
        OutboundPropagationInterceptor interceptor = new OutboundPropagationInterceptor(null);
        MockClientHttpRequest out = new MockClientHttpRequest();
        ClientHttpResponse response = interceptor.intercept(out, new byte[0],
                (request, body) -> new MockClientHttpResponse(new byte[0], HttpStatus.OK));
        response.close();

        assertEquals("Bearer jwt-z", out.getHeaders().getFirst("Authorization"));
        assertEquals("corr-z", out.getHeaders().getFirst("X-Correlation-Id"));
        assertEquals("req-z", out.getHeaders().getFirst("X-Request-Id"));
        assertNull(out.getHeaders().getFirst("X-Service-Token"),
                "X-Service-Token must be absent when no provider (G14)");
    }

    /**
     * G4 — interceptor fail-open: when the provider throws, the interceptor still
     * forwards user JWT + trace ids WITHOUT X-Service-Token and does not rethrow.
     */
    @Test
    void g4_interceptorFailOpenWhenProviderThrows() throws Exception {
        RequestContext ctx = RequestContextBuilder.build(
                new Principals.User("u4", "MANAGER"), null, "corr-q", "req-q");
        MockHttpServletRequest httpReq = new MockHttpServletRequest();
        httpReq.setAttribute(AuthzRequestContext.CONTEXT_ATTR, ctx);
        httpReq.setAttribute(AuthzRequestContext.USER_JWT_ATTR, "jwt-q");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(httpReq));

        Spi.ServiceIdentityProvider throwingProvider = () -> {
            throw new RuntimeException("SSO down");
        };
        OutboundPropagationInterceptor interceptor = new OutboundPropagationInterceptor(throwingProvider);
        MockClientHttpRequest out = new MockClientHttpRequest();

        // Must NOT throw — fail-open
        ClientHttpResponse response = assertDoesNotThrow(() ->
                interceptor.intercept(out, new byte[0],
                        (request, body) -> new MockClientHttpResponse(new byte[0], HttpStatus.OK)));
        response.close();

        assertEquals("Bearer jwt-q", out.getHeaders().getFirst("Authorization"));
        assertEquals("corr-q", out.getHeaders().getFirst("X-Correlation-Id"));
        assertNull(out.getHeaders().getFirst("X-Service-Token"),
                "X-Service-Token must be absent when provider throws (G4 fail-open)");
    }

    /**
     * A1 — proactive scheduler: verify it can start and stop cleanly without errors,
     * and that stop() is idempotent (calling stop twice does not throw).
     */
    @Test
    void a1_proactiveSchedulerStartsAndStopsCleanly() throws IOException {
        startTokenServer(List.of(new Response(200, tokenJson("tok"))));
        var provider = new ClientCredentialsServiceIdentityProvider(
                tokenUrl(), "c", "s", Duration.ofSeconds(60), 3, 1);

        assertDoesNotThrow(() -> provider.startProactiveRefresh(50_000)); // long interval — won't fire in test
        assertDoesNotThrow(provider::stop);
        assertDoesNotThrow(provider::stop); // idempotent
    }

    /**
     * G11 — startup probe is fail-open: probing an unreachable URL must not throw.
     */
    @Test
    void g11_startupProbeIsFailOpen() {
        // Port 1 is almost certainly unreachable; probe must be a no-op, not a throw.
        var provider = new ClientCredentialsServiceIdentityProvider(
                "http://127.0.0.1:1/token", "c", "s", Duration.ofSeconds(60), 1, 1);

        assertDoesNotThrow(provider::probeTokenEndpoint,
                "startup token-endpoint probe must be fail-open (G11)");
    }

    /**
     * M3 — startup probe warms the token cache: after a successful probeTokenEndpoint(),
     * the first getServiceToken() must reuse the cached token without triggering a second
     * HTTP acquisition.
     */
    @Test
    void m3_startupProbeWarmsTokenCacheOnSuccess() throws IOException {
        startTokenServer(List.of(new Response(200, tokenJson("warm-token"))));
        var provider = new ClientCredentialsServiceIdentityProvider(
                tokenUrl(), "c", "s", Duration.ofSeconds(60), 3, 1);

        // Startup probe performs a real acquisition and warms the cache.
        provider.probeTokenEndpoint();

        // Exactly one HTTP call should have been made (the warm-acquire).
        assertEquals(1, hits.get(), "probeTokenEndpoint must perform exactly one token acquisition");

        // getServiceToken() must return the warm token without a second HTTP call.
        String token = provider.getServiceToken();
        assertEquals("warm-token", token, "getServiceToken must return the cached warm token");
        assertEquals(1, hits.get(), "no second HTTP call expected after cache warm");
    }

    /**
     * M3 — startup probe fail-open when token endpoint returns a server error:
     * probeTokenEndpoint() must not throw even if the server returns HTTP 500.
     */
    @Test
    void m3_startupProbeFailOpenOnServerError() throws IOException {
        startTokenServer(List.of(new Response(500, "{}")));
        // maxAttempts=1 so retries do not slow the test
        var provider = new ClientCredentialsServiceIdentityProvider(
                tokenUrl(), "c", "s", Duration.ofSeconds(60), 1, 1);

        assertDoesNotThrow(provider::probeTokenEndpoint,
                "probeTokenEndpoint must be fail-open even when server returns 500 (M3)");
    }
}
