package com.example.authz;

import com.example.authz.audit.AuditEvent;
import com.example.authz.cache.PermissionCache;
import com.example.authz.config.YamlLoader;
import com.example.authz.context.Principals;
import com.example.authz.context.RequestContext;
import com.example.authz.context.RequestContextBuilder;
import com.example.authz.engine.AuthType;
import com.example.authz.engine.AuthorizationEngine;
import com.example.authz.engine.AuthorizationRequest;
import com.example.authz.engine.DecisionResult;
import com.example.authz.observability.Metrics;
import com.example.authz.outbound.OutboundPropagationInterceptor;
import com.example.authz.spi.Spi;
import com.example.authz.sync.CacheBootstrap;
import com.example.authz.sync.DiskCache;
import com.example.authz.web.AuthorizationFilter;
import com.example.authz.web.AuthzRequestContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ArchitectureFixesTest {

    @AfterEach
    void resetContext() {
        RequestContextHolder.resetRequestAttributes();
    }

    private static AuthorizationEngine engine(String yaml) {
        return YamlLoader.load(yaml);
    }

    /** Spi.TokenValidator whose user/service validations each throw. */
    private static final Spi.TokenValidator THROWING = new Spi.TokenValidator() {
        public Map<String, Object> validateUserToken(String jwt) { throw new RuntimeException("bad user token"); }
        public Map<String, Object> validateServiceToken(String jwt) { throw new RuntimeException("bad service token"); }
    };

    private static class CapturingSink implements Spi.AuditSink {
        AuditEvent last;
        public void emit(AuditEvent e) { this.last = e; }
    }

    // ---- §10.1 audit permission surfaced from the matched rule -------------

    @Test
    void evaluateReportsMatchedRulePermissions() {
        AuthorizationEngine e = engine("""
                rules:
                  - path: /orders
                    methods: [POST]
                    permissions: [WRITE_ORDER, ADMIN]
                    decision: ANY
                  - path: /internal/reconcile
                    methods: [POST]
                    allowedServices: [scheduler]
                """);
        PermissionCache cache = new PermissionCache(Map.of("M", List.of("WRITE_ORDER")));

        DecisionResult allow = e.evaluate(
                new AuthorizationRequest("POST", "/orders", AuthType.USER, "M", null), cache);
        assertEquals("WRITE_ORDER,ADMIN", allow.auditPermission());

        DecisionResult svcOnly = e.evaluate(
                new AuthorizationRequest("POST", "/internal/reconcile", AuthType.SERVICE, null, "scheduler"), cache);
        assertNull(svcOnly.auditPermission());

        DecisionResult noMatch = e.evaluate(
                new AuthorizationRequest("GET", "/nope", AuthType.USER, "M", null), cache);
        assertNull(noMatch.auditPermission());
    }

    // ---- §10.2 inbound token-failure metrics split by token kind -----------

    @Test
    void userTokenFailureIncrementsJwtMetricOnly() throws Exception {
        Metrics metrics = new Metrics();
        AuthorizationFilter filter = new AuthorizationFilter(
                engine("rules:\n  - path: /x\n    methods: [GET]\n    permissions: [READ]\n"),
                new PermissionCache(), THROWING, new CapturingSink(), metrics);

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/x");
        req.addHeader("Authorization", "Bearer x");
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(req, res, new MockFilterChain());

        assertEquals(HttpStatus.UNAUTHORIZED.value(), res.getStatus());
        assertEquals(1, metrics.get(Metrics.JWT_VALIDATION_FAILURES));
        assertEquals(0, metrics.get(Metrics.SERVICE_TOKEN_FAILURES));
    }

    @Test
    void serviceTokenFailureIncrementsServiceMetricOnly() throws Exception {
        Metrics metrics = new Metrics();
        AuthorizationFilter filter = new AuthorizationFilter(
                engine("rules:\n  - path: /x\n    methods: [GET]\n    permissions: [READ]\n"),
                new PermissionCache(), THROWING, new CapturingSink(), metrics);

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/x");
        req.addHeader("X-Service-Token", "y");
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(req, res, new MockFilterChain());

        assertEquals(HttpStatus.UNAUTHORIZED.value(), res.getStatus());
        assertEquals(1, metrics.get(Metrics.SERVICE_TOKEN_FAILURES));
        assertEquals(0, metrics.get(Metrics.JWT_VALIDATION_FAILURES));
    }

    // ---- §9 Spring retains the user JWT + §10.1 audit permission on ALLOW --

    @Test
    void allowStoresUserJwtAndAuditsPermission() throws Exception {
        Spi.TokenValidator validUser = new Spi.TokenValidator() {
            public Map<String, Object> validateUserToken(String jwt) { return Map.of("userId", "u1", "roleId", "R"); }
            public Map<String, Object> validateServiceToken(String jwt) { throw new RuntimeException("n/a"); }
        };
        Metrics metrics = new Metrics();
        CapturingSink sink = new CapturingSink();
        AuthorizationFilter filter = new AuthorizationFilter(
                engine("rules:\n  - path: /x\n    methods: [GET]\n    permissions: [READ]\n"),
                new PermissionCache(Map.of("R", List.of("READ"))), validUser, sink, metrics);

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/x");
        req.addHeader("Authorization", "Bearer tok-123");
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(req, res, chain);

        assertNotNull(chain.getRequest(), "ALLOW should pass the request down the chain");
        assertEquals("tok-123", req.getAttribute(AuthzRequestContext.USER_JWT_ATTR));
        assertEquals("READ", sink.last.permission());
        assertEquals(1, metrics.get(Metrics.AUTHZ_SUCCESS));
    }

    // ---- §9/§12 outbound auto-propagation interceptor ----------------------

    @Test
    void outboundInterceptorAttachesHeadersFromCurrentRequest() throws Exception {
        RequestContext ctx = RequestContextBuilder.build(
                new Principals.User("u", "R"), null, "c-1", "r-1");
        MockHttpServletRequest httpReq = new MockHttpServletRequest();
        httpReq.setAttribute(AuthzRequestContext.CONTEXT_ATTR, ctx);
        httpReq.setAttribute(AuthzRequestContext.USER_JWT_ATTR, "user-jwt");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(httpReq));

        OutboundPropagationInterceptor interceptor =
                new OutboundPropagationInterceptor(() -> "svc-tok");
        MockClientHttpRequest out = new MockClientHttpRequest();
        ClientHttpResponse response = interceptor.intercept(out, new byte[0],
                (request, body) -> new MockClientHttpResponse(new byte[0], HttpStatus.OK));
        response.close();

        assertEquals("Bearer user-jwt", out.getHeaders().getFirst("Authorization"));
        assertEquals("svc-tok", out.getHeaders().getFirst("X-Service-Token"));
        assertEquals("c-1", out.getHeaders().getFirst("X-Correlation-Id"));
        assertEquals("r-1", out.getHeaders().getFirst("X-Request-Id"));
    }

    @Test
    void outboundInterceptorIsNoOpOutsideARequest() throws Exception {
        OutboundPropagationInterceptor interceptor =
                new OutboundPropagationInterceptor(() -> "svc-tok");
        MockClientHttpRequest out = new MockClientHttpRequest();
        interceptor.intercept(out, new byte[0],
                (request, body) -> new MockClientHttpResponse(new byte[0], HttpStatus.OK)).close();
        assertNull(out.getHeaders().getFirst("X-Service-Token"));
    }

    // ---- §8.4 Kafka unreachable at startup is fail-open --------------------

    @Test
    void kafkaUnreachableAtStartupIsFailOpen(@org.junit.jupiter.api.io.TempDir Path tmp) {
        // CacheBootstrap.start() no longer manages Kafka subscription — that is
        // driven by RoleEventKafkaListener. start() must succeed (NORMAL) even
        // when no Kafka infrastructure is present, and kafkaConnected stays false
        // until the listener calls setKafkaConnected(true).
        Spi.RoleServiceClient ok = () -> Map.of("VIEWER", List.of("READ_ORDER"));
        PermissionCache cache = new PermissionCache();
        CacheBootstrap boot = new CacheBootstrap(
                cache, ok, new DiskCache(tmp.resolve("k.json")), new Metrics());

        assertEquals(CacheBootstrap.Mode.NORMAL, boot.start());
        assertFalse(boot.isKafkaConnected());
        assertTrue(cache.permissionsForRole("VIEWER").contains("READ_ORDER"));
    }
}
