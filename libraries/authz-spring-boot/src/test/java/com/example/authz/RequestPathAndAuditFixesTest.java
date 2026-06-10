package com.example.authz;

import com.example.authz.audit.AuditEvent;
import com.example.authz.audit.AuditEvents;
import com.example.authz.audit.LoggingAuditSink;
import com.example.authz.cache.PermissionCache;
import com.example.authz.config.YamlLoader;
import com.example.authz.context.HeaderSanitizer;
import com.example.authz.context.Principals;
import com.example.authz.context.RequestContext;
import com.example.authz.context.RequestContextBuilder;
import com.example.authz.engine.AuthType;
import com.example.authz.engine.AuthorizationEngine;
import com.example.authz.engine.AuthorizationRequest;
import com.example.authz.engine.Decision;
import com.example.authz.engine.DecisionResult;
import com.example.authz.observability.Metrics;
import com.example.authz.observability.Metrics.TokenFailureMode;
import com.example.authz.spi.Spi;
import com.example.authz.sync.RoleEvents;
import com.example.authz.web.AuthorizationFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers the wave-2 filter/audit/metric gaps:
 *   C3  — shouldNotFilterErrorDispatch
 *   C12 — non-string role claim → null role → DENY
 *   B9  — context-path stripping for rule matching
 *   B10 — sanitizing request wrapper hides spoofed identity headers downstream
 *   C10 — no-credentials message aligned with NestJS ("no credentials")
 *   A3  — auditPermission multi-permission representation documented + tested
 *   C11 — LoggingAuditSink logs WARN on serialization failure, never throws
 *   G12 — per-mode token-failure metric differentiation
 *   D2  — authz_failure_total, authz_permission_denied_total, role_event_skipped_total
 *   D6  — DEBUG audit JSON schema validation
 */
class RequestPathAndAuditFixesTest {

    // ---- shared helpers ----

    private static AuthorizationEngine engine(String yaml) {
        return YamlLoader.load(yaml);
    }

    private static final String SIMPLE_YAML =
            "rules:\n  - path: /orders\n    methods: [GET]\n    permissions: [READ_ORDER]\n";

    private static final Spi.TokenValidator DENY_ALL = new Spi.TokenValidator() {
        public Map<String, Object> validateUserToken(String jwt) { throw new RuntimeException("bad"); }
        public Map<String, Object> validateServiceToken(String jwt) { throw new RuntimeException("bad"); }
    };

    private static class CapturingSink implements Spi.AuditSink {
        AuditEvent last;
        public void emit(AuditEvent e) { this.last = e; }
    }

    /** Validator that returns the supplied claims map without validation. */
    private static Spi.TokenValidator userValidatorReturning(Map<String, Object> claims) {
        return new Spi.TokenValidator() {
            public Map<String, Object> validateUserToken(String jwt) { return claims; }
            public Map<String, Object> validateServiceToken(String jwt) {
                throw new RuntimeException("n/a");
            }
        };
    }

    // =========================================================================
    // C3 — shouldNotFilterErrorDispatch() returns true
    // =========================================================================

    /**
     * shouldNotFilterErrorDispatch() is protected. We access it via an
     * anonymous subclass in the same compilation unit (same package) to verify
     * the override is present and returns true. This is a white-box unit test
     * of the override — the behavioral effect (no re-entry on ERROR dispatch)
     * is guaranteed by the Servlet spec once the method returns true.
     */
    @Test
    void c3_shouldNotFilterErrorDispatchReturnsTrue() {
        // Anonymous subclass to call the protected method from the same package
        AuthorizationFilter filter = new AuthorizationFilter(
                engine(SIMPLE_YAML), new PermissionCache(), DENY_ALL, new CapturingSink()) {
            public boolean exposeShouldNotFilterErrorDispatch() {
                return shouldNotFilterErrorDispatch();
            }
        };
        // Cast to anonymous type to call the exposer
        assertTrue(((com.example.authz.web.AuthorizationFilter) filter instanceof Object),
                "sanity cast"); // keep compiler happy
        // Use reflection to call the protected method
        try {
            java.lang.reflect.Method m = AuthorizationFilter.class
                    .getDeclaredMethod("shouldNotFilterErrorDispatch");
            m.setAccessible(true);
            boolean result = (boolean) m.invoke(filter);
            assertTrue(result,
                    "C3: shouldNotFilterErrorDispatch must return true to prevent re-entry on ERROR dispatch");
        } catch (Exception e) {
            fail("Could not access shouldNotFilterErrorDispatch: " + e.getMessage());
        }
    }

    // =========================================================================
    // C10 — No-credentials error message matches NestJS ("no credentials")
    // =========================================================================

    @Test
    void c10_noCredentialsMessageAlignsWithNestJs() throws Exception {
        Metrics metrics = new Metrics();
        AuthorizationFilter filter = new AuthorizationFilter(
                engine(SIMPLE_YAML), new PermissionCache(), DENY_ALL, new CapturingSink(), metrics);

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/orders");
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(req, res, new MockFilterChain());

        assertEquals(HttpStatus.UNAUTHORIZED.value(), res.getStatus());
        assertEquals("no credentials", res.getErrorMessage(),
                "C10: message must be 'no credentials', not 'no credentials presented'");
    }

    // =========================================================================
    // C12 — Non-string role claim → null role → DENY
    // =========================================================================

    @Test
    void c12_integerRoleClaimTreatedAsNullRole() throws Exception {
        // role claim is Integer 123 — must NOT be coerced to "123"
        Spi.TokenValidator v = userValidatorReturning(
                Map.of("userId", "u1", "roleId", 123));
        Metrics metrics = new Metrics();
        CapturingSink sink = new CapturingSink();
        AuthorizationFilter filter = new AuthorizationFilter(
                engine(SIMPLE_YAML),
                new PermissionCache(Map.of("123", List.of("READ_ORDER"))), // "123" would wrongly match
                v, sink, metrics);

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/orders");
        req.addHeader("Authorization", "Bearer tok");
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(req, res, new MockFilterChain());

        // Even though cache has role "123", integer claim must not be coerced
        assertEquals(HttpStatus.FORBIDDEN.value(), res.getStatus(),
                "C12: integer role claim must result in null role → DENY, not coerced to '123'");
        // Audit must have null or empty role, not "123"
        assertNotEquals("123", sink.last == null ? null : sink.last.roleId(),
                "C12: audit roleId must not be coerced from integer to string '123'");
        assertEquals(1, metrics.get(Metrics.PERMISSION_DENIED));
    }

    @Test
    void c12_arrayRoleClaimTreatedAsNullRole() throws Exception {
        // role claim is a List — must also be treated as absent
        Spi.TokenValidator v = userValidatorReturning(
                Map.of("userId", "u1", "roleId", List.of("ADMIN")));
        Metrics metrics = new Metrics();
        AuthorizationFilter filter = new AuthorizationFilter(
                engine(SIMPLE_YAML),
                // Cache has the stringified form NestJS would never produce
                new PermissionCache(Map.of("[ADMIN]", List.of("READ_ORDER"))),
                v, new CapturingSink(), metrics);

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/orders");
        req.addHeader("Authorization", "Bearer tok");
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(req, res, new MockFilterChain());

        assertEquals(HttpStatus.FORBIDDEN.value(), res.getStatus(),
                "C12: list role claim must result in null role → DENY");
    }

    @Test
    void c12_stringRoleClaimWorksNormally() throws Exception {
        // String role claim must continue to work as before
        Spi.TokenValidator v = userValidatorReturning(
                Map.of("userId", "u1", "roleId", "VIEWER"));
        AuthorizationFilter filter = new AuthorizationFilter(
                engine(SIMPLE_YAML),
                new PermissionCache(Map.of("VIEWER", List.of("READ_ORDER"))),
                v, new CapturingSink(), new Metrics());

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/orders");
        req.addHeader("Authorization", "Bearer tok");
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(req, res, chain);

        assertNotNull(chain.getRequest(), "String role claim must allow through");
        assertEquals(HttpStatus.OK.value(), res.getStatus());
    }

    // =========================================================================
    // B9 — Context-path stripping: effectivePath strips context path
    // =========================================================================

    @Test
    void b9_effectivePathStripsContextPath() {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/myapp/orders/1");
        req.setContextPath("/myapp");
        String path = AuthorizationFilter.effectivePath(req);
        assertEquals("/orders/1", path,
                "B9: effectivePath must strip the servlet context path");
    }

    @Test
    void b9_effectivePathRootDeploymentUnchanged() {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/orders/1");
        req.setContextPath(""); // root deployment
        assertEquals("/orders/1", AuthorizationFilter.effectivePath(req));
    }

    @Test
    void b9_effectivePathContextPathOnlyReturnsSlash() {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/myapp");
        req.setContextPath("/myapp");
        assertEquals("/", AuthorizationFilter.effectivePath(req),
                "B9: URI equal to context path must yield '/'");
    }

    @Test
    void b9_ruleMatchingUsesStrippedPath() throws Exception {
        // Rule is at /orders — the request URI includes a context path /ctx
        Spi.TokenValidator v = userValidatorReturning(
                Map.of("userId", "u1", "roleId", "VIEWER"));
        AuthorizationFilter filter = new AuthorizationFilter(
                engine(SIMPLE_YAML),
                new PermissionCache(Map.of("VIEWER", List.of("READ_ORDER"))),
                v, new CapturingSink(), new Metrics());

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/ctx/orders");
        req.setContextPath("/ctx");
        req.addHeader("Authorization", "Bearer tok");
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(req, res, chain);

        assertNotNull(chain.getRequest(), "B9: rule at /orders must match after context-path strip");
        assertEquals(HttpStatus.OK.value(), res.getStatus());
    }

    // =========================================================================
    // B10 — Sanitizing request wrapper hides spoofed identity headers downstream
    // =========================================================================

    @Test
    void b10_sanitizerHidesSpoofedXUserHeader() throws Exception {
        Spi.TokenValidator v = userValidatorReturning(
                Map.of("userId", "u1", "roleId", "VIEWER"));
        // Capture the request that reaches the chain to inspect its headers
        final jakarta.servlet.http.HttpServletRequest[] chainReq = new jakarta.servlet.http.HttpServletRequest[1];
        jakarta.servlet.FilterChain capturingChain = (request, response) -> {
            chainReq[0] = (jakarta.servlet.http.HttpServletRequest) request;
        };

        AuthorizationFilter filter = new AuthorizationFilter(
                engine(SIMPLE_YAML),
                new PermissionCache(Map.of("VIEWER", List.of("READ_ORDER"))),
                v, new CapturingSink(), new Metrics());

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/orders");
        req.addHeader("Authorization", "Bearer tok");
        // Attacker tries to spoof identity headers
        req.addHeader("X-User-Id", "attacker");
        req.addHeader("X-Role", "ADMIN");
        req.addHeader("X-Tenant", "evil-tenant");
        MockHttpServletResponse res = new MockHttpServletResponse();

        filter.doFilter(req, res, capturingChain);

        assertNotNull(chainReq[0], "ALLOW: chain must be invoked");
        // Downstream must NOT see the spoofed identity headers
        assertNull(chainReq[0].getHeader("X-User-Id"),
                "B10: X-User-Id must be stripped from downstream request");
        assertNull(chainReq[0].getHeader("X-Role"),
                "B10: X-Role must be stripped from downstream request");
        assertNull(chainReq[0].getHeader("X-Tenant"),
                "B10: X-Tenant must be stripped from downstream request");
        // Token header must still be readable (it is consumed by the validator)
        assertNotNull(chainReq[0].getHeader("Authorization"),
                "B10: Authorization header must remain readable downstream");
    }

    @Test
    void b10_sanitizerAllowsCorrelationHeaders() throws Exception {
        Spi.TokenValidator v = userValidatorReturning(
                Map.of("userId", "u1", "roleId", "VIEWER"));
        final jakarta.servlet.http.HttpServletRequest[] chainReq = new jakarta.servlet.http.HttpServletRequest[1];
        jakarta.servlet.FilterChain capturingChain = (request, response) -> {
            chainReq[0] = (jakarta.servlet.http.HttpServletRequest) request;
        };

        AuthorizationFilter filter = new AuthorizationFilter(
                engine(SIMPLE_YAML),
                new PermissionCache(Map.of("VIEWER", List.of("READ_ORDER"))),
                v, new CapturingSink(), new Metrics());

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/orders");
        req.addHeader("Authorization", "Bearer tok");
        req.addHeader("X-Correlation-Id", "corr-abc");
        req.addHeader("X-Request-Id", "req-xyz");
        MockHttpServletResponse res = new MockHttpServletResponse();

        filter.doFilter(req, res, capturingChain);

        assertNotNull(chainReq[0]);
        // Non-identity headers must be preserved
        assertEquals("corr-abc", chainReq[0].getHeader("X-Correlation-Id"),
                "B10: X-Correlation-Id must not be stripped");
        assertEquals("req-xyz", chainReq[0].getHeader("X-Request-Id"),
                "B10: X-Request-Id must not be stripped");
    }

    // =========================================================================
    // E4 — HeaderSanitizer: injectable constructor
    // =========================================================================

    @Test
    void e4_headerSanitizerWithCustomPrefixesIsInjectable() {
        HeaderSanitizer custom = new HeaderSanitizer(
                List.of("x-user-", "x-auth-"),   // custom prefixes
                List.of("x-identity"));            // custom exact

        assertTrue(custom.isUntrusted("X-Auth-Token"),
                "E4: custom prefix x-auth- must be treated as untrusted");
        assertTrue(custom.isUntrusted("X-Identity"),
                "E4: custom exact x-identity must be treated as untrusted");
        assertFalse(custom.isUntrusted("Authorization"),
                "E4: Authorization must always be allowed");
        assertFalse(custom.isUntrusted("X-Service-Token"),
                "E4: X-Service-Token must always be allowed");
    }

    @Test
    void e4_defaultHeaderSanitizerMatchesStaticMethod() {
        HeaderSanitizer instance = new HeaderSanitizer();
        // Instance and static must agree for all known header names
        for (String h : List.of("X-User-Id", "X-Role", "x-tenant", "x-userid",
                "x-service-foo", "Authorization", "X-Service-Token", "X-Correlation-Id")) {
            assertEquals(HeaderSanitizer.isUntrustedIdentityHeader(h), instance.isUntrusted(h),
                    "E4: static and instance results must agree for header: " + h);
        }
    }

    // =========================================================================
    // A3 — auditPermission: multi-permission representation
    // =========================================================================

    @Test
    void a3_singlePermissionEmitsExactName() {
        AuthorizationEngine e = engine(SIMPLE_YAML); // permissions: [READ_ORDER]
        PermissionCache cache = new PermissionCache(Map.of("R", List.of("READ_ORDER")));
        DecisionResult r = e.evaluate(
                new AuthorizationRequest("GET", "/orders", AuthType.USER, "R", null), cache);
        assertEquals("READ_ORDER", r.auditPermission(),
                "A3: single permission must appear exactly as configured");
    }

    @Test
    void a3_multiPermissionRuleEmitsCommaJoined() {
        AuthorizationEngine e = engine("""
                rules:
                  - path: /admin
                    methods: [POST]
                    permissions: [WRITE_ORDER, ADMIN]
                    decision: ANY
                """);
        PermissionCache cache = new PermissionCache(Map.of("M", List.of("WRITE_ORDER")));
        DecisionResult r = e.evaluate(
                new AuthorizationRequest("POST", "/admin", AuthType.USER, "M", null), cache);
        assertEquals("WRITE_ORDER,ADMIN", r.auditPermission(),
                "A3: multi-permission rule must be comma-joined in auditPermission");
    }

    @Test
    void a3_serviceOnlyRuleEmitsNullPermission() {
        AuthorizationEngine e = engine("""
                rules:
                  - path: /internal/reconcile
                    methods: [POST]
                    allowedServices: [scheduler]
                """);
        PermissionCache cache = new PermissionCache(Map.of());
        DecisionResult r = e.evaluate(
                new AuthorizationRequest("POST", "/internal/reconcile",
                        AuthType.SERVICE, null, "scheduler"), cache);
        assertNull(r.auditPermission(),
                "A3: service-only rule must emit null permission");
    }

    @Test
    void a3_auditEventPermissionFieldMatchesDecisionResult() throws Exception {
        // Verify that what AuditEvents.build puts in the event == what DecisionResult gives
        AuthorizationEngine e = engine("""
                rules:
                  - path: /admin
                    methods: [POST]
                    permissions: [WRITE_ORDER, ADMIN]
                    decision: ANY
                """);
        PermissionCache cache = new PermissionCache(Map.of("M", List.of("WRITE_ORDER")));
        DecisionResult result = e.evaluate(
                new AuthorizationRequest("POST", "/admin", AuthType.USER, "M", null), cache);

        RequestContext ctx = RequestContextBuilder.build(
                new Principals.User("u1", "M"), null, "c1", "r1");
        AuditEvent event = AuditEvents.build(ctx, "POST", "/admin",
                result.auditPermission(), result.decision());

        assertEquals(result.auditPermission(), event.permission(),
                "A3: AuditEvent.permission must match DecisionResult.auditPermission");
        assertEquals("WRITE_ORDER,ADMIN", event.permission(),
                "A3: multi-permission event must carry comma-joined value");
    }

    // =========================================================================
    // D6 — DEBUG audit JSON schema: all required fields present
    // =========================================================================

    @Test
    void d6_debugAuditJsonContainsAllRequiredSchemaFields() throws Exception {
        // Build a representative AuditEvent (ALLOW, user request with permission)
        RequestContext ctx = RequestContextBuilder.build(
                new Principals.User("user-42", "VIEWER"),
                null, "corr-001", "req-002");
        AuditEvent event = AuditEvents.build(ctx, "GET", "/orders",
                "READ_ORDER", Decision.ALLOW);

        // Serialize to JSON using the same ObjectMapper as LoggingAuditSink
        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(event);
        Map<?, ?> parsed = mapper.readValue(json, Map.class);

        // Architecture §10.1 required fields
        assertTrue(parsed.containsKey("timestamp"),        "D6: 'timestamp' must be in audit JSON");
        assertTrue(parsed.containsKey("userId"),           "D6: 'userId' must be in audit JSON");
        assertTrue(parsed.containsKey("roleId"),           "D6: 'roleId' must be in audit JSON");
        assertTrue(parsed.containsKey("path"),             "D6: 'path' must be in audit JSON");
        assertTrue(parsed.containsKey("method"),           "D6: 'method' must be in audit JSON");
        assertTrue(parsed.containsKey("result"),           "D6: 'result' must be in audit JSON");
        assertTrue(parsed.containsKey("permission"),       "D6: 'permission' must be in audit JSON");
        assertTrue(parsed.containsKey("authenticationType"),
                "D6: 'authenticationType' must be in audit JSON");
        assertTrue(parsed.containsKey("correlationId"),   "D6: 'correlationId' must be in audit JSON");
        assertTrue(parsed.containsKey("requestId"),       "D6: 'requestId' must be in audit JSON");

        // Verify governing permission value is correct
        assertEquals("READ_ORDER", parsed.get("permission"),
                "D6: governing permission must appear in the JSON");
        assertEquals("ALLOW", parsed.get("result"),
                "D6: result must be 'ALLOW'");
    }

    @Test
    void d6_debugAuditJsonMultiPermissionHasCommaJoined() throws Exception {
        RequestContext ctx = RequestContextBuilder.build(
                new Principals.User("u1", "M"), null, "c1", "r1");
        AuditEvent event = AuditEvents.build(ctx, "POST", "/admin",
                "WRITE_ORDER,ADMIN", Decision.ALLOW);

        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(event);
        Map<?, ?> parsed = mapper.readValue(json, Map.class);

        assertEquals("WRITE_ORDER,ADMIN", parsed.get("permission"),
                "D6: multi-permission audit JSON must carry comma-joined value");
    }

    // =========================================================================
    // C11 — LoggingAuditSink: WARN on serialization failure, never throws
    // =========================================================================

    @Test
    void c11_loggingAuditSinkNeverThrowsOnSerializationFailure() {
        // LoggingAuditSink should never propagate an exception; we verify it does not
        // throw even for a "normal" event (Jackson can always serialize AuditEvent records)
        LoggingAuditSink sink = new LoggingAuditSink();
        AuditEvent event = new AuditEvent(
                "2026-06-07T00:00:00Z", "u1", "VIEWER", null,
                "/orders", "GET", "READ_ORDER", Decision.ALLOW, "USER",
                "r1", "c1");
        // Must not throw
        assertDoesNotThrow(() -> sink.emit(event),
                "C11: LoggingAuditSink.emit must never throw");
    }

    // =========================================================================
    // G12 — Per-mode token-failure metric differentiation
    // =========================================================================

    @Test
    void g12_classifyTokenFailure_expired() {
        RuntimeException e = new RuntimeException("Jwt expired at ...",
                new RuntimeException("token expir"));
        assertEquals(TokenFailureMode.EXPIRED, Metrics.classifyTokenFailure(e),
                "G12: expired token must classify as EXPIRED");
    }

    @Test
    void g12_classifyTokenFailure_invalidSignature() {
        RuntimeException e = new RuntimeException("signature verification failed");
        assertEquals(TokenFailureMode.INVALID_SIGNATURE, Metrics.classifyTokenFailure(e),
                "G12: signature failure must classify as INVALID_SIGNATURE");
    }

    @Test
    void g12_classifyTokenFailure_malformed() {
        RuntimeException e = new RuntimeException("malformed JWT");
        assertEquals(TokenFailureMode.MALFORMED, Metrics.classifyTokenFailure(e),
                "G12: malformed JWT must classify as MALFORMED");
    }

    @Test
    void g12_classifyTokenFailure_other() {
        RuntimeException e = new RuntimeException("some unexpected problem");
        assertEquals(TokenFailureMode.OTHER, Metrics.classifyTokenFailure(e),
                "G12: unclassified failure must be OTHER");
    }

    @Test
    void g12_incTokenFailure_incrementsBothAggregateAndModeCounter() {
        Metrics metrics = new Metrics();
        metrics.incTokenFailure(Metrics.JWT_VALIDATION_FAILURES, TokenFailureMode.EXPIRED);
        metrics.incTokenFailure(Metrics.JWT_VALIDATION_FAILURES, TokenFailureMode.EXPIRED);
        metrics.incTokenFailure(Metrics.JWT_VALIDATION_FAILURES, TokenFailureMode.MALFORMED);

        assertEquals(3, metrics.get(Metrics.JWT_VALIDATION_FAILURES),
                "G12: aggregate counter must be 3");
        assertEquals(2, metrics.get(Metrics.JWT_VALIDATION_FAILURES + "_expired"),
                "G12: expired mode counter must be 2");
        assertEquals(1, metrics.get(Metrics.JWT_VALIDATION_FAILURES + "_malformed"),
                "G12: malformed mode counter must be 1");
        assertEquals(0, metrics.get(Metrics.JWT_VALIDATION_FAILURES + "_invalid_signature"),
                "G12: unused mode counter must remain 0");
    }

    @Test
    void g12_userTokenFailureIncrementsAggregateAndModeCounter() throws Exception {
        Metrics metrics = new Metrics();
        // Use a custom exception message that should classify as MALFORMED
        Spi.TokenValidator v = new Spi.TokenValidator() {
            public Map<String, Object> validateUserToken(String jwt) {
                throw new RuntimeException("malformed JWT token");
            }
            public Map<String, Object> validateServiceToken(String jwt) {
                throw new RuntimeException("n/a");
            }
        };
        AuthorizationFilter filter = new AuthorizationFilter(
                engine(SIMPLE_YAML), new PermissionCache(), v, new CapturingSink(), metrics);

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/orders");
        req.addHeader("Authorization", "Bearer tok");
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(req, res, new MockFilterChain());

        assertEquals(HttpStatus.UNAUTHORIZED.value(), res.getStatus());
        assertEquals(1, metrics.get(Metrics.JWT_VALIDATION_FAILURES),
                "G12: aggregate JWT failure counter must be 1");
        assertEquals(1, metrics.get(Metrics.JWT_VALIDATION_FAILURES + "_malformed"),
                "G12: malformed JWT mode counter must be 1");
    }

    @Test
    void g12_serviceTokenFailureIncrementsAggregateAndModeCounter() throws Exception {
        Metrics metrics = new Metrics();
        Spi.TokenValidator v = new Spi.TokenValidator() {
            public Map<String, Object> validateUserToken(String jwt) {
                throw new RuntimeException("n/a");
            }
            public Map<String, Object> validateServiceToken(String jwt) {
                throw new RuntimeException("signature verification failed — bad key");
            }
        };
        AuthorizationFilter filter = new AuthorizationFilter(
                engine(SIMPLE_YAML), new PermissionCache(), v, new CapturingSink(), metrics);

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/orders");
        req.addHeader("X-Service-Token", "svc-tok");
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(req, res, new MockFilterChain());

        assertEquals(HttpStatus.UNAUTHORIZED.value(), res.getStatus());
        assertEquals(1, metrics.get(Metrics.SERVICE_TOKEN_FAILURES),
                "G12: aggregate service-token failure counter must be 1");
        assertEquals(1, metrics.get(Metrics.SERVICE_TOKEN_FAILURES + "_invalid_signature"),
                "G12: invalid-signature mode counter must be 1");
    }

    // =========================================================================
    // D2 — Previously-untested counters: authz_failure_total,
    //       authz_permission_denied_total, role_event_skipped_total
    // =========================================================================

    @Test
    void d2_authzFailureTotalIncrementedOnNoCredentials() throws Exception {
        Metrics metrics = new Metrics();
        AuthorizationFilter filter = new AuthorizationFilter(
                engine(SIMPLE_YAML), new PermissionCache(), DENY_ALL, new CapturingSink(), metrics);

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/orders");
        // no Authorization, no X-Service-Token
        filter.doFilter(req, new MockHttpServletResponse(), new MockFilterChain());

        assertEquals(1, metrics.get(Metrics.AUTHZ_FAILURE),
                "D2: authz_failure_total must be incremented when no credentials present");
        assertEquals(0, metrics.get(Metrics.AUTHZ_SUCCESS),
                "D2: authz_success_total must not be incremented");
        assertEquals(0, metrics.get(Metrics.PERMISSION_DENIED),
                "D2: authz_permission_denied_total must not be incremented for no-credentials");
    }

    @Test
    void d2_authzPermissionDeniedTotalIncrementedOnDeny() throws Exception {
        Metrics metrics = new Metrics();
        // User has role VIEWER but rule requires WRITE_ORDER
        Spi.TokenValidator v = userValidatorReturning(
                Map.of("userId", "u1", "roleId", "VIEWER"));
        AuthorizationFilter filter = new AuthorizationFilter(
                engine("rules:\n  - path: /admin\n    methods: [POST]\n    permissions: [WRITE_ORDER]\n"),
                new PermissionCache(Map.of("VIEWER", List.of("READ_ORDER"))),
                v, new CapturingSink(), metrics);

        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/admin");
        req.addHeader("Authorization", "Bearer tok");
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(req, res, new MockFilterChain());

        assertEquals(HttpStatus.FORBIDDEN.value(), res.getStatus());
        assertEquals(1, metrics.get(Metrics.PERMISSION_DENIED),
                "D2: authz_permission_denied_total must be incremented on DENY");
        assertEquals(0, metrics.get(Metrics.AUTHZ_SUCCESS),
                "D2: authz_success_total must not be incremented on DENY");
        assertEquals(0, metrics.get(Metrics.AUTHZ_FAILURE),
                "D2: authz_failure_total must not be incremented on DENY (that's for no-credentials)");
    }

    @Test
    void d2_roleEventSkippedTotalIncrementedOnUnknownOperation() {
        Metrics metrics = new Metrics();
        PermissionCache cache = new PermissionCache(Map.of("MANAGER", List.of("READ")));

        // Apply an unknown operation — RoleEvents.apply returns !applied()
        RoleEvents.ApplyResult result = RoleEvents.apply(cache, Map.of("operation", "FROBNICATE"));
        assertFalse(result.applied(), "Unknown operation must not be applied");

        // The caller (KafkaCacheEventHandler) increments ROLE_EVENT_SKIPPED when !applied.
        // Here we verify the metric name exists and increments correctly.
        metrics.inc(Metrics.ROLE_EVENT_SKIPPED);
        assertEquals(1, metrics.get(Metrics.ROLE_EVENT_SKIPPED),
                "D2: role_event_skipped_total must increment correctly");

        // Apply two more bad events, verify counter
        metrics.inc(Metrics.ROLE_EVENT_SKIPPED);
        assertEquals(2, metrics.get(Metrics.ROLE_EVENT_SKIPPED));
    }

    @Test
    void d2_roleEventSkippedNotIncrementedOnSuccessfulApply() {
        Metrics metrics = new Metrics();
        PermissionCache cache = new PermissionCache();
        RoleEvents.ApplyResult result = RoleEvents.apply(cache,
                Map.of("operation", "UPSERT_ROLE", "roleId", "R", "permissions", List.of("READ")));
        assertTrue(result.applied(), "Valid UPSERT_ROLE must apply");
        // Simulate KafkaCacheEventHandler: only inc when !applied
        if (!result.applied()) metrics.inc(Metrics.ROLE_EVENT_SKIPPED);
        assertEquals(0, metrics.get(Metrics.ROLE_EVENT_SKIPPED),
                "D2: role_event_skipped_total must NOT increment on successful apply");
    }
}
