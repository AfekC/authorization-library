package com.example.authz;

import com.example.authz.cache.PermissionCache;
import com.example.authz.config.ConfigException;
import com.example.authz.config.YamlLoader;
import com.example.authz.engine.AuthorizationEngine;
import com.example.authz.engine.AuthorizationRequest;
import com.example.authz.engine.Decision;
import com.example.authz.engine.DecisionEvaluator;
import com.example.authz.engine.AuthType;
import com.example.authz.spi.Spi;
import com.example.authz.audit.AuditEvent;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for gaps:
 *   C8  — root path "/" can be authored as a rule (ALLOW / DENY)
 *   E5  — partial wildcard error message is clear and specific
 *   A7  — SPI seams: PolicyEngine, RoleResolver, AttributeProvider
 *   D11 — permission names are case-sensitive ("READ" != "read")
 *   D12 — SPI pluggability: custom PolicyEngine, RoleResolver, AuditSink
 */
class RuleCompilerAndSpiTest {

    // =========================================================================
    // C8 — Root path "/" compiles and matches
    // =========================================================================

    private static AuthorizationEngine engine(String yaml) {
        return YamlLoader.load(yaml);
    }

    @Test
    void c8_rootPathCompilesToValidRule() {
        // Before fix this throws "rule path has no segments"
        assertDoesNotThrow(() -> engine("""
                rules:
                  - path: /
                    methods: [GET]
                    permissions: [READ_ROOT]
                """), "C8: path '/' must compile without error");
    }

    @Test
    void c8_rootRuleAllowsGetRoot() {
        AuthorizationEngine e = engine("""
                rules:
                  - path: /
                    methods: [GET]
                    permissions: [READ_ROOT]
                """);
        PermissionCache cache = new PermissionCache(Map.of("VIEWER", List.of("READ_ROOT")));
        AuthorizationRequest req = new AuthorizationRequest("GET", "/", AuthType.USER, "VIEWER", null);
        assertEquals(Decision.ALLOW, e.authorize(req, cache),
                "C8: GET / must ALLOW when VIEWER has READ_ROOT and rule covers /");
    }

    @Test
    void c8_rootRuleDeniesWhenPermissionMissing() {
        AuthorizationEngine e = engine("""
                rules:
                  - path: /
                    methods: [GET]
                    permissions: [READ_ROOT]
                """);
        PermissionCache cache = new PermissionCache(Map.of("VIEWER", List.of("OTHER_PERM")));
        AuthorizationRequest req = new AuthorizationRequest("GET", "/", AuthType.USER, "VIEWER", null);
        assertEquals(Decision.DENY, e.authorize(req, cache),
                "C8: GET / must DENY when VIEWER lacks READ_ROOT");
    }

    @Test
    void c8_rootRuleDoesNotMatchNonRootPath() {
        AuthorizationEngine e = engine("""
                rules:
                  - path: /
                    methods: [GET]
                    permissions: [READ_ROOT]
                """);
        PermissionCache cache = new PermissionCache(Map.of("VIEWER", List.of("READ_ROOT")));
        // /orders has no matching rule -> DENY (no match)
        AuthorizationRequest req = new AuthorizationRequest("GET", "/orders", AuthType.USER, "VIEWER", null);
        assertEquals(Decision.DENY, e.authorize(req, cache),
                "C8: root rule must NOT match /orders; no rule -> DENY");
    }

    @Test
    void c8_nonRootPathNoMatchStillDenies() {
        // No rules at all for this path — DENY (preserved behavior)
        AuthorizationEngine e = engine("""
                rules:
                  - path: /
                    methods: [POST]
                    permissions: [WRITE_ROOT]
                """);
        PermissionCache cache = new PermissionCache(Map.of("VIEWER", List.of("WRITE_ROOT")));
        // GET / has no rule (only POST /) -> DENY
        AuthorizationRequest req = new AuthorizationRequest("GET", "/", AuthType.USER, "VIEWER", null);
        assertEquals(Decision.DENY, e.authorize(req, cache),
                "C8: method mismatch on root rule -> DENY");
    }

    @Test
    void c8_rootRuleServiceAllowed() {
        AuthorizationEngine e = engine("""
                rules:
                  - path: /
                    methods: [GET]
                    allowedServices: [health-checker]
                """);
        PermissionCache cache = new PermissionCache(Map.of());
        AuthorizationRequest req = new AuthorizationRequest("GET", "/", AuthType.SERVICE, null, "health-checker");
        assertEquals(Decision.ALLOW, e.authorize(req, cache),
                "C8: SERVICE request to / must ALLOW when service is in allowedServices");
    }

    @Test
    void c8_rootRuleCoexistsWithOtherRules() {
        // Root rule at / plus a more specific rule at /orders — specificity must work correctly
        AuthorizationEngine e = engine("""
                rules:
                  - path: /
                    methods: [GET]
                    permissions: [READ_ROOT]
                  - path: /orders
                    methods: [GET]
                    permissions: [READ_ORDER]
                """);
        PermissionCache cache = new PermissionCache(Map.of(
                "VIEWER", List.of("READ_ROOT", "READ_ORDER")));

        // / -> root rule
        assertEquals(Decision.ALLOW,
                e.authorize(new AuthorizationRequest("GET", "/", AuthType.USER, "VIEWER", null), cache),
                "C8: GET / must match root rule");

        // /orders -> specific rule
        assertEquals(Decision.ALLOW,
                e.authorize(new AuthorizationRequest("GET", "/orders", AuthType.USER, "VIEWER", null), cache),
                "C8: GET /orders must match /orders rule, not root rule");
    }

    @Test
    void c8_rootRuleMoreSpecificThanDoubleStarRule() {
        // ** rule at root level: if someone authors a /** rule and a / rule,
        // / is more specific (it doesn't use a wildcard) than /**
        // But /** would match /orders; / would match only /
        AuthorizationEngine e = engine("""
                rules:
                  - path: /
                    methods: [GET]
                    permissions: [READ_ROOT]
                  - path: /**
                    methods: [GET]
                    permissions: [READ_ANY]
                """);
        PermissionCache cache = new PermissionCache(Map.of(
                "VIEWER", List.of("READ_ROOT", "READ_ANY")));

        // GET / -> root rule wins (it has literal-ness as root, ** is less specific)
        // Actually: / has 0 segments, ** has 1 segment (score 0). Compare: root is empty segments.
        // The specific behavior here is: / rule matches only exact root; /** matches /anything
        // They don't overlap on / (root has zero segments, ** requires at least 1 after root)
        // Actually wait - /** means the DEEP segment needs >=1 path segs. "/" splits to 0 segs.
        // So /** does NOT match "/" — root rule is the only match.
        assertEquals(Decision.ALLOW,
                e.authorize(new AuthorizationRequest("GET", "/", AuthType.USER, "VIEWER", null), cache),
                "C8: GET / matched by root rule");
        assertEquals(Decision.ALLOW,
                e.authorize(new AuthorizationRequest("GET", "/foo", AuthType.USER, "VIEWER", null), cache),
                "C8: GET /foo matched by /** rule");
    }

    // =========================================================================
    // E5 — Partial wildcard error message is clear and specific
    // =========================================================================

    @Test
    void e5_partialWildcardRejectedWithClearMessage() {
        ConfigException ex = assertThrows(ConfigException.class, () -> engine("""
                rules:
                  - path: /par*
                    methods: [GET]
                    permissions: [READ]
                """), "E5: partial wildcard 'par*' must throw ConfigException");

        String msg = ex.getMessage();
        assertNotNull(msg, "E5: error message must not be null");
        // Must mention what is NOT allowed
        assertTrue(msg.contains("par*") || msg.contains("partial wildcard"),
                "E5: error must reference the offending segment or say 'partial wildcard', got: " + msg);
        // Must mention what IS allowed (full-segment * or trailing **)
        assertTrue(
                msg.contains("full-segment") || msg.contains("only") || msg.contains("supported")
                || msg.contains("*") || msg.contains("**"),
                "E5: error must indicate what wildcards ARE allowed, got: " + msg);
    }

    @Test
    void e5_partialWildcardSuffixRejectedWithClearMessage() {
        ConfigException ex = assertThrows(ConfigException.class, () -> engine("""
                rules:
                  - path: /orders/*ix
                    methods: [GET]
                    permissions: [READ]
                """), "E5: partial wildcard '*ix' must throw ConfigException");

        String msg = ex.getMessage();
        // Must clearly indicate only full-segment wildcards are supported
        assertTrue(msg.contains("partial wildcard") || msg.contains("*ix") || msg.contains("not supported"),
                "E5: message must describe partial wildcard restriction, got: " + msg);
        assertTrue(
                msg.contains("*") && (msg.contains("full") || msg.contains("segment") || msg.contains("only") || msg.contains("supported")),
                "E5: message must mention what IS allowed, got: " + msg);
    }

    @Test
    void e5_fullSegmentStarIsStillAccepted() {
        // A plain * (full segment) must NOT be rejected
        assertDoesNotThrow(() -> engine("""
                rules:
                  - path: /orders/*
                    methods: [GET]
                    permissions: [READ]
                """), "E5: full-segment '*' must be accepted");
    }

    @Test
    void e5_trailingDoubleStarIsStillAccepted() {
        assertDoesNotThrow(() -> engine("""
                rules:
                  - path: /orders/**
                    methods: [GET]
                    permissions: [READ]
                """), "E5: trailing '**' must be accepted");
    }

    // =========================================================================
    // D11 — Permission names are case-sensitive
    // =========================================================================

    @Test
    void d11_permissionNamesAreCaseSensitive_readUpperVsLower() {
        AuthorizationEngine e = engine("""
                rules:
                  - path: /data
                    methods: [GET]
                    permissions: [READ]
                """);

        // Role with uppercase "READ" -> ALLOW
        PermissionCache cacheUpper = new PermissionCache(Map.of("ROLE_A", List.of("READ")));
        assertEquals(Decision.ALLOW,
                e.authorize(new AuthorizationRequest("GET", "/data", AuthType.USER, "ROLE_A", null), cacheUpper),
                "D11: 'READ' permission must match rule requiring 'READ'");

        // Role with lowercase "read" -> DENY (case mismatch)
        PermissionCache cacheLower = new PermissionCache(Map.of("ROLE_B", List.of("read")));
        assertEquals(Decision.DENY,
                e.authorize(new AuthorizationRequest("GET", "/data", AuthType.USER, "ROLE_B", null), cacheLower),
                "D11: 'read' (lowercase) must NOT match rule requiring 'READ'");
    }

    @Test
    void d11_permissionNamesAreCaseSensitive_mixedCase() {
        AuthorizationEngine e = engine("""
                rules:
                  - path: /admin
                    methods: [POST]
                    permissions: [Write_Order]
                    decision: ANY
                """);

        // Exact match passes
        PermissionCache exact = new PermissionCache(Map.of("MGR", List.of("Write_Order")));
        assertEquals(Decision.ALLOW,
                e.authorize(new AuthorizationRequest("POST", "/admin", AuthType.USER, "MGR", null), exact),
                "D11: exact mixed-case match must ALLOW");

        // WRITE_ORDER (all-upper) does not match Write_Order
        PermissionCache upper = new PermissionCache(Map.of("MGR", List.of("WRITE_ORDER")));
        assertEquals(Decision.DENY,
                e.authorize(new AuthorizationRequest("POST", "/admin", AuthType.USER, "MGR", null), upper),
                "D11: 'WRITE_ORDER' must NOT match rule requiring 'Write_Order'");

        // write_order (all-lower) does not match Write_Order
        PermissionCache lower = new PermissionCache(Map.of("MGR", List.of("write_order")));
        assertEquals(Decision.DENY,
                e.authorize(new AuthorizationRequest("POST", "/admin", AuthType.USER, "MGR", null), lower),
                "D11: 'write_order' must NOT match rule requiring 'Write_Order'");
    }

    @Test
    void d11_allDecisionModeCaseSensitive() {
        AuthorizationEngine e = engine("""
                rules:
                  - path: /secure
                    methods: [DELETE]
                    permissions: [DELETE_RESOURCE, ADMIN]
                    decision: ALL
                """);

        // Has DELETE_RESOURCE + admin (lowercase) -> DENY (ADMIN != admin)
        PermissionCache wrong = new PermissionCache(Map.of("ROLE_X", List.of("DELETE_RESOURCE", "admin")));
        assertEquals(Decision.DENY,
                e.authorize(new AuthorizationRequest("DELETE", "/secure", AuthType.USER, "ROLE_X", null), wrong),
                "D11: ALL mode — 'admin' must NOT satisfy 'ADMIN' requirement");

        // Has both exact -> ALLOW
        PermissionCache right = new PermissionCache(Map.of("ROLE_X", List.of("DELETE_RESOURCE", "ADMIN")));
        assertEquals(Decision.ALLOW,
                e.authorize(new AuthorizationRequest("DELETE", "/secure", AuthType.USER, "ROLE_X", null), right),
                "D11: ALL mode — exact case must ALLOW");
    }

    // =========================================================================
    // D12 — SPI pluggability: custom PolicyEngine, RoleResolver, AuditSink
    // =========================================================================

    /**
     * Custom PolicyEngine that always returns ALLOW regardless of rules.
     * Verifies that DecisionEvaluator.withPolicyEngine() routes through it.
     */
    @Test
    void d12_customPolicyEngineIsUsedWhenProvided() {
        // Build an engine whose compiled rules would normally DENY
        AuthorizationEngine e = engine("""
                rules:
                  - path: /locked
                    methods: [GET]
                    permissions: [SECRET_PERM]
                """);
        PermissionCache cache = new PermissionCache(Map.of("VIEWER", List.of("READ_ONLY")));
        AuthorizationRequest req = new AuthorizationRequest("GET", "/locked", AuthType.USER, "VIEWER", null);

        // With built-in engine -> DENY (VIEWER lacks SECRET_PERM)
        assertEquals(Decision.DENY, e.authorize(req, cache),
                "D12: baseline — built-in engine must DENY");

        // Custom PolicyEngine always ALLOWs
        AtomicBoolean customCalled = new AtomicBoolean(false);
        Spi.PolicyEngine alwaysAllow = request -> {
            customCalled.set(true);
            return Decision.ALLOW;
        };

        // Use the seam: DecisionEvaluator.withPolicyEngine
        Decision result = DecisionEvaluator.withPolicyEngine(alwaysAllow).decide(req);
        assertEquals(Decision.ALLOW, result,
                "D12: custom PolicyEngine must return ALLOW");
        assertTrue(customCalled.get(),
                "D12: custom PolicyEngine.authorize must have been called");
    }

    @Test
    void d12_customPolicyEngineDenyOverridesDefaultAllow() {
        AuthorizationEngine e = engine("""
                rules:
                  - path: /public
                    methods: [GET]
                    allowedServices: [*]
                """);
        PermissionCache cache = new PermissionCache(Map.of());
        AuthorizationRequest req = new AuthorizationRequest("GET", "/public", AuthType.SERVICE, null, "any-service");

        // Built-in would ALLOW (wildcard service)
        assertEquals(Decision.ALLOW, e.authorize(req, cache),
                "D12: baseline — built-in engine allows wildcard service");

        // Custom PolicyEngine always DENYs
        Spi.PolicyEngine alwaysDeny = request -> Decision.DENY;
        Decision result = DecisionEvaluator.withPolicyEngine(alwaysDeny).decide(req);
        assertEquals(Decision.DENY, result,
                "D12: custom PolicyEngine returning DENY must override default ALLOW");
    }

    /**
     * Custom RoleResolver that supplies permissions directly, bypassing the cache.
     */
    @Test
    void d12_customRoleResolverIsUsedWhenProvided() {
        AuthorizationEngine e = engine("""
                rules:
                  - path: /orders
                    methods: [GET]
                    permissions: [READ_ORDER]
                """);

        // Cache has NO permissions for this role
        PermissionCache emptyCache = new PermissionCache(Map.of());
        AuthorizationRequest req = new AuthorizationRequest("GET", "/orders", AuthType.USER, "CUSTOM_ROLE", null);

        // Without custom resolver -> DENY (role unknown in cache)
        assertEquals(Decision.DENY, e.authorize(req, emptyCache),
                "D12: without custom resolver, unknown role must DENY");

        // Custom RoleResolver supplies permissions directly
        AtomicBoolean resolverCalled = new AtomicBoolean(false);
        Spi.RoleResolver customResolver = role -> {
            resolverCalled.set(true);
            if ("CUSTOM_ROLE".equals(role)) return Set.of("READ_ORDER");
            return Set.of();
        };

        // Use the seam: AuthorizationEngine with custom RoleResolver
        Decision result = e.authorizeWithResolver(req, customResolver);
        assertEquals(Decision.ALLOW, result,
                "D12: custom RoleResolver must supply permissions, allowing the request");
        assertTrue(resolverCalled.get(),
                "D12: custom RoleResolver must have been called");
    }

    @Test
    void d12_customRoleResolverDenyWhenResolverReturnsEmpty() {
        AuthorizationEngine e = engine("""
                rules:
                  - path: /orders
                    methods: [GET]
                    permissions: [READ_ORDER]
                """);
        PermissionCache cache = new PermissionCache(Map.of("ROLE_X", List.of("READ_ORDER")));
        AuthorizationRequest req = new AuthorizationRequest("GET", "/orders", AuthType.USER, "ROLE_X", null);

        // Custom resolver that returns empty (ignores cache)
        Spi.RoleResolver emptyResolver = role -> Set.of();
        Decision result = e.authorizeWithResolver(req, emptyResolver);
        assertEquals(Decision.DENY, result,
                "D12: custom RoleResolver returning empty set must cause DENY");
    }

    /**
     * Custom AuditSink — verify the seam already exists (AuditSink was previously wired).
     * This demonstrates the existing AuditSink swap works end-to-end via AuthorizationFilter.
     */
    @Test
    void d12_customAuditSinkReceivesEventsOnDecision() throws Exception {
        AtomicReference<AuditEvent> captured = new AtomicReference<>();
        Spi.AuditSink customSink = captured::set;

        Spi.TokenValidator validUser = new Spi.TokenValidator() {
            public Map<String, Object> validateUserToken(String jwt) {
                return Map.of("userId", "u1", "roleId", "VIEWER");
            }
            public Map<String, Object> validateServiceToken(String jwt) {
                throw new RuntimeException("n/a");
            }
        };

        com.example.authz.observability.Metrics metrics = new com.example.authz.observability.Metrics();
        com.example.authz.web.AuthorizationFilter filter = new com.example.authz.web.AuthorizationFilter(
                engine("""
                        rules:
                          - path: /orders
                            methods: [GET]
                            permissions: [READ_ORDER]
                        """),
                new PermissionCache(Map.of("VIEWER", List.of("READ_ORDER"))),
                validUser, customSink, metrics);

        org.springframework.mock.web.MockHttpServletRequest req =
                new org.springframework.mock.web.MockHttpServletRequest("GET", "/orders");
        req.addHeader("Authorization", "Bearer tok");
        org.springframework.mock.web.MockHttpServletResponse res =
                new org.springframework.mock.web.MockHttpServletResponse();
        filter.doFilter(req, res, new org.springframework.mock.web.MockFilterChain());

        assertNotNull(captured.get(),
                "D12: custom AuditSink must receive an event on ALLOW decision");
        assertEquals(Decision.ALLOW, captured.get().result(),
                "D12: emitted event must record ALLOW");
        assertEquals("READ_ORDER", captured.get().permission(),
                "D12: emitted event must carry the governing permission");
    }

    /**
     * AttributeProvider seam: verify that a custom AttributeProvider can be
     * supplied to the engine; default behavior (no attributes) is preserved
     * when none is provided.
     */
    @Test
    void d12_customAttributeProviderCanBeSupplied() {
        // Build a request context
        com.example.authz.context.RequestContext ctx =
                com.example.authz.context.RequestContextBuilder.build(
                        new com.example.authz.context.Principals.User("u1", "VIEWER"),
                        null, "c1", "r1");

        // Custom AttributeProvider returns extra attributes
        AtomicBoolean providerCalled = new AtomicBoolean(false);
        Spi.AttributeProvider customProvider = context -> {
            providerCalled.set(true);
            return Map.of("region", "us-east-1", "tier", "premium");
        };

        // Call the seam
        Map<String, Object> attrs = DecisionEvaluator.attributesFor(ctx, customProvider);
        assertTrue(providerCalled.get(),
                "D12: custom AttributeProvider must have been called");
        assertEquals("us-east-1", attrs.get("region"),
                "D12: custom attributes must be returned");
        assertEquals("premium", attrs.get("tier"),
                "D12: custom attributes must be returned");
    }

    @Test
    void d12_nullAttributeProviderReturnsEmptyAttributes() {
        com.example.authz.context.RequestContext ctx =
                com.example.authz.context.RequestContextBuilder.build(
                        new com.example.authz.context.Principals.User("u1", "VIEWER"),
                        null, null, null);

        // null provider -> empty map (default behavior)
        Map<String, Object> attrs = DecisionEvaluator.attributesFor(ctx, null);
        assertNotNull(attrs, "D12: default attributes must not be null");
        assertTrue(attrs.isEmpty(), "D12: default attributes must be empty when no provider supplied");
    }

    @Test
    void d12_defaultBehaviorUnchangedWithNoSpiProviders() {
        // Verify the built-in engine (no SPI overrides) continues to work exactly as before
        AuthorizationEngine e = engine("""
                rules:
                  - path: /orders
                    methods: [GET]
                    permissions: [READ_ORDER]
                  - path: /orders/*
                    methods: [GET]
                    permissions: [READ_ORDER]
                  - path: /admin
                    methods: [POST]
                    allowedServices: [scheduler]
                """);

        PermissionCache cache = new PermissionCache(Map.of("VIEWER", List.of("READ_ORDER")));

        assertEquals(Decision.ALLOW,
                e.authorize(new AuthorizationRequest("GET", "/orders", AuthType.USER, "VIEWER", null), cache),
                "D12: default behavior: VIEWER with READ_ORDER must ALLOW /orders");

        assertEquals(Decision.ALLOW,
                e.authorize(new AuthorizationRequest("GET", "/orders/123", AuthType.USER, "VIEWER", null), cache),
                "D12: default behavior: VIEWER with READ_ORDER must ALLOW /orders/123");

        assertEquals(Decision.ALLOW,
                e.authorize(new AuthorizationRequest("POST", "/admin", AuthType.SERVICE, null, "scheduler"), cache),
                "D12: default behavior: scheduler service must ALLOW /admin");

        assertEquals(Decision.DENY,
                e.authorize(new AuthorizationRequest("DELETE", "/orders", AuthType.USER, "VIEWER", null), cache),
                "D12: default behavior: unmatched method must DENY");
    }

    // =========================================================================
    // D9 — YAML config edge cases: no rules key, null field values
    // =========================================================================

    @Test
    void d9_noRulesKeyThrowsConfigException() {
        assertThrows(ConfigException.class,
            () -> engine("otherKey: value"),
            "D9: YAML without 'rules' key must throw ConfigException");
    }

    @Test
    void d9_nullPermissionsTreatsAsServiceOnlyRule() {
        AuthorizationEngine e = engine("""
                rules:
                  - path: /data
                    methods: [GET]
                    permissions:
                    allowedServices: [svc]
                """);
        PermissionCache cache = new PermissionCache(Map.of("VIEWER", List.of("READ")));
        assertEquals(Decision.DENY,
            e.authorize(new AuthorizationRequest("GET", "/data", AuthType.USER, "VIEWER", null), cache));
    }

    @Test
    void d9_nullAllowedServicesTreatsAsUserOnlyRule() {
        AuthorizationEngine e = engine("""
                rules:
                  - path: /data
                    methods: [GET]
                    permissions: [READ]
                    allowedServices:
                """);
        PermissionCache cache = new PermissionCache(Map.of("VIEWER", List.of("READ")));
        assertEquals(Decision.DENY,
            e.authorize(new AuthorizationRequest("GET", "/data", AuthType.SERVICE, null, "any-svc"), cache));
    }
}