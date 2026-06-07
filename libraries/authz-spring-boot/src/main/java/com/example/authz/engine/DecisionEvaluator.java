package com.example.authz.engine;

import com.example.authz.cache.PermissionCache;
import com.example.authz.config.CompiledRule;
import com.example.authz.config.DecisionMode;
import com.example.authz.context.RequestContext;
import com.example.authz.spi.Spi;

import java.util.List;
import java.util.Map;
import java.util.Set;

/** Applies the decision matrix for a single matched rule. */
public final class DecisionEvaluator {
    private DecisionEvaluator() {}

    public static Decision decide(CompiledRule rule, AuthorizationRequest req, PermissionCache cache) {
        boolean hasPerms = rule.hasPermissions();
        boolean hasServices = rule.hasAllowedServices();

        return switch (req.authType()) {
            case USER -> (hasPerms && permissionCheckPasses(rule, req.role(), cache))
                    ? Decision.ALLOW : Decision.DENY;
            case SERVICE -> (hasServices && serviceCheckPasses(rule, req.serviceName()))
                    ? Decision.ALLOW : Decision.DENY;
            case USER_AND_SERVICE -> (hasPerms && hasServices
                    && permissionCheckPasses(rule, req.role(), cache)
                    && serviceCheckPasses(rule, req.serviceName()))
                    ? Decision.ALLOW : Decision.DENY;
        };
    }

    private static boolean permissionCheckPasses(CompiledRule rule, String role, PermissionCache cache) {
        List<String> required = rule.permissions();
        if (required == null || required.isEmpty()) return false;
        Set<String> held = cache.permissionsForRole(role);
        if (rule.decision() == DecisionMode.ALL) {
            return held.containsAll(required);
        }
        for (String p : required) if (held.contains(p)) return true;
        return false;
    }

    private static boolean serviceCheckPasses(CompiledRule rule, String serviceName) {
        List<String> allowed = rule.allowedServices();
        if (allowed == null || allowed.isEmpty()) return false;
        if (allowed.contains("*")) return true;
        return serviceName != null && allowed.contains(serviceName);
    }

    public static WithPolicyEngine withPolicyEngine(Spi.PolicyEngine engine) {
        return new WithPolicyEngine(engine);
    }

    public static final class WithPolicyEngine {
        private final Spi.PolicyEngine engine;
        private WithPolicyEngine(Spi.PolicyEngine engine) { this.engine = engine; }
        public Decision decide(AuthorizationRequest req) {
            return engine.authorize(req);
        }
    }

    public static Map<String, Object> attributesFor(RequestContext ctx, Spi.AttributeProvider provider) {
        if (provider == null) return Map.of();
        return provider.attributesFor(ctx);
    }
}
