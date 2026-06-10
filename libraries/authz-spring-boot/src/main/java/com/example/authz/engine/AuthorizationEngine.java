package com.example.authz.engine;

import com.example.authz.cache.PermissionCache;
import com.example.authz.config.CompiledRule;
import com.example.authz.config.RuleCompiler;
import com.example.authz.spi.Spi;

import java.util.List;
import java.util.Map;

/** Local authorization engine: compiled rules + decision logic. */
public final class AuthorizationEngine {
    private final List<CompiledRule> rules;

    private AuthorizationEngine(List<CompiledRule> rules) {
        this.rules = rules;
    }

    /** Compile + validate rules; throws ConfigException on invalid config. */
    public static AuthorizationEngine compile(List<Map<String, Object>> rawRules) {
        return new AuthorizationEngine(RuleCompiler.compile(rawRules));
    }

    /** The single most-specific rule matching method+path, or null. */
    public CompiledRule matchRule(String method, String path) {
        String upper = method.toUpperCase();
        List<String> segs = Scoring.splitPath(path);
        CompiledRule best = null;
        for (CompiledRule rule : rules) {
            if (!rule.matchesMethod(upper)) continue;
            if (!Scoring.matchPath(rule.segments(), segs)) continue;
            if (best == null || Scoring.compareSpecificity(rule, best) > 0) best = rule;
        }
        return best;
    }

    /** Decide ALLOW/DENY. No matching rule -> DENY. */
    public Decision authorize(AuthorizationRequest req, PermissionCache cache) {
        return evaluate(req, cache).decision();
    }

    /** Decide and report the matched rule (for audit). No matching rule -> DENY. */
    public DecisionResult evaluate(AuthorizationRequest req, PermissionCache cache) {
        CompiledRule rule = matchRule(req.method(), req.path());
        if (rule == null) return new DecisionResult(Decision.DENY, null);
        return new DecisionResult(DecisionEvaluator.decide(rule, req, cache), rule);
    }

    /** Decide using a custom RoleResolver instead of the cache. */
    public Decision authorizeWithResolver(AuthorizationRequest req, Spi.RoleResolver resolver) {
        PermissionCache temp;
        if (req.role() != null) {
            temp = new PermissionCache(Map.of(req.role(), List.copyOf(resolver.permissionsForRole(req.role()))));
        } else {
            temp = new PermissionCache(Map.of());
        }
        return authorize(req, temp);
    }
}
