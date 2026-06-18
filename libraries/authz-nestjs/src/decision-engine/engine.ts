import { compileRules } from "../rule-config/compile.js";
import { PermissionCache } from "../permission-cache/cache.js";
import {
  AuthorizationRequest,
  CompiledRule,
  Decision,
  RuleInput,
} from "../rule-config/types.js";
import { compareSpecificity, matchPath, splitPath } from "./scoring.js";
import { decide, decideWithResolver } from "./decision.js";
import { PolicyEngine, RoleResolver, AttributeProvider } from "../spi/index.js";
import { RequestContext } from "../inbound-auth/context.js";

/**
 * Outcome of a single evaluation: the decision plus the matched rule (null when
 * none matched). The matched rule lets callers report the governing permission
 * in the audit event (architecture §10.1).
 */
export interface DecisionResult {
  decision: Decision;
  matchedRule: CompiledRule | null;
}

/**
 * The permission string for the audit event: the matched rule's required
 * permissions joined with ",", or null for a service-only / unmatched rule.
 */
export function auditPermission(rule: CompiledRule | null): string | null {
  if (!rule || !rule.permissions || rule.permissions.length === 0) return null;
  return rule.permissions.join(",");
}

/**
 * The local authorization engine: compiled rules + decision logic.
 * Construction fails fast on invalid configuration (throws ConfigError).
 */
export class AuthorizationEngine {
  private constructor(private readonly rules: CompiledRule[]) {}

  static compile(rules: RuleInput[]): AuthorizationEngine {
    return new AuthorizationEngine(compileRules(rules));
  }

  /** Find the single most-specific rule matching method+path, or null. */
  matchRule(method: string, path: string): CompiledRule | null {
    const upper = method.toUpperCase();
    const segs = splitPath(path);
    let best: CompiledRule | null = null;
    for (const rule of this.rules) {
      // methods: ["*"] matches any HTTP method.
      if (!rule.methods.has("*") && !rule.methods.has(upper)) continue;
      if (!matchPath(rule.segments, segs)) continue;
      if (best === null || compareSpecificity(rule, best) > 0) best = rule;
    }
    return best;
  }

  /** Decide ALLOW/DENY for a request against the cache. No-match -> DENY. */
  authorize(
    request: AuthorizationRequest,
    cache: PermissionCache,
  ): Decision {
    return this.evaluate(request, cache).decision;
  }

  /**
   * D12: Create a PolicyEngine that delegates to a custom implementation.
   * Usage: AuthorizationEngine.withPolicyEngine(myEngine).decide(request)
   */
  static withPolicyEngine(engine: PolicyEngine): { decide(req: AuthorizationRequest): Decision } {
    return {
      decide(req: AuthorizationRequest): Decision {
        return engine.authorize(req);
      },
    };
  }

  /**
   * D12: Evaluate using a custom RoleResolver instead of the cache.
   */
  authorizeWithResolver(
    request: AuthorizationRequest,
    resolver: RoleResolver,
  ): Decision {
    const rule = this.matchRule(request.method, request.path);
    if (rule === null) return "DENY";
    return decideWithResolver(rule, request, resolver);
  }

  /**
   * D12: Extract attributes from a custom AttributeProvider (or empty map when null).
   */
  static attributesFor(
    ctx: RequestContext,
    provider: AttributeProvider | null,
  ): Record<string, unknown> {
    if (!provider) return {};
    return provider.attributesFor(ctx);
  }

  /** Decide and report the matched rule (for audit). No-match -> DENY. */
  evaluate(
    request: AuthorizationRequest,
    cache: PermissionCache,
  ): DecisionResult {
    const rule = this.matchRule(request.method, request.path);
    if (rule === null) return { decision: "DENY", matchedRule: null };
    return { decision: decide(rule, request, cache), matchedRule: rule };
  }
}
