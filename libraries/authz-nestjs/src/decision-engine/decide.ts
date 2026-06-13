import { AuthorizationEngine, auditPermission } from "./engine";
import { PermissionCache } from "../permission-cache/cache";
import {
  buildRequestContext,
  stripUntrustedHeaders,
  RequestContext,
} from "../inbound-auth/context";
import {
  servicePrincipalFromClaims,
  userPrincipalFromClaims,
} from "../inbound-auth/token-validator";
import { extractBearer } from "../inbound-auth/bearer";
import { buildAuditEvent } from "../audit/audit";
import { Metrics, METRIC, classifyTokenFailure } from "../observability/metrics";
import { AuditSink, TokenValidator, PolicyEngine, RoleResolver } from "../spi";
import { Decision, CompiledRule } from "../rule-config/types";

/** Everything the core decision needs — no framework types. */
export interface DecideDeps {
  engine: AuthorizationEngine;
  cache: PermissionCache;
  validator: TokenValidator;
  audit: AuditSink;
  metrics: Metrics;
  policyEngine?: PolicyEngine;
  roleResolver?: RoleResolver;
  /** False = SERVICE-ONLY mode (§0.5): user JWTs are ignored. */
  userAuthEnabled: boolean;
}

export interface DecideInput {
  method: string;
  /** req.path ?? req.url — query string is stripped inside. */
  rawPath: string;
  /** Raw inbound headers; untrusted identity headers are stripped inside. */
  headers: Record<string, unknown>;
}

export type DecideOutcome =
  | { kind: "allow"; ctx: RequestContext; bearer: string | null }
  | { kind: "deny"; status: 401 | 403; error: string };

/**
 * The single authorization decision for the NestJS library. Pure with respect to
 * the framework: it never touches req/res. Both AuthzGuard and the Express
 * middleware call this, guaranteeing identical behavior (cross-language parity).
 */
export async function decideRequest(input: DecideInput, deps: DecideDeps): Promise<DecideOutcome> {
  const headers = stripUntrustedHeaders(input.headers ?? {});
  const bearer = deps.userAuthEnabled ? (extractBearer(headers["authorization"]) ?? null) : null;
  const serviceToken = (headers["x-service-token"] as string) ?? null;
  const requestPath = (input.rawPath ?? "").split("?")[0];

  // §3.1 — public:true routes need no credentials (built-in engine only).
  if (!deps.policyEngine) {
    const pre = deps.engine.matchRule(input.method, requestPath);
    if (pre && pre.isPublic) {
      const anon = buildRequestContext({
        user: null, service: null,
        correlationId: headers["x-correlation-id"] as string,
        requestId: headers["x-request-id"] as string,
      });
      deps.audit.emit(buildAuditEvent({ ctx: anon, method: input.method, path: requestPath, permission: null, result: "ALLOW" }));
      deps.metrics.inc(METRIC.authzSuccess);
      return { kind: "allow", ctx: anon, bearer: null };
    }
  }

  if (!bearer && !serviceToken) {
    deps.metrics.inc(METRIC.authzFailure);
    return { kind: "deny", status: 401, error: "no credentials" };
  }

  let user = null;
  let service = null;
  if (bearer) {
    try {
      user = userPrincipalFromClaims(await deps.validator.validateUserToken(bearer));
    } catch (err) {
      deps.metrics.incTokenFailure(METRIC.jwtValidationFailures, classifyTokenFailure(err));
      return { kind: "deny", status: 401, error: "user token validation failed" };
    }
  }
  if (serviceToken) {
    try {
      service = servicePrincipalFromClaims(await deps.validator.validateServiceToken(serviceToken));
    } catch (err) {
      deps.metrics.incTokenFailure(METRIC.serviceTokenFailures, classifyTokenFailure(err));
      return { kind: "deny", status: 401, error: "service token validation failed" };
    }
  }

  const ctx = buildRequestContext({
    user, service,
    correlationId: headers["x-correlation-id"] as string,
    requestId: headers["x-request-id"] as string,
  });

  const authRequest = { method: input.method, path: requestPath, authType: ctx.authenticationType, role: ctx.roleId, serviceName: ctx.serviceName };
  let decision: Decision;
  let matchedRule: CompiledRule | null = null;

  if (deps.policyEngine) {
    decision = deps.policyEngine.authorize(authRequest);
  } else if (deps.roleResolver) {
    decision = deps.engine.authorizeWithResolver(authRequest, deps.roleResolver);
    const rule = deps.engine.matchRule(input.method, requestPath);
    if (rule) matchedRule = rule;
  } else {
    const result = deps.engine.evaluate(authRequest, deps.cache);
    decision = result.decision;
    matchedRule = result.matchedRule;
  }

  deps.audit.emit(buildAuditEvent({ ctx, method: input.method, path: requestPath, permission: auditPermission(matchedRule), result: decision }));

  if (decision === "ALLOW") {
    deps.metrics.inc(METRIC.authzSuccess);
    return { kind: "allow", ctx, bearer };
  }
  deps.metrics.inc(METRIC.permissionDenied);
  return { kind: "deny", status: 403, error: "authorization denied" };
}
