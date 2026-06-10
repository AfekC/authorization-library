import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
} from "@nestjs/common";
import { AuthorizationEngine, auditPermission } from "../decision-engine/engine";
import { PermissionCache } from "../permission-cache/cache";
import {
  buildRequestContext,
  RequestContext,
  stripUntrustedHeaders,
} from "../inbound-auth/context";
import {
  servicePrincipalFromClaims,
  userPrincipalFromClaims,
} from "../inbound-auth/token-validator";
import { TokenValidator, AuditSink, PolicyEngine, RoleResolver } from "../spi";
import { buildAuditEvent } from "../audit/audit";
import { Metrics, METRIC, classifyTokenFailure } from "../observability/metrics";
import { REQUEST_CONTEXT_KEY } from "./request-context.decorator";
import { extractBearer } from "../inbound-auth/bearer";

export interface AuthzGuardDeps {
  engine: AuthorizationEngine;
  cache: PermissionCache;
  validator: TokenValidator;
  audit: AuditSink;
  metrics: Metrics;
  /** Optional: replaces the default engine.evaluate() with a custom policy. */
  policyEngine?: PolicyEngine;
  /** Optional: replaces the cache-based role lookup with a custom resolver. */
  roleResolver?: RoleResolver;
  /** FULL mode when true/undefined; SERVICE-ONLY mode (ignore user JWTs) when false (§0.5). */
  userAuthEnabled?: boolean;
}

/**
 * Global guard: authenticates inbound tokens, builds the RequestContext from
 * validated claims only, and applies the local decision. Deny -> 403; bad
 * token -> 401. Registered via APP_GUARD so every route is covered.
 */
@Injectable()
export class AuthzGuard implements CanActivate {
  constructor(private readonly deps: AuthzGuardDeps) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const headers = stripUntrustedHeaders(req.headers ?? {});

    // §0.5 — in SERVICE-ONLY mode the Authorization/Bearer header is ignored.
    const userAuthEnabled = this.deps.userAuthEnabled !== false;
    const bearer = userAuthEnabled ? extractBearer(headers["authorization"]) : undefined;
    const serviceToken = headers["x-service-token"] as string | undefined;

    const requestPath = (req.path ?? req.url ?? "").split("?")[0];

    // §3.1 — public:true routes require no validation and are allowed even
    // without credentials (built-in engine only; a custom PolicyEngine owns all
    // decisions, including public handling).
    if (!this.deps.policyEngine) {
      const pre = this.deps.engine.matchRule(req.method, requestPath);
      if (pre && pre.isPublic) {
        const anon = buildRequestContext({
          user: null,
          service: null,
          correlationId: headers["x-correlation-id"] as string | undefined,
          requestId: headers["x-request-id"] as string | undefined,
        });
        req[REQUEST_CONTEXT_KEY] = anon;
        this.deps.audit.emit(
          buildAuditEvent({ ctx: anon, method: req.method, path: requestPath,
            permission: null, result: "ALLOW" }),
        );
        this.deps.metrics.inc(METRIC.authzSuccess);
        return true;
      }
    }

    if (!bearer && !serviceToken) {
      this.deps.metrics.inc(METRIC.authzFailure);
      throw new HttpException({ error: "no credentials" }, HttpStatus.UNAUTHORIZED);
    }

    let userPrincipal = null;
    let servicePrincipal = null;
    if (bearer) {
      try {
        userPrincipal = userPrincipalFromClaims(
          await this.deps.validator.validateUserToken(bearer),
        );
      } catch (err) {
        this.deps.metrics.incTokenFailure(METRIC.jwtValidationFailures, classifyTokenFailure(err));
        throw new HttpException({ error: "user token validation failed" }, HttpStatus.UNAUTHORIZED);
      }
    }
    if (serviceToken) {
      try {
        servicePrincipal = servicePrincipalFromClaims(
          await this.deps.validator.validateServiceToken(serviceToken),
        );
      } catch (err) {
        this.deps.metrics.incTokenFailure(METRIC.serviceTokenFailures, classifyTokenFailure(err));
        throw new HttpException({ error: "service token validation failed" }, HttpStatus.UNAUTHORIZED);
      }
    }

    const ctx: RequestContext = buildRequestContext({
      user: userPrincipal,
      service: servicePrincipal,
      correlationId: headers["x-correlation-id"] as string | undefined,
      requestId: headers["x-request-id"] as string | undefined,
    });
    req[REQUEST_CONTEXT_KEY] = ctx;
    if (bearer) req.authzUserJwt = bearer;

    const authRequest = { method: req.method, path: requestPath, authType: ctx.authenticationType, role: ctx.roleId, serviceName: ctx.serviceName };

    let decision: import("../rule-config/types").Decision;
    let matchedRule: import("../rule-config/types").CompiledRule | null = null;

    if (this.deps.policyEngine) {
      decision = this.deps.policyEngine.authorize(authRequest);
    } else if (this.deps.roleResolver) {
      decision = this.deps.engine.authorizeWithResolver(authRequest, this.deps.roleResolver);
      const rule = this.deps.engine.matchRule(req.method, requestPath);
      if (rule) matchedRule = rule;
    } else {
      const result = this.deps.engine.evaluate(authRequest, this.deps.cache);
      decision = result.decision;
      matchedRule = result.matchedRule;
    }

    this.deps.audit.emit(
      buildAuditEvent({
        ctx,
        method: req.method,
        path: requestPath,
        permission: auditPermission(matchedRule),
        result: decision,
      }),
    );

    if (decision === "ALLOW") {
      this.deps.metrics.inc(METRIC.authzSuccess);
      return true;
    }
    this.deps.metrics.inc(METRIC.permissionDenied);
    throw new HttpException({ error: "authorization denied" }, HttpStatus.FORBIDDEN);
  }
}
