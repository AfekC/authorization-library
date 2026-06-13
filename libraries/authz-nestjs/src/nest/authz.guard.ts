import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
} from "@nestjs/common";
import { AuthorizationEngine } from "../decision-engine/engine";
import { PermissionCache } from "../permission-cache/cache";
import { TokenValidator, AuditSink, PolicyEngine, RoleResolver } from "../spi";
import { Metrics } from "../observability/metrics";
import { REQUEST_CONTEXT_KEY } from "./request-context.decorator";
import { decideRequest } from "../decision-engine/decide";

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
    const out = await decideRequest(
      { method: req.method, rawPath: req.path ?? req.url ?? "", headers: req.headers ?? {} },
      {
        engine: this.deps.engine, cache: this.deps.cache, validator: this.deps.validator,
        audit: this.deps.audit, metrics: this.deps.metrics,
        policyEngine: this.deps.policyEngine, roleResolver: this.deps.roleResolver,
        userAuthEnabled: this.deps.userAuthEnabled !== false,
      },
    );
    if (out.kind === "deny") {
      throw new HttpException(
        { error: out.error },
        out.status === 401 ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN,
      );
    }
    req[REQUEST_CONTEXT_KEY] = out.ctx;
    if (out.bearer) req.authzUserJwt = out.bearer;
    return true;
  }
}
