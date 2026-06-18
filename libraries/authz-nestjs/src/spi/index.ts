import { AuthorizationRequest, Decision, RuleInput } from "../rule-config/types.js";
import { RequestContext } from "../inbound-auth/context.js";

/** Parsed claims from a validated token. */
export interface TokenClaims {
  [claim: string]: unknown;
}

/** Validates user JWTs and service tokens against trusted JWKS. */
export interface TokenValidator {
  validateUserToken(jwt: string): Promise<TokenClaims>;
  validateServiceToken(jwt: string): Promise<TokenClaims>;
}

/** Acquires this service's outbound identity token (today: SSO client-credentials). */
export interface ServiceIdentityProvider {
  getServiceToken(): Promise<string>;
}

/** Resolves a role to its permission set (today: single role -> permissions). */
export interface RoleResolver {
  permissionsForRole(role: string | null | undefined): ReadonlySet<string>;
}

/** Decides ALLOW/DENY for a request (today: local config rule engine). */
export interface PolicyEngine {
  authorize(request: AuthorizationRequest): Decision;
}

/** Supplies extra attributes for future ABAC policies. */
export interface AttributeProvider {
  attributesFor(ctx: RequestContext): Record<string, unknown>;
}

/**
 * Authoritative full role state: a bare `roleId -> permissions` map
 * (`GET /roles`). No envelope, no version — the reconciler re-fetches and
 * replaces the whole map each cycle.
 */
export type RoleMap = Record<string, string[]>;
export interface RoleServiceClient {
  fetchSnapshot(): Promise<RoleMap>;
}

/**
 * Incremental cache change events (Kafka). The wire message carries only
 * `roleId` (+ `permissions` for upserts); the operation is derived from the
 * source topic (`role-updates` vs `role-delete`) by the event handler.
 */
export type RoleEvent =
  | { operation: "UPSERT_ROLE"; roleId: string; permissions: string[] }
  | { operation: "DELETE_ROLE"; roleId: string };

export interface CacheEventHandler {
  start(
    onEvent: (event: RoleEvent) => void,
    onRefresh: () => void,
  ): Promise<void>;
  stop(): Promise<void>;
}

/** Audit event emitted per decision. */
export interface AuditEvent {
  timestamp: string;
  userId: string | null;
  roleId: string | null;
  serviceName: string | null;
  path: string;
  method: string;
  permission: string | null;
  result: Decision;
  authenticationType: string;
  requestId: string;
  correlationId: string;
}

export interface AuditSink {
  emit(event: AuditEvent): void;
}

export type { RuleInput };
