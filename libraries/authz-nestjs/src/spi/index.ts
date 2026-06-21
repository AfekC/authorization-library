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

/**
 * T24 — Versioned snapshot entry from a Role Service that supports the new
 * monotonic serial. Each entry carries `permissions` + a monotonic `version`
 * used to guard against out-of-order cache application. The Role Service may
 * return entries in this format alongside (or instead of) the bare string[].
 */
export interface VersionedRoleEntry {
  permissions: string[];
  version: number;
}

/**
 * T24 — Richer snapshot structure returned by a Role Service that includes
 * per-role monotonic versions. Each value is either a plain string[] (legacy)
 * or a VersionedRoleEntry (new). HttpRoleServiceClient normalises both into
 * a VersionedSnapshot; callers that only need permissions use plain RoleMap.
 */
export type VersionedSnapshot = Record<string, VersionedRoleEntry | string[]>;

export interface RoleServiceClient {
  fetchSnapshot(): Promise<RoleMap>;
}

/**
 * Incremental cache upsert event (from `role-updates` Kafka topic, Avro-decoded).
 *
 * T24: `version` is an optional monotonic serial. When present, the event is
 * applied only if strictly greater than the stored version for that roleId.
 */
export interface RoleUpsertEvent {
  roleId: string;
  permissions: string[];
  version?: number;
}

/**
 * Incremental cache delete event (from `role-delete` Kafka topic, Avro-decoded).
 *
 * T24: `version` is optional; when present the same monotonic guard applies.
 */
export interface RoleDeleteEvent {
  roleId: string;
  version?: number;
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
