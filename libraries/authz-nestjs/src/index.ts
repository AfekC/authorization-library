// Core decision logic
export * from "./rule-config/types";
export { compileRules } from "./rule-config/compile";
export { loadAuthorizationConfig, loadAuthorizationFile } from "./rule-config/loader";
export { PermissionCache } from "./permission-cache/cache";
export { AuthorizationEngine, auditPermission, DecisionResult } from "./decision-engine/engine";
export { decide } from "./decision-engine/decision";
export {
  compareSpecificity,
  matchPath,
  splitPath,
  scoreSegment,
} from "./decision-engine/scoring";

// Inbound auth
export {
  RequestContext,
  UserPrincipal,
  ServicePrincipal,
  buildRequestContext,
  stripUntrustedHeaders,
} from "./inbound-auth/context";
export {
  JwksTokenValidator,
  JwksValidatorConfig,
  userPrincipalFromClaims,
  servicePrincipalFromClaims,
} from "./inbound-auth/token-validator";

// Distribution / cache sync
export { HttpRoleServiceClient } from "./role-service-client/client";
export { DiskCache, DiskSnapshot } from "./cache-sync/disk";
export { applyRoleEvent, parseRoleEvent } from "./cache-sync/events";
export { KafkaCacheEventHandler } from "./cache-sync/kafka";
export { CacheBootstrap, CacheBootstrapError, CacheMode } from "./cache-sync/bootstrap";

// Outbound / service token
export { ClientCredentialsProvider } from "./service-token/provider";
export {
  buildOutboundHeaders,
  attachOutboundPropagation,
  AxiosLike,
} from "./outbound/propagation";
export {
  runWithOutboundContext,
  currentOutboundContext,
  OutboundContext,
} from "./outbound/context-store";

// Audit / observability
export { LoggingAuditSink, buildAuditEvent, formatInfoLine } from "./audit/audit";
export { Metrics, METRIC, GAUGE, buildHealth, HealthReport } from "./observability/metrics";

// One-call bootstrap (simplest adoption path)
export { createAuthz, CreateAuthzOptions, Authz, AuthorizedRequest } from "./bootstrap/create-authz";

// NestJS integration
export { AuthzGuard, AuthzGuardDeps } from "./nest/authz.guard";
export { AuthzOutboundInterceptor } from "./nest/outbound.interceptor";
export { AuthzContext, REQUEST_CONTEXT_KEY } from "./nest/request-context.decorator";
export { AuthzModule, AUTHZ } from "./nest/authz.module";

// SPI
export * from "./spi";
