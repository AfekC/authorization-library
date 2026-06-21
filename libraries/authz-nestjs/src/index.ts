// Core decision logic
export * from "./rule-config/types.js";
export { compileRules } from "./rule-config/compile.js";
export { loadAuthorizationConfig, loadAuthorizationFile } from "./rule-config/loader.js";
export { PermissionCache } from "./permission-cache/cache.js";
export { AuthorizationEngine, auditPermission, DecisionResult } from "./decision-engine/engine.js";
export { decide } from "./decision-engine/decision.js";
export {
  compareSpecificity,
  matchPath,
  splitPath,
  scoreSegment,
} from "./decision-engine/scoring.js";

// Inbound auth
export {
  RequestContext,
  UserPrincipal,
  ServicePrincipal,
  buildRequestContext,
  stripUntrustedHeaders,
  sanitizeHeadersInPlace,
  StripHeadersOptions,
} from "./inbound-auth/context.js";
export { extractBearer } from "./inbound-auth/bearer.js";
export {
  JwksTokenValidator,
  JwksValidatorConfig,
  userPrincipalFromClaims,
  servicePrincipalFromClaims,
} from "./inbound-auth/token-validator.js";

// Distribution / cache sync
export { HttpRoleServiceClient } from "./role-service-client/client.js";
export { DiskCache, DiskSnapshot } from "./cache-sync/disk.js";
export { applyUpsert, applyDelete } from "./cache-sync/events.js";
export { CacheBootstrap, CacheBootstrapError, CacheMode } from "./cache-sync/bootstrap.js";
export { RoleEventsController } from "./cache-sync/role-events.controller.js";
export { authzKafkaOptions } from "./cache-sync/kafka-options.js";

// Outbound / service token
export { ClientCredentialsProvider } from "./service-token/provider.js";
export {
  buildOutboundHeaders,
  attachOutboundPropagation,
  AxiosLike,
} from "./outbound/propagation.js";
export {
  runWithOutboundContext,
  currentOutboundContext,
  OutboundContext,
} from "./outbound/context-store.js";

// Audit / observability
export { LoggingAuditSink, buildAuditEvent, formatInfoLine } from "./audit/audit.js";
export { Metrics, METRIC, GAUGE, buildHealth, HealthReport } from "./observability/metrics.js";

// One-call bootstrap (simplest adoption path)
export {
  createAuthz,
  createAuthzFromOptions,
  CreateAuthzOptions,
  Authz,
  AuthorizedRequest,
} from "./bootstrap/create-authz.js";

// Environment-variable-driven bootstrap (parity with Spring @ConfigurationProperties)
export { optionsFromEnv, EnvSource } from "./bootstrap/env-config.js";

// NestJS integration
export { AuthzGuard, AuthzGuardDeps } from "./nest/authz.guard.js";
export { AuthzOutboundInterceptor } from "./nest/outbound.interceptor.js";
export { AuthzContext, REQUEST_CONTEXT_KEY } from "./nest/request-context.decorator.js";
export { AuthzModule, AUTHZ } from "./nest/authz.module.js";

// NestJS feature modules + options token (idiomatic adoption)
export {
  AUTHZ_OPTIONS, AUTHZ_ENGINE, AUTHZ_CACHE, AUTHZ_METRICS, AUTHZ_AUDIT,
  AUTHZ_VALIDATOR, AUTHZ_BOOTSTRAP, AUTHZ_SERVICE_IDENTITY, AUTHZ_USER_AUTH_ENABLED,
  AuthzModuleAsyncOptions,
} from "./nest/authz-options.js";
export { decideRequest, DecideDeps, DecideInput, DecideOutcome } from "./decision-engine/decide.js";

// SPI
export * from "./spi/index.js";
