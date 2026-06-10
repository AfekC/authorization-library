# Implementation Plan — sync code to doc/architecture changes

Source of truth: edits in `authz-middleware-architecture.md`, `docs/contracts/*`,
library + demo READMEs. Decisions confirmed by repo owner (2026-06-10):

- **Scope:** full parity stack (Spring + NestJS libraries, test vectors, mock-service, demo configs, e2e).
- **JWT claims:** rename `sub`→`userId`, `role`→`roleId`; drop `tenant`. Drop `serviceId`, `jwtId` from `RequestContext`. Update the mock token issuer + validators + audit + vectors.
- **Cache version:** remove `version()` *everywhere* — interface, `permission_cache_version` gauge, `currentVersion` health field — and fix the docs that still reference them.

Parity rule: every behavioural change lands in **both** libraries and is covered by the
language-neutral vectors where it is a decision-matrix/rule change.

---

## Phase 1 — Rule config: `public: true` + `methods: ["*"]`
- Spring `RuleCompiler`/`CompiledRule`/`AuthorizationEngine.matchRule`; NestJS `compile.ts`/`types.ts`/`engine.ts`.
- `public: true` → no validation; mutually exclusive with `permissions`/`decision`/`allowedServices` (fail-fast else). Matched public rule → ALLOW.
- `methods: ["*"]` → matches any method (matcher + ambiguity intersection).
- Add `ALLOWED_KEYS` entries `public`. New vectors: `operating-modes`/`public-and-method-wildcard`.

## Phase 2 — Claim/context rename
- Spring `Principals`, `RequestContext`, `RequestContextBuilder`, `AuthorizationFilter` claim reads (`userId`/`roleId`, drop tenant/serviceId/jwtId).
- NestJS `context.ts` (`RequestContext`, `UserPrincipal`, `buildRequestContext`), `token-validator.ts`/guard claim reads.
- Mock-service token issuer: emit `userId`/`roleId` instead of `sub`/`role`/`tenant`.
- Audit events: emit `userId`/`roleId`. Update affected unit tests + vectors request key `role`→`roleId` (or keep `role` in vectors as the abstract resolved-role param — decide during impl; prefer keeping vector key `role` since it's the resolved role, not a claim).

## Phase 3 — Remove `version()` everywhere
- Spring `Spi` (RoleResolver/cache), `PermissionCache.version()`, `AuthorizationFilter` audit call, `AuditEvents`, `Metrics.permission_cache_version`, `AuthzHealth.currentVersion`, `CacheBootstrap` logging.
- NestJS `cache.ts`, metrics, health report, audit.
- Docs: drop `permission_cache_version` row (arch §10.2), `currentVersion` row (arch §10.3 + rest-api.md), `version` field in `authorization-cache.json` (config-files.md) if present.

## Phase 4 — Config restructuring (nested `authz.user.*`)
- Spring `AuthzProperties`: nested `user.{issuer,jwks-uri,audience}`; keep `role-service-url` at top. `ConfigValidator` updated.
- NestJS `env-config.ts`: `AUTHZ_USER_AUDIENCE` (was `AUTHZ_AUDIENCE`); `AUTHZ_USER_ISSUER`/`AUTHZ_USER_JWKS_URI` already exist.
- Demo configs: spring-demo `application.properties` (already edited in README — apply to actual file), nestjs-demo env.

## Phase 5 — Operating modes (service-only) — the big one
- Detect user-auth enabled = presence of the `authz.user` block / `AUTHZ_USER_*`. All-or-nothing: partial → fail-fast.
- When **disabled**:
  - inbound: ignore `Authorization: Bearer`; only `X-Service-Token`. authType always `SERVICE`.
  - decision: service-only matrix (§5.1) — only allowedServices/public; `permissions`-only rule → DENY.
  - wiring: no PermissionCache, RoleServiceClient, Kafka, DiskCache, reconciler, RoleResolver. Token validator validates service tokens only.
  - metrics/health: role/cache metrics + cache health fields absent; jwt_validation_failures not emitted.
  - startup: trivial (load yaml → READY).
- Spring: gate beans in `AuthzAutoConfiguration` on user-auth; `AuthorizationFilter` mode flag; `Metrics`/`AuthzHealth` gating.
- NestJS: gate in `create-authz.ts`; guard/middleware mode flag.
- Vectors: service-only-mode vectors (authType SERVICE, permissions-only DENY, public ALLOW).

## Phase 6 — Docs reconciliation
- Fix remaining version references in arch/rest-api/config-files (Phase 3 covers).
- Confirm demo READMEs (already user-edited) match applied configs.

## Phase 7 — Build + verify
- `tests/scripts/mvn.ps1 -ModuleDir libraries/authz-spring-boot test` (Docker JDK21).
- `cd libraries/authz-nestjs && npm test`.
- `cd libraries/authz-spring-boot` SharedVectorsTest + NestJS vectors.spec.ts must pass identical vectors.
- e2e (`tests/e2e`) if Docker available — add a service-only scenario.

Notes: Java build via **mvn.ps1 (PowerShell)**, not mvn.sh. Subagents can't commit here — controller commits.

## Progress
- [x] SPRING phases 1-5 complete. `mvn test` green: **278 tests, 0 failures** (incl. 53 shared vectors).
  - mvn.ps1 must be called with ABSOLUTE path + `-dangerouslyDisableSandbox` (needs docker); image pulled.
- [x] NESTJS phases 1-5 complete. `npm test` green: **405 tests, 0 failures** (incl. 54 shared-vector cases). `tsc --noEmit` clean.
  - Fixed config-validation tests for new service-always / user-all-or-nothing order; `AUTHZ_AUDIENCE`→`AUTHZ_USER_AUDIENCE` in env tests + demo.
- [x] mock-service token issuer emits `userId`/`roleId` (accepts `sub`/`role` as legacy aliases); e2e `login()` sends `userId`/`roleId`.
- [x] demo configs: spring-demo `application.properties` nested `authz.user.*`; nestjs-demo `AUTHZ_USER_AUDIENCE`.
- [x] new vectors: `public-and-method-wildcard.vectors.json` (7 cases) — pass in BOTH languages.
- [x] docs reconciliation: removed `permission_cache_version` (arch §10.2, CLAUDE.md, AGENTS.md), `currentVersion` (arch §10.3, rest-api.md), `policyVersion` + `role`→`roleId` in audit examples, dropped serviceId from §2.3, "bump the cache version" wording; standards docs cache version/age → age.
- [x] e2e (`tests/e2e`) — **39/39 checks pass on both languages** (decision matrix 14, kafka 2, forced refresh 2, outbound both dirs 14, audience 1, invalid service token 6).
  - Gotcha: spring-demo bundles a PREBUILT fat jar (`target/spring-demo-0.1.0.jar`, COPY'd in Dockerfile). After a library change you MUST: `mvn install` authz-spring-boot → `mvn package` spring-demo → `docker compose up --build`. `compose --build` alone reuses the stale jar → all user requests 403 (old `role` claim vs new `roleId`).
