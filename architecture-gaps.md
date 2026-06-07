# Architecture Gaps — Implementation vs `authz-middleware-architecture.md`

Gaps identified during audit sessions. Items H1-L4 fixed 2026-06-07. New findings M1-N8 from second pass 2026-06-07. **M1–M4 and N1–N8 resolved 2026-06-07 (third pass, best-of-both parity) — see Resolution Status below.**

## Resolution Status (third pass, 2026-06-07)

HIGH (M) and MEDIUM (N) gaps fixed across both libraries; parity direction = best-of-both (adopt the safer/better behavior in both languages, deviations noted). Verified green: NestJS 315 tests, Java 230 tests.

- **M1** — NestJS `AuthzGuard` service-token failure path now uses `incTokenFailure(METRIC.serviceTokenFailures, classifyTokenFailure(err))`, matching middleware + Java filter.
- **M2** — `createAuthz()` `Authz` return type now exposes `validator` and `audit`, enabling guard/module wiring without duplicate setup.
- **M3** — Java `probeTokenEndpoint()` now performs a fail-open real token acquisition that **warms the cache** at startup (best-of-both: warm cache wins), matching NestJS `checkTokenEndpoint()`. Both first outbound calls are now instant.
- **M4** — No code change: jose `clockTolerance` and Java `NbfValidator` (`nbf - skew > now`) produce identical accept/reject decisions at the nbf boundary. Confirmed by new boundary tests in both libraries.
- **N1** — `AuthzGuardDeps` gained optional `policyEngine`/`roleResolver`; guard now branches identically to the middleware.
- **N2** — Unified error body on `{ "error": "<msg>" }`. Guard now throws `HttpException({ error }, status)` instead of bare `Unauthorized/ForbiddenException`. **Deviation/breaking:** the guard's legacy `{message,statusCode,error}` envelope is gone; clients read `body.error`.
- **N3** — Shared `extractBearer()` (`src/inbound-auth/bearer.ts`), array-aware + `/^Bearer\s+(.+)$/i`, used by both guard and middleware. Double-space `Bearer  token` now handled consistently. (Helper returns `undefined`; middleware normalizes with `?? null`.)
- **N4** — NestJS `sanitizeHeadersInPlace(headers, options?)` exported from `context.ts`, sharing the identity-detection predicate with `stripUntrustedHeaders`; mirrors Java `SanitizingRequestWrapper` defense-in-depth for downstream reads.
- **N5** — Java reconciler catch block now increments `role_refresh_failures_total`, matching `forcedRefresh()` and the NestJS reconciler.
- **N6 / L2** — NestJS `cache-sync/bootstrap.ts` routes both `onEvent` and `onRefresh` through a single `applyChain` promise-mutex, serializing applies against forced refreshes (no lost-upsert race) with a `.catch()` guard against unhandled rejections.
- **N7** — NestJS `loader.ts` preprocesses YAML to auto-quote bare `*` (`/\*(?=\s*[,\]])/g` → `"*"`), exactly matching Java `YamlLoader`. `allowedServices: [*]` now parses in both.
- **N8** — Added `AuthzModule.forRoot(options)` (`src/nest/authz.module.ts`): calls `createAuthz()` once, provides `AUTHZ`/`AuthzGuard` DI tokens, registers `APP_GUARD` for global enforcement, and cleans up via `OnModuleDestroy` → `authz.stop()`. Mirrors Java `AuthzAutoConfiguration`.


## Remaining Gaps (from first pass, LOW only)

All HIGH and MEDIUM gaps from the first pass (H1-H9, I1-I2, J1-J5, K1-K4, L1) have been fixed.

## New Gaps (second pass, 2026-06-07)

---

## I. Observability Gaps

### I3. (LOW) Health mode name case inconsistency

**Java** `AuthzHealth` emits `"NORMAL"` / `"SEED"` (UPPER_CASE enum name).
**NestJS** `buildHealth` emits `"normal"` / `"seed"` (lower_case). Documented in `contracts/rest-api.md` but not resolved.

**Files:**
- `contracts/rest-api.md:54-55`
- `libraries/authz-spring-boot/src/main/java/com/example/authz/observability/AuthzHealth.java:32`

### I4. (LOW) No metrics for service token refresh success in either library

Both libraries track `service_token_failures_total` but neither has counters for successful token refreshes or total refresh attempts. Impossible to calculate refresh success rate.

---

## J. Configuration & Standards Gaps

### J6. (LOW) NestJS lacks TSDoc on core type definitions

**Java** provides Javadoc on all enums/records: `Decision`, `AuthType`, `DecisionMode`, `Segment`, `SegmentKind`, `AuthorizationRequest`, `ConfigException`.
**NestJS** defines equivalent TypeScript types with no TSDoc documentation.

**Files:**
- `libraries/authz-nestjs/src/rule-config/types.ts` (Decision, AuthType, DecisionMode, Segment, SegmentKind)
- `libraries/authz-spring-boot/src/main/java/com/example/authz/engine/Decision.java`

### J7. (LOW) Error message wording differs for partial wildcard rejection

**Java**: `"partial wildcards are not supported (segment \"...\" in \"...\")".
**NestJS**: `` `partial wildcards are not supported; use full-segment * or trailing ** only (segment "${...}" in "${...}")` ``.

More informative in NestJS but deviates from cross-language parity for test vectors.

**Files:**
- `libraries/authz-spring-boot/src/main/java/com/example/authz/config/RuleCompiler.java:104`
- `libraries/authz-nestjs/src/rule-config/compile.ts:28-30`

### J8. (LOW) NestJS exposes more internal functions in public API than Java

**NestJS** exports `parseRoleEvent`, `AxiosLike`, `OutboundContext`, `currentOutboundContext`, `runWithOutboundContext` as public API from `index.ts`.
**Java** keeps these as package-private (e.g., `RoleEvents`, `SanitizingRequestWrapper`). Creates stronger backward-compatibility commitment for NestJS.

**File:**
- `libraries/authz-nestjs/src/index.ts`

---

## K. Test Coverage Gaps (Second Pass)

### K5. (LOW) Java Scoring wildcard-matching functions not directly unit-tested

`Scoring.splitPath()`, `scoreSegment()`, `matchPath()`, `compareSpecificity()` — core wildcard matching — tested only indirectly via `AuthorizationEngine.compile`.

### K6. (LOW) NestJS scoring.ts not directly unit-tested

Same as K5 for NestJS — wildcard-scoring functions tested only through integration.

### K7. (LOW) No AuthzProperties property-binding test

No `@SpringBootTest` verifies property binding, default values, or that missing required properties trigger the `ConfigValidator`'s fail-fast checks.

---

## L. Error-Handling & Edge-Case Gaps

### L2. (LOW) NestJS forcedRefresh Promise not awaited in Kafka callback

`void this.forcedRefresh()` in Kafka message handler — if it rejects before the catch, the rejection is unhandled. Java runs this synchronously within a try-catch.

**File:**
- `libraries/authz-nestjs/src/cache-sync/bootstrap.ts:112`

### L3. (LOW) OutboundPropagationInterceptor always created even without outbound identity

The bean is created unconditionally (no `@ConditionalOnProperty(authz.client-id)` guard). While `OutboundHeaders` handles null gracefully, an empty interceptor is added to every `RestClient`/`RestTemplate`. A `DEFERRED` comment acknowledges this.

**File:**
- `libraries/authz-spring-boot/src/main/java/com/example/authz/outbound/OutboundPropagationInterceptor.java:25`

### L4. (LOW) Sparse Javadoc/JSDoc coverage on public APIs

Only 13 `@param`/`@return`/`@throws` annotations exist across the entire main Java source. Many public constructors, methods, and records lack documentation. NestJS `Metrics` class has no method-level JSDoc.

---

## M. Cross-Language Observability & Wiring Gaps (Second Audit 2026-06-07)

### M1. (HIGH) AuthzGuard missing `classifyTokenFailure` for service tokens

The middleware (`create-authz.ts`) and Java `AuthorizationFilter` both call `metrics.incTokenFailure(METRIC.serviceTokenFailures, classifyTokenFailure(err))` for service token validation failures, incrementing both aggregate AND mode-specific counters. The `AuthzGuard` only calls `this.deps.metrics.inc(METRIC.serviceTokenFailures)` — no mode classification for the service token path. The `classifyTokenFailure` import is present in the guard but never used for service tokens.

**Files:**
- `libraries/authz-nestjs/src/nest/authz.guard.ts:71-73`
- `libraries/authz-nestjs/src/bootstrap/create-authz.ts:233-234`
- `libraries/authz-spring-boot/src/main/java/com/example/authz/web/AuthorizationFilter.java:169-175`

### M2. (HIGH) `createAuthz()` does not expose `validator` or `audit` for guard wiring

The `Authz` return type from `createAuthz()` (lines 90-117) includes `engine`, `cache`, `metrics`, `mode`, `serviceIdentity`, `middleware`, `attachOutbound`, `createClient`, `health`, `stop` — but NOT the `validator` (TokenValidator) or `audit` (AuditSink) instances. `AuthzGuardDeps` requires both `validator` and `audit`. A developer cannot bootstrap the guard from `createAuthz()` without duplicating dependency setup.

**Files:**
- `libraries/authz-nestjs/src/bootstrap/create-authz.ts:90-117`
- `libraries/authz-nestjs/src/nest/authz.guard.ts:25-31`

### M3. (HIGH) Token endpoint probe: Java `HEAD` vs NestJS full token acquisition

Java's `probeTokenEndpoint()` sends a lightweight `HEAD` request to the token URL with timeout but no side effects. NestJS's `checkTokenEndpoint()` performs a full `getServiceToken()` call, which acquires and **caches** a real token. This means NestJS has a warm token cache at startup (first outbound call is instant) while Java's first outbound call pays the latency of a fresh token acquisition. Different startup behavior for outbound calls.

**Files:**
- `libraries/authz-spring-boot/src/main/java/com/example/authz/outbound/ClientCredentialsServiceIdentityProvider.java:234-250`
- `libraries/authz-nestjs/src/service-token/provider.ts:121-130`

### M4. (HIGH) `nbf` (not-before) validation: Java explicit vs NestJS implicit

Java has a custom `NbfValidator` class (lines 147-172) that checks the `nbf` claim with explicit clock-skew subtraction: `nbf.minus(clockSkew).isAfter(now)`. NestJS relies on the `jose` library's `jwtVerify` built-in `nbf` handling via the `clockTolerance` parameter. If `jose` applies the clock skew differently from Java's explicit `nbf - skew > now` check, tokens could be accepted by one and rejected by the other at timing boundaries.

**Files:**
- `libraries/authz-spring-boot/src/main/java/com/example/authz/web/NimbusJwksTokenValidator.java:147-172`
- `libraries/authz-nestjs/src/inbound-auth/token-validator.ts:46-61`

---

## N. Cross-Language Behavioral & SPI Gaps (Second Audit 2026-06-07)

### N1. (MEDIUM) AuthzGuard ignores PolicyEngine/RoleResolver SPI overrides

The middleware branches on `opts.policyEngine` / `opts.roleResolver` to support SPI-based decision overrides. The guard unconditionally calls `this.deps.engine.evaluate(...)` with the cache. `AuthzGuardDeps` has no `policyEngine` or `roleResolver` fields. Users who configure a custom `PolicyEngine` or `RoleResolver` get it honored by the middleware and Java filter, but silently ignored by the guard.

**File:**
- `libraries/authz-nestjs/src/nest/authz.guard.ts:86-90`

### N2. (MEDIUM) Error response JSON shapes differ between middleware and guard

| Scenario | Middleware (Express) | Guard (NestJS exception) |
|---|---|---|
| 401 | `{ "error": "..." }` | `{ "message": "...", "statusCode": 401 }` |
| 403 | `{ "error": "authorization denied" }` | `{ "message": "...", "error": "Forbidden", "statusCode": 403 }` |

API consumers parsing the `error` field would get `undefined` from the guard path (where it's `message`). Different client-visible contracts between the two NestJS auth paths.

**Files:**
- `libraries/authz-nestjs/src/bootstrap/create-authz.ts:213,224,235,302`
- `libraries/authz-nestjs/src/nest/authz.guard.ts:51,63,73,108`

### N3. (MEDIUM) Bearer extraction: middleware cannot handle array/duplicate headers

The guard's `extractBearer` handles Express aggregating duplicate headers into an array (`Array.isArray(header) ? header[0] : header`). The middleware's inline check uses `typeof authHeader === "string"` only — if `Authorization` arrives as an array, it silently treats it as absent. Additionally, the guard uses regex `\s+` (any whitespace after `Bearer`) while the middleware uses `.slice(7)` (exactly one space). A double-space `Bearer  token` would produce `" token"` (leading space) in the middleware but `"token"` (clean) in the guard.

**Files:**
- `libraries/authz-nestjs/src/nest/authz.guard.ts:112-119`
- `libraries/authz-nestjs/src/bootstrap/create-authz.ts:205-208`

### N4. (MEDIUM) No defense-in-depth header sanitization in NestJS

Java wraps the servlet request in a `SanitizingRequestWrapper` that intercepts ALL calls to `getHeader()` / `getHeaders()` for untrusted identity headers. Any downstream code (filters, controllers, services) that reads raw headers gets sanitized values automatically. NestJS's `stripUntrustedHeaders` returns a filtered copy — only the guard/middleware uses it. Downstream NestJS code reading `req.headers` directly sees raw, untrusted identity headers.

**Files:**
- `libraries/authz-spring-boot/src/main/java/com/example/authz/web/AuthorizationFilter.java:130-136`
- `libraries/authz-nestjs/src/inbound-auth/context.ts:52-80`

### N5. (MEDIUM) Reconciler failure metric not incremented in Java

The Java `CacheBootstrap` reconciler catch block (line 138) logs `LOG.warn("authz reconciler snapshot fetch failed...", e)` but does NOT increment `role_refresh_failures_total`. The NestJS reconciler catch (line 168) DOES increment `METRIC.roleRefreshFailures`. If the Role Service is intermittently down, Java silently logs warnings while NestJS increments the observable failure counter. Metrics diverge between the two implementations.

**Files:**
- `libraries/authz-spring-boot/src/main/java/com/example/authz/sync/CacheBootstrap.java:137-139`
- `libraries/authz-nestjs/src/cache-sync/bootstrap.ts:163-166`

### N6. (MEDIUM) forcedRefresh execution model: synchronous (Java) vs fire-and-forget (NestJS)

Java calls `this::forcedRefresh` synchronously on the Kafka consumer thread — blocks further message processing until the refresh completes, ensuring serialized event ordering. NestJS fires `() => { void this.forcedRefresh(); }` — the Promise is discarded and the refresh runs concurrently with Kafka message processing. A `publish-roles` message triggers an async refresh → a concurrent `role-updates` message is applied to cache → refresh completes and overwrites the cache with a snapshot that doesn't include the just-applied upsert → the upsert is silently lost.

**Files:**
- `libraries/authz-spring-boot/src/main/java/com/example/authz/sync/CacheBootstrap.java:96`
- `libraries/authz-nestjs/src/cache-sync/bootstrap.ts:114-116`

### N7. (MEDIUM) YAML unquoted `*` auto-quoting missing in NestJS

Java's `YamlLoader.java` (line 21) preprocesses YAML text with `yamlText.replaceAll("\\*(?=\\s*[,\\]])", "\"*\"")`, auto-quoting bare `*` values in arrays before SnakeYAML parsing. This prevents SnakeYAML from interpreting `*` as a YAML alias reference. NestJS's `loader.ts` passes raw text to `js-yaml` with no preprocessing. A YAML file with `allowedServices: [*]` (unquoted) parses in Java but may fail in NestJS.

**Files:**
- `libraries/authz-spring-boot/src/main/java/com/example/authz/config/YamlLoader.java:21`
- `libraries/authz-nestjs/src/rule-config/loader.ts:15`

### N8. (MEDIUM) No NestJS `@Module()` for auto-wiring

Java provides `AuthzAutoConfiguration` with `@ConditionalOnMissingBean` semantics — every SPI component is auto-wired, configurable via properties, and individually overridable. The NestJS library has no equivalent `@Module()` decorator. The `AuthzGuard`, `AuthzOutboundInterceptor`, `AuthzContext` decorator, and all dependencies must be manually registered by the consumer. The NestJS demo service uses the middleware path, confirming the guard path has no auto-configuration story.

**Files:**
- `libraries/authz-spring-boot/src/main/java/com/example/authz/boot/AuthzAutoConfiguration.java`
- Missing `libraries/authz-nestjs/src/nest/authz.module.ts`

---

## O. Test & Documentation Gaps (third pass, 2026-06-07)

> New findings from a project-wide audit. Unresolved — candidates for a future fix pass.
> Verified against current code (NestJS 315 tests, Java 230 tests).

### O1. (MEDIUM) Stale test/vector counts in docs

Root `README.md` advertises `58 tests` (NestJS) and `51 tests` (Spring); actual current counts are **315** and **230**. The "29 shared vectors" claim (README + `CLAUDE.md` + `contracts/test-vectors/README.md`) is also stale — `contracts/test-vectors/edge-cases-3.vectors.json` was added (now 7 vector files) without updating the count anywhere.

**Files:**
- `README.md:63,70` · `CLAUDE.md` (Cross-Language Correctness + Commands) · `contracts/test-vectors/README.md`

### O2. (MEDIUM) `CreateAuthzOptions` tuning parameters undocumented

`CreateAuthzOptions` exposes ~13 optional fields (Kafka topic names, `kafkaGroupId`/`kafkaClientId`, `reconcileIntervalMs`, `clockSkewSeconds`, role-service timeouts, `serviceTokenUseClaim`, `diskCachePath`). The NestJS `README.md` Configuration table documents only required fields; adopters must read the TypeScript source to tune anything.

**Files:**
- `libraries/authz-nestjs/src/bootstrap/create-authz.ts:33-82` · `libraries/authz-nestjs/README.md`

### O3. (LOW) `clockSkewSeconds` default/behavior not documented anywhere user-facing

Default is 5s (`token-validator.ts:52,69`) and mentioned only in prose in `authz-middleware-architecture.md`. Not in the NestJS README config table, `contracts/rest-api.md`, or `CLAUDE.md`. No documented range/semantics.

**Files:**
- `libraries/authz-nestjs/src/inbound-auth/token-validator.ts:52,69` · `libraries/authz-nestjs/README.md`

### O4. (LOW) No unit coverage for `StripHeadersOptions` extension parameters

The N4 `sanitizeHeadersInPlace` / `stripUntrustedHeaders` deny-list is extensible via `additionalPrefixes` / `additionalExactNames` (`resolveHeaderLists`), but no test exercises the extension path (custom prefix, case-folding, overlap).

**Files:**
- `libraries/authz-nestjs/src/inbound-auth/context.ts` (`resolveHeaderLists`) · `libraries/authz-nestjs/test/`

### O5. (LOW) Outbound combined-auth re-propagation not covered by a shared vector

The e2e forwards a USER request downstream with the caller's own service token (a USER_AND_SERVICE downstream call). The shared vectors cover USER_AND_SERVICE *decisions* but never the outbound *re-propagation* of user JWT + service token. (Vectors are decision-only by design — may belong in e2e instead.)

**Files:**
- `tests/e2e/run.mjs` · `contracts/test-vectors/*.vectors.json`

---

## P. Cross-Language Consistency & Standards Gaps (third pass, 2026-06-07)

### P1. (HIGH) NestJS `createAuthz` cannot configure `serviceTokenUseValue`

`JwksTokenValidator` honors `serviceTokenUseValue` (`token-validator.ts:31,86`) and Java exposes both `serviceTokenUseClaim` and `serviceTokenUseValue` via `AuthzProperties` (`:26-27,77-78`). But `createAuthz` only plumbs `serviceTokenUseClaim` (`create-authz.ts:163`) — the value is hard-defaulted to `"service"`. A deployment that issues service tokens with a non-default `token_use` value works in Spring but cannot be configured in NestJS via the bootstrap path.

**Files:**
- `libraries/authz-nestjs/src/bootstrap/create-authz.ts:156-166` · `libraries/authz-spring-boot/src/main/java/com/example/authz/boot/AuthzProperties.java:26-27`

### P2. (HIGH) NestJS startup validates only 4 of 6 required URLs

`createAuthz` fail-fast checks `audience`, `userIssuer`, `userJwksUri`, `roleServiceUrl` (`create-authz.ts:136-139`) but NOT `serviceIssuer` / `serviceJwksUri`. Java's `AuthzAutoConfiguration` validates all six. A NestJS deployment missing the service JWKS config starts successfully and only fails at the first service-token validation (runtime), not startup.

**Files:**
- `libraries/authz-nestjs/src/bootstrap/create-authz.ts:136-139` · `libraries/authz-spring-boot/src/main/java/com/example/authz/boot/AuthzAutoConfiguration.java`

### P3. (MEDIUM) N3/N4 helpers not re-exported from the package entry point

`extractBearer` (`inbound-auth/bearer.ts`), `sanitizeHeadersInPlace` and `StripHeadersOptions` (`inbound-auth/context.ts`) are not re-exported from `src/index.ts`. Consumers writing custom middleware must deep-import internal paths, defeating the public-API barrel.

**Files:**
- `libraries/authz-nestjs/src/index.ts:16-22` · `libraries/authz-nestjs/src/inbound-auth/bearer.ts` · `libraries/authz-nestjs/src/inbound-auth/context.ts`

### P4. (LOW) Required-property validation order differs → different first error

NestJS validates `audience` first then issuers; Java validates issuers first and `audience` last. For a config missing multiple required fields, the two libraries surface different "first missing" error messages.

**Files:**
- `libraries/authz-nestjs/src/bootstrap/create-authz.ts:136-139` · `libraries/authz-spring-boot/.../boot/AuthzAutoConfiguration.java`

### P5. (LOW) Proactive-refresh fraction: named constant (Java) vs magic literal (NestJS)

Java defines `PROACTIVE_REFRESH_FRACTION = 0.70` (`ClientCredentialsServiceIdentityProvider.java:66`). NestJS uses the bare literal `0.7` as the default (`service-token/provider.ts:92`) — no named constant.

**Files:**
- `libraries/authz-spring-boot/.../outbound/ClientCredentialsServiceIdentityProvider.java:66` · `libraries/authz-nestjs/src/service-token/provider.ts:92`

> Note: cache-mode name casing (`NORMAL`/`SEED` vs `normal`/`seed`) is already tracked as **I3** — not re-listed here.

---

## Q. Error-Handling, Edge-Case, Security & Resilience Gaps (third pass, 2026-06-07)

### Q1. (HIGH) NestJS disk-cache write is unguarded and synchronous

`DiskCache.write()` calls `fs.writeFileSync` with no try/catch (`disk.ts:13-19`). After the N6 fix, writes run inside the `applyChain.then(...).catch(...)`, so a write failure (disk full, EACCES, missing dir) is **silently swallowed with no log and no metric** — the in-memory cache advances while the disk fallback goes stale, and a later restart reloads the stale snapshot. Being synchronous, it also blocks the event loop during a Kafka event burst. Java throws a checked exception and runs disk I/O off the request thread.

**Files:**
- `libraries/authz-nestjs/src/cache-sync/disk.ts:13-19` · `libraries/authz-nestjs/src/cache-sync/bootstrap.ts` (write call sites)

### Q2. (HIGH) Role Service snapshot is shape-checked but not value-validated

`HttpRoleServiceClient.fetchSnapshot()` rejects non-object/null/array bodies but does not validate that each map value is a `string[]` (`client.ts:39-45`). A response like `{"ADMIN": null}` or `{"ADMIN": {"x":1}}` is accepted and stored, producing wrong permission evaluation or runtime errors downstream.

**Files:**
- `libraries/authz-nestjs/src/role-service-client/client.ts:39-45`

### Q3. (MEDIUM) No timeout on NestJS JWKS fetch

`createRemoteJWKSet(new URL(...))` is constructed without `timeoutDuration` (`token-validator.ts:41-42`). A slow/unresponsive JWKS endpoint hangs `jwtVerify` and the request handler; concurrent requests pile up. Java's Nimbus decoder has a configurable HTTP timeout (default 5s).

**Files:**
- `libraries/authz-nestjs/src/inbound-auth/token-validator.ts:41-42`

### Q4. (MEDIUM) Config URLs not validated for well-formedness (both libraries)

`userIssuer`/`userJwksUri`/`serviceIssuer`/`serviceJwksUri`/`roleServiceUrl`/`tokenUrl` are presence-checked but never parsed/validated. A typo (`htp://…`, `http://`) starts cleanly and fails later with a cryptic network error instead of a fail-fast config error at startup.

**Files:**
- `libraries/authz-nestjs/src/bootstrap/create-authz.ts:136-166` · `libraries/authz-spring-boot/.../boot/AuthzAutoConfiguration.java`

### Q5. (MEDIUM) Kafka role events not validated for empty `roleId`/permissions

`applyRoleEvent` checks `roleId` is a string but not non-empty, and does not validate permission entries are non-empty strings (`events.ts`). An event `{"roleId":"","permissions":["READ"]}` (or a `""` permission) is applied to the cache, creating a phantom empty-string role/permission that can match unexpectedly. Same pattern in Java `RoleEvents`.

**Files:**
- `libraries/authz-nestjs/src/cache-sync/events.ts` · `libraries/authz-spring-boot/.../sync/RoleEvents.java`

### Q6. (MEDIUM) Java reconciler can be double-started

`CacheBootstrap.startReconciler()` creates a fresh daemon `new Thread(...)` on every call with no guard (`CacheBootstrap.java:121-122`). Two invocations without an intervening `stop()` run two concurrent reconcile loops → duplicate Role Service fetches and a race on the `mode` SEED→NORMAL transition.

**Files:**
- `libraries/authz-spring-boot/src/main/java/com/example/authz/sync/CacheBootstrap.java:121-146`

### Q7. (LOW) mock-service has no request body-size limit

`express.json()` is registered without a `limit` (`demo-services/mock-service/src/index.js`). Default 100KB is usually fine, but `/admin/roles`-style bulk endpoints have no explicit cap or content-type guard — a large body buffers fully in memory. Test infra only, but worth a bound.

**Files:**
- `demo-services/mock-service/src/index.js`
