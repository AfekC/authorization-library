# Framework-Idiomatic Restructure — Design

**Date:** 2026-06-11
**Status:** Approved (Approach A)
**Topic:** Restructure both libraries so each fits its framework's idioms — NestJS as real feature modules, Spring Boot as sliced auto-configuration — without changing any authorization decision.

## Problem

Both libraries are deliberately organized in **parallel, framework-agnostic** domain folders
(`audit`, `cache-sync`, `decision-engine`, `inbound-auth`, `outbound`, `observability`,
`role-service-client`, `rule-config`, `service-token`). Framework wiring is bolted on at the edge:

- **NestJS** — every component is a plain class built imperatively in `bootstrap/create-authz.ts`,
  producing one large `Authz` object. `nest/AuthzModule.forRoot()` wraps that whole object into DI via
  factory providers, so NestJS DI never sees the individual components. The real decision logic lives in
  an Express middleware (`runAuthz()`) inside `create-authz.ts`, while `nest/authz.guard.ts` is a
  *separate* guard — two places that must stay behaviorally identical.
- **Spring** — a single ~400-line `boot/AuthzAutoConfiguration` holds *every* `@Bean` (engine, cache,
  sync, validator, outbound, security filter chain, micrometer binding, o11y compat). It is auto-config
  driven (idiomatic in spirit) but monolithic, with no per-concern slicing or ordering.

The goal is a **full idiomatic redesign** of both, accepting demo/e2e churn.

## Non-Negotiable Invariant: Runtime Parity

The project's core guarantee is **cross-language correctness**, and it stays sacred:

1. The 46 language-neutral test vectors (`docs/contracts/test-vectors/*.vectors.json`) are **unchanged**
   and continue to pass in **both** libraries.
2. `tests/e2e/run.mjs` drives identical HTTP requests against both demo services and asserts **identical
   decisions** (decision matrix, live Kafka propagation, outbound propagation, audience rejection).

Internal structure and the *adoption API* may diverge per framework. **Authorization behavior may not.**

### The linchpin: a single shared decision core (per language)

Today NestJS has the decision logic duplicated in spirit (Express `runAuthz()` vs. `AuthzGuard`). Making
the guard a first-class citizen risks two divergent copies — the exact failure mode the parity spine
exists to prevent. Therefore, in **each** library the redesign extracts one framework-agnostic decision
function that every entry point delegates to:

- **NestJS** — `decision-engine` (or a new `core/decide.ts`) exposes `decideRequest(input, deps)`
  returning a pure decision outcome (decision, matched rule, principals, audit event, metrics intents).
  Both `AuthzGuard` (NestJS path) and the `createAuthz()` Express middleware call it. No logic is copied.
- **Spring** — the request-handling core of `AuthorizationFilter` is already the single path; it stays the
  one decision site. The slicing below must not introduce a second one.

This is the safety net that lets us refactor structure aggressively.

## Approach A (chosen)

Idiomatic in place, **single artifact per library**, shared decision core. (Rejected: B — `core` +
`-starter` Maven split / NestJS sub-path entrypoints: doubles Spring build/CI/Docker-mvn surface for no
runtime gain here. C — minimal provider veneer: doesn't make components real DI citizens, fails the
"full idiomatic" goal.)

### NestJS target structure

Domain folders become **NestJS feature modules**, each exposing real `@Injectable()` providers; a root
module composes them.

| Module | Provides | Source folders folded in |
|---|---|---|
| `DecisionEngineModule` | `AuthorizationEngine` (from compiled config), shared `decideRequest()` | `decision-engine`, `rule-config` |
| `PermissionCacheModule` | `PermissionCache` (singleton) | `permission-cache` |
| `InboundAuthModule` | `TokenValidator` (factory), context/bearer helpers | `inbound-auth` |
| `CacheSyncModule` | `HttpRoleServiceClient`, `DiskCache`, `KafkaCacheEventHandler`, `CacheBootstrap` | `role-service-client`, `cache-sync` |
| `OutboundModule` | `ClientCredentialsProvider`, `AuthzOutboundInterceptor`, AsyncLocalStorage context store | `service-token`, `outbound` |
| `ObservabilityModule` | `Metrics`, `AuditSink` (factory), OTel bridge | `observability`, `audit` |

Root: `AuthzModule.forRoot(options)` and `AuthzModule.forRootAsync({ useFactory, inject })` provide an
`AUTHZ_OPTIONS` token consumed by the feature modules' factories. The async variant is the idiomatic
NestJS shape (config from `ConfigService`, etc.); `forRoot` is kept for the static case, and an
env-driven default mirrors today's `createAuthz()`.

**Justification (NestJS API shape, per the open question):** `forRootAsync` + sub-modules is the standard
NestJS dynamic-module pattern and is what lets the lib integrate with `@nestjs/config`. We provide both
`forRoot` (sync/static, used by tests) and `forRootAsync` (idiomatic runtime), composing the same feature
modules underneath, so there is exactly one wiring graph.

**Lifecycle:** the imperative startup sequence (`boot.start()` → `startSeedRetry()` →
`startReconciler()` → service-token endpoint probe) moves into NestJS lifecycle hooks. `CacheBootstrap`
becomes `@Injectable()` implementing `OnApplicationBootstrap` (run the state machine after the DI graph is
built) and `OnModuleDestroy` (`stop()`); `ClientCredentialsProvider` implements `OnModuleDestroy` to clear
its refresh timer. The root module no longer hand-manages a single `Authz` promise.

**Guard as sole NestJS decision path:** `AuthzGuard` is registered as `APP_GUARD` (global enforcement,
no per-route opt-in) and injects the real providers (`AuthorizationEngine`, `PermissionCache`, `Metrics`,
`TokenValidator`, `AuditSink`, optional `PolicyEngine`/`RoleResolver`). It calls `decideRequest()`.

**`createAuthz()` retained** as a thin Express-compat wrapper over the same `decideRequest()` core and the
same providers, so non-Nest Express hosts (and existing tests) keep working.

**Public API / barrel:** `src/index.ts` keeps exporting the same primitives (engine, cache, SPI, helpers,
`createAuthz`) plus the new `AuthzModule`/feature modules. Existing named exports remain so downstream
imports don't break; folder moves are internal.

### Spring target structure

Split the monolith into **ordered `@AutoConfiguration` slices** under a dedicated `autoconfigure` package;
domain packages (`engine`, `cache`, `sync`, `context`, `outbound`, `observability`, `web`) are unchanged.

| Auto-config slice | Beans |
|---|---|
| `AuthzCoreAutoConfiguration` | `AuthzProperties`, config validator, `AuthorizationEngine`, `PermissionCache` |
| `InboundAuthAutoConfiguration` | `TokenValidator`, `HeaderSanitizer`, request-scoped `AuthzRequestContext` |
| `CacheSyncAutoConfiguration` (`@Conditional OnUserAuthEnabled`) | `CacheEventHandler` (Kafka), `CacheBootstrap`, `AuthzHealth`, `RoleResolver` |
| `OutboundAutoConfiguration` | `ServiceIdentityProvider`, `OutboundPropagationInterceptor`, RestClient/RestTemplate customizers |
| `ObservabilityAutoConfiguration` | `Metrics`, Micrometer binding, o11y compat util, `AuditSink` |
| `WebSecurityAutoConfiguration` | `AuthorizationFilter`, `SecurityFilterChain` |

Registered in `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` with
explicit ordering via `@AutoConfiguration(after = …, before = …)` — Core first; Web/Security last (after
the filter's collaborators and `CacheBootstrap` exist); the existing
`beforeName = "idf.hatraa.ObservabilityAutoConfiguration"` constraint is preserved on the Observability
slice. Every bean keeps `@ConditionalOnMissingBean` so apps can still override anything. `PolicyEngine`
/ `AttributeProvider` defaults stay where their consumers live.

Package move: `com.example.authz.boot` → `com.example.authz.autoconfigure` (idiomatic Spring Boot starter
convention). The single `.imports` file lists the six slices.

### Demos

- **nestjs-demo** is converted from an Express host calling `createAuthz()` into a **real NestJS
  application** (`AppModule` importing `AuthzModule.forRoot(...)`, a Nest controller mirroring the current
  routes). It must expose the same HTTP surface on the same port with the same env contract so
  `tests/e2e/run.mjs` is unaffected behaviorally.
- **spring-demo** keeps relying purely on auto-config; only its dependency on the sliced config (via the
  `.imports` file) needs to resolve — no code change expected beyond verification.

## Data Flow (unchanged)

Inbound request → header sanitization → token validation (user JWT and/or service token) → build
`RequestContext` from validated claims only → `decideRequest()` (rule match by wildcard scoring →
decision-matrix evaluation against role permissions / service allow-list) → audit emit + metrics inc →
ALLOW (attach outbound context) or DENY. Startup, Kafka, reconciler, disk-cache fallback, and outbound
propagation semantics are all preserved; only *where the wiring lives* changes.

## Error Handling

- Config errors remain **fail-fast at startup** (NestJS: thrown from factory/lifecycle and surfaced
  before the app serves; Spring: `ConfigException` from the validator bean). Seed-mode fallback is
  unchanged.
- The shared `decideRequest()` core preserves today's failure mapping: missing credentials → 401,
  token validation failure → 401 + `*_token_failures_total`, denied decision → 403 +
  `authz_permission_denied_total`.

## Testing Strategy

- **Parity first:** the vector runners (`vectors.spec.ts`, `SharedVectorsTest.java`) keep loading the same
  JSON and must pass before and after each step. They may relocate to idiomatic test folders but stay
  functionally identical.
- **Per-module unit tests:** existing suites move alongside their modules/slices and are updated only for
  new wiring (e.g., `authz-module.spec.ts` exercises `forRootAsync`; a Spring slice test per
  auto-config). No assertion of authorization behavior changes.
- **e2e unchanged:** `tests/e2e/run.mjs` runs against both demos (now: real NestJS app + Spring app) and
  must show identical outcomes — the ultimate parity gate.
- **TDD discipline:** for each move, run the relevant suite green → restructure → green again; new wiring
  (forRootAsync, lifecycle hooks, each Spring slice) gets a test written before the wiring.

## Sequencing (high level — detailed plan to follow)

1. **Extract shared decision core** in each lib first (NestJS `decideRequest()`; confirm Spring's single
   path), with tests, *before* moving folders. This locks parity.
2. **Spring slicing** — split auto-config into the six `@AutoConfiguration` classes, move `boot` →
   `autoconfigure`, update `.imports`, keep beans byte-identical. Run unit + vector suites.
3. **NestJS modularization** — introduce feature modules + `forRoot/forRootAsync`, move folders, lifecycle
   hooks, guard-as-sole-path; keep `createAuthz()` wrapper. Run unit + vector suites.
4. **Convert nestjs-demo** to a real NestJS app; keep HTTP surface/port/env identical.
5. **Full e2e** parity run across both demos.
6. **Docs** — update `CLAUDE.md` project-structure section and standards docs to reflect the new layout
   and the now-intentional structural divergence (with the parity spine called out as the invariant).

## Risks & Mitigations

- **Divergent decision logic** (primary) → shared `decideRequest()` core + vector/e2e gates at every step.
- **Public API breakage** for downstream consumers → keep all existing named exports / bean types and
  `@ConditionalOnMissingBean`; only relocate internals.
- **NestJS startup ordering** (cache must be ready before serving) → `OnApplicationBootstrap` for the
  state machine; guard depends on populated providers.
- **e2e drift when nestjs-demo becomes a Nest app** → hold port, routes, and env contract constant;
  validate with `run.mjs` before declaring done.
- **Spring auto-config ordering regressions** → explicit `@AutoConfiguration(before/after)` and a slice
  test asserting the security filter sees its collaborators.

## Out of Scope

- Changing the test vectors or any authorization semantics.
- Spring `core` + `-starter` Maven split (Approach B).
- NestJS package sub-path entrypoints.
- Any refactor of decision-matrix / scoring algorithms.
