# NestJS Feature Modules + Demo Conversion — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the NestJS library genuinely idiomatic — a root `AuthzModule.forRoot()/forRootAsync()` composing cohesive feature modules whose providers are real DI citizens with framework lifecycle — while keeping authorization decisions byte-identical and the framework-agnostic core usable without NestJS.

**Architecture:** Extract one shared `decideRequest()` core that both the `AuthzGuard` (NestJS path) and the `createAuthz()` Express middleware call (parity linchpin — eliminates the current duplicated decision logic). Introduce feature modules (`ObservabilityModule`, `DecisionEngineModule`, `PermissionCacheModule`, `InboundAuthModule`, `CacheSyncModule`, `OutboundModule`) that provide the existing core classes via `useFactory` against an `AUTHZ_OPTIONS` token. Startup/shutdown (cache bootstrap state machine, token-refresh timer) moves into thin NestJS lifecycle providers. Convert nestjs-demo from an Express host into a real NestJS app.

**Tech Stack:** TypeScript 5.x, NestJS 11 (optional peer dep), Jest, Express (core path), axios, kafkajs.

**Key constraint — optional NestJS:** `@nestjs/common`/`@nestjs/core` are *optional* peer deps. The pure-logic core (engine, cache, validator, bootstrap, providers, `decideRequest`) MUST NOT import `@nestjs/common`. Only files under `src/nest/` may. Feature modules register core classes via `useFactory` (no `@Injectable()` decorators added to core classes), so the Express path and non-Nest consumers keep working.

**Parity gate (run after every task):** `cd libraries/authz-nestjs; npm test` must stay green, with `vectors.spec.ts` (46 vectors) green throughout.

---

## File Structure

Created:
- `src/decision-engine/decide.ts` — framework-agnostic `decideRequest(input, deps)` returning a pure outcome; the single decision site for both guard and middleware.
- `src/nest/authz-options.ts` — `AUTHZ_OPTIONS` injection token + `AuthzModuleAsyncOptions` type.
- `src/nest/modules/observability.module.ts` — provides `Metrics`, `AuditSink`, OTel bridge.
- `src/nest/modules/decision-engine.module.ts` — provides `AuthorizationEngine` (compiled from options).
- `src/nest/modules/permission-cache.module.ts` — provides `PermissionCache` (singleton).
- `src/nest/modules/inbound-auth.module.ts` — provides `TokenValidator`.
- `src/nest/modules/cache-sync.module.ts` — provides `CacheBootstrap` + Kafka handler; `CacheSyncLifecycle` runs/stops the state machine.
- `src/nest/modules/outbound.module.ts` — provides `ServiceIdentityProvider` (+ lifecycle stop), `AuthzOutboundInterceptor`.
- `tests/demo-services/nestjs-demo/src/app.module.ts`, `orders.controller.ts`, `health.controller.ts`, `main.ts` — the converted Nest app.
- `tests/demo-services/nestjs-demo/package.json` — Nest runtime deps.

Modified:
- `src/nest/authz.guard.ts` — call `decideRequest()` instead of inline logic.
- `src/bootstrap/create-authz.ts` — `runAuthz()` delegates to `decideRequest()`; keep the Express wrapper + `Authz` object.
- `src/nest/authz.module.ts` — `forRoot()/forRootAsync()` compose the feature modules; register `AuthzGuard` (APP_GUARD) + `AuthzOutboundInterceptor` (APP_INTERCEPTOR).
- `src/index.ts` — export the new modules + `decideRequest`; keep all existing exports.
- `tests/demo-services/nestjs-demo/authorization.yaml` — add a `public: true` rule for `GET /health`.

> **Note on "folding folders into modules":** the design's module table is a *logical* grouping. Physically, the pure-logic files stay in their domain folders (so the core remains NestJS-free and shared with the Express path); each feature module *exposes* those classes as providers. This is the correct reconciliation of "fully idiomatic NestJS" with "optional NestJS core."

---

## Task 1: Pin current behavior (baseline)

- [ ] **Step 1: Run the suite and record the green baseline**

Run: `cd libraries/authz-nestjs; npm test`
Expected: all suites pass; note `vectors.spec.ts` = 46 vectors and the total test count.

- [ ] **Step 2: Confirm the two decision paths that must converge**

Read `src/bootstrap/create-authz.ts` `runAuthz()` (lines ~294–418) and `src/nest/authz.guard.ts` `canActivate()`. Confirm they implement the same sequence (header strip → public check → no-creds → validate → build ctx → decide → audit → metrics). Task 2 unifies them.

---

## Task 2: Extract the shared `decideRequest()` core

**Files:**
- Create: `src/decision-engine/decide.ts`
- Test: `test/decide-core.spec.ts`

- [ ] **Step 1: Write the failing test for the core outcome shape**

```ts
// test/decide-core.spec.ts
import { decideRequest, DecideDeps } from "../src/decision-engine/decide";
import { loadAuthorizationConfig } from "../src/rule-config/loader";
import { PermissionCache } from "../src/permission-cache/cache";
import { Metrics } from "../src/observability/metrics";
import { LoggingAuditSink } from "../src/audit/audit";

const yaml = `
rules:
  - path: /orders/**
    method: GET
    authenticationType: SERVICE
    allowedServices: [billing]
`;

function deps(): DecideDeps {
  return {
    engine: loadAuthorizationConfig(yaml),
    cache: new PermissionCache(),
    metrics: new Metrics(),
    audit: new LoggingAuditSink(),
    validator: {
      validateUserToken: async () => { throw new Error("no user"); },
      validateServiceToken: async () => ({ sub: "billing", token_use: "service", serviceName: "billing" } as any),
    },
    userAuthEnabled: true,
  };
}

it("denies when no credentials are present", async () => {
  const out = await decideRequest(
    { method: "GET", rawPath: "/orders/7", headers: {} },
    deps(),
  );
  expect(out.kind).toBe("deny");
  if (out.kind === "deny") expect(out.status).toBe(401);
});

it("allows a valid service token against the allow-list", async () => {
  const out = await decideRequest(
    { method: "GET", rawPath: "/orders/7", headers: { "x-service-token": "svc" } },
    deps(),
  );
  expect(out.kind).toBe("allow");
  if (out.kind === "allow") expect(out.ctx.serviceName).toBe("billing");
});
```

- [ ] **Step 2: Run it — expect failure (module not found)**

Run: `cd libraries/authz-nestjs; npx jest decide-core -i`
Expected: FAIL — `Cannot find module '../src/decision-engine/decide'`.

- [ ] **Step 3: Implement `decideRequest()` by lifting the logic verbatim from `runAuthz()`**

```ts
// src/decision-engine/decide.ts
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
```

- [ ] **Step 4: Run the core test — expect PASS**

Run: `cd libraries/authz-nestjs; npx jest decide-core -i`
Expected: PASS (both cases).

- [ ] **Step 5: Commit**

```bash
git add libraries/authz-nestjs/src/decision-engine/decide.ts libraries/authz-nestjs/test/decide-core.spec.ts
git commit -m "feat(nestjs): extract framework-agnostic decideRequest core"
```

---

## Task 3: Route the guard and Express middleware through the core

**Files:**
- Modify: `src/nest/authz.guard.ts`
- Modify: `src/bootstrap/create-authz.ts`

- [ ] **Step 1: Rewrite `AuthzGuard.canActivate()` to delegate to `decideRequest()`**

Replace the body (keeping the `AuthzGuardDeps` interface and `@Injectable()` class) with:

```ts
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
```

Add `import { decideRequest } from "../decision-engine/decide";` and drop now-unused imports (engine/context/validator helpers that moved into the core), keeping `HttpException`, `HttpStatus`, `REQUEST_CONTEXT_KEY`, and the dep types.

- [ ] **Step 2: Rewrite `runAuthz()` in `create-authz.ts` to delegate to the core**

Replace the inline decision body (the public-check / no-creds / validation / decide block) with a call that preserves the Express response + outbound-context behavior:

```ts
const runAuthz = async (req: any, res: any, next: () => void, span?: AuthzSpan) => {
  const out = await decideRequest(
    { method: req.method, rawPath: req.path ?? req.url ?? "", headers: req.headers ?? {} },
    { engine, cache, validator, audit, metrics,
      policyEngine: opts.policyEngine, roleResolver: opts.roleResolver, userAuthEnabled },
  );
  if (span && out.kind === "allow") {
    span.setAttribute("authz.path", (req.path ?? req.url ?? "").split("?")[0]);
    span.setAttribute("authz.method", req.method);
    span.setAttribute("authz.authType", out.ctx.authenticationType);
    if (out.ctx.roleId) span.setAttribute("authz.role", out.ctx.roleId);
    if (out.ctx.serviceName) span.setAttribute("authz.service", out.ctx.serviceName);
  }
  if (out.kind === "deny") {
    res.status(out.status).json({ error: out.error });
    return;
  }
  req.authz = out.ctx;
  if (out.bearer) (req as AuthorizedRequest).authzUserJwt = out.bearer;
  runWithOutboundContext(out.ctx, out.bearer, next);
};
```

Add `import { decideRequest } from "../decision-engine/decide";`. Remove the now-dead imports/helpers used only by the old inline path (e.g. `auditPermission`, `extractBearer`, principal builders, `buildAuditEvent`) **only if** nothing else in the file uses them — verify with the compiler.

- [ ] **Step 3: Run the full suite — the guard/middleware/vector tests must all stay green**

Run: `cd libraries/authz-nestjs; npm test`
Expected: PASS, 46 vectors green, `guard-parity-gaps.spec.ts` green (proves guard == middleware behavior).

- [ ] **Step 4: Commit**

```bash
git add libraries/authz-nestjs/src/nest/authz.guard.ts libraries/authz-nestjs/src/bootstrap/create-authz.ts
git commit -m "refactor(nestjs): guard and middleware both call decideRequest"
```

---

## Task 4: Options token + feature modules

**Files:**
- Create: `src/nest/authz-options.ts`
- Create: `src/nest/modules/observability.module.ts`, `decision-engine.module.ts`, `permission-cache.module.ts`, `inbound-auth.module.ts`, `cache-sync.module.ts`, `outbound.module.ts`

- [ ] **Step 1: Create the options token and async-options type**

```ts
// src/nest/authz-options.ts
import { ModuleMetadata } from "@nestjs/common";
import { CreateAuthzOptions } from "../bootstrap/create-authz";

/** Injection token carrying the resolved CreateAuthzOptions to every feature module. */
export const AUTHZ_OPTIONS = "AUTHZ_OPTIONS";

/** Async configuration for AuthzModule.forRootAsync (idiomatic Nest dynamic module). */
export interface AuthzModuleAsyncOptions extends Pick<ModuleMetadata, "imports"> {
  useFactory: (...args: any[]) => Promise<CreateAuthzOptions> | CreateAuthzOptions;
  inject?: any[];
}
```

- [ ] **Step 2: Provider tokens — define them once in `authz-options.ts`**

Append:

```ts
export const AUTHZ_ENGINE = "AUTHZ_ENGINE";
export const AUTHZ_CACHE = "AUTHZ_CACHE";
export const AUTHZ_METRICS = "AUTHZ_METRICS";
export const AUTHZ_AUDIT = "AUTHZ_AUDIT";
export const AUTHZ_VALIDATOR = "AUTHZ_VALIDATOR";
export const AUTHZ_BOOTSTRAP = "AUTHZ_BOOTSTRAP";
export const AUTHZ_SERVICE_IDENTITY = "AUTHZ_SERVICE_IDENTITY";
export const AUTHZ_USER_AUTH_ENABLED = "AUTHZ_USER_AUTH_ENABLED";
```

- [ ] **Step 3: `PermissionCacheModule` (singleton cache)**

```ts
// src/nest/modules/permission-cache.module.ts
import { Module } from "@nestjs/common";
import { PermissionCache } from "../../permission-cache/cache";
import { AUTHZ_CACHE } from "../authz-options";

@Module({
  providers: [{ provide: AUTHZ_CACHE, useFactory: () => new PermissionCache() }],
  exports: [AUTHZ_CACHE],
})
export class PermissionCacheModule {}
```

- [ ] **Step 4: `ObservabilityModule` (metrics + audit, options-driven)**

```ts
// src/nest/modules/observability.module.ts
import { Module } from "@nestjs/common";
import { Metrics } from "../../observability/metrics";
import { LoggingAuditSink } from "../../audit/audit";
import { OtelAuditSink } from "../../observability/otel-audit-sink";
import { initObservability, createAuthzTracer } from "../../observability/otel";
import { bridgeMetricsToOtel } from "../../observability/otel-bridge";
import { AuditSink } from "../../spi";
import { CreateAuthzOptions } from "../../bootstrap/create-authz";
import { AUTHZ_OPTIONS, AUTHZ_METRICS, AUTHZ_AUDIT } from "../authz-options";

@Module({
  providers: [
    {
      provide: AUTHZ_METRICS,
      useFactory: (opts: CreateAuthzOptions) => {
        const metrics = new Metrics();
        if (opts.observability?.enabled) {
          initObservability(opts.observability);
          bridgeMetricsToOtel(metrics);
          createAuthzTracer("authz");
        }
        return metrics;
      },
      inject: [AUTHZ_OPTIONS],
    },
    {
      provide: AUTHZ_AUDIT,
      useFactory: (opts: CreateAuthzOptions): AuditSink =>
        opts.auditSink ?? (opts.observability?.enabled ? new OtelAuditSink() : new LoggingAuditSink()),
      inject: [AUTHZ_OPTIONS],
    },
  ],
  exports: [AUTHZ_METRICS, AUTHZ_AUDIT],
})
export class ObservabilityModule {}
```

- [ ] **Step 5: `DecisionEngineModule` (compiled engine)**

```ts
// src/nest/modules/decision-engine.module.ts
import * as fs from "fs";
import { Module } from "@nestjs/common";
import { loadAuthorizationConfig } from "../../rule-config/loader";
import { CreateAuthzOptions } from "../../bootstrap/create-authz";
import { AUTHZ_OPTIONS, AUTHZ_ENGINE } from "../authz-options";

@Module({
  providers: [
    {
      provide: AUTHZ_ENGINE,
      useFactory: (opts: CreateAuthzOptions) => {
        const yaml = opts.authorizationYaml
          ?? (opts.authorizationYamlPath
            ? fs.readFileSync(opts.authorizationYamlPath, "utf8")
            : (() => { throw new Error("AuthzModule requires authorizationYaml or authorizationYamlPath"); })());
        return loadAuthorizationConfig(yaml); // fail-fast on config error
      },
      inject: [AUTHZ_OPTIONS],
    },
  ],
  exports: [AUTHZ_ENGINE],
})
export class DecisionEngineModule {}
```

- [ ] **Step 6: `InboundAuthModule` (token validator + userAuthEnabled flag)**

```ts
// src/nest/modules/inbound-auth.module.ts
import { Module } from "@nestjs/common";
import { JwksTokenValidator } from "../../inbound-auth/token-validator";
import { TokenValidator } from "../../spi";
import { CreateAuthzOptions } from "../../bootstrap/create-authz";
import { AUTHZ_OPTIONS, AUTHZ_VALIDATOR, AUTHZ_USER_AUTH_ENABLED } from "../authz-options";

function userAuthEnabled(opts: CreateAuthzOptions): boolean {
  return Boolean(opts.userIssuer || opts.userJwksUri || opts.audience || opts.roleServiceUrl);
}

@Module({
  providers: [
    {
      provide: AUTHZ_USER_AUTH_ENABLED,
      useFactory: (opts: CreateAuthzOptions) => userAuthEnabled(opts),
      inject: [AUTHZ_OPTIONS],
    },
    {
      provide: AUTHZ_VALIDATOR,
      useFactory: (opts: CreateAuthzOptions): TokenValidator =>
        opts.validator ?? new JwksTokenValidator({
          userIssuer: opts.userIssuer, userJwksUri: opts.userJwksUri,
          serviceIssuer: opts.serviceIssuer, serviceJwksUri: opts.serviceJwksUri,
          serviceTokenUseClaim: opts.serviceTokenUseClaim,
          serviceTokenUseValue: opts.serviceTokenUseValue,
          audience: opts.audience, clockSkewSeconds: opts.clockSkewSeconds ?? 5,
        }),
      inject: [AUTHZ_OPTIONS],
    },
  ],
  exports: [AUTHZ_VALIDATOR, AUTHZ_USER_AUTH_ENABLED],
})
export class InboundAuthModule {}
```

- [ ] **Step 7: `CacheSyncModule` (bootstrap + Kafka + lifecycle)**

```ts
// src/nest/modules/cache-sync.module.ts
import { Module, OnApplicationBootstrap, OnModuleDestroy, Injectable, Inject } from "@nestjs/common";
import { HttpRoleServiceClient } from "../../role-service-client/client";
import { DiskCache } from "../../cache-sync/disk";
import { KafkaCacheEventHandler } from "../../cache-sync/kafka";
import { CacheBootstrap } from "../../cache-sync/bootstrap";
import { PermissionCache } from "../../permission-cache/cache";
import { Metrics, METRIC } from "../../observability/metrics";
import { CreateAuthzOptions } from "../../bootstrap/create-authz";
import {
  AUTHZ_OPTIONS, AUTHZ_CACHE, AUTHZ_METRICS, AUTHZ_BOOTSTRAP, AUTHZ_USER_AUTH_ENABLED,
} from "../authz-options";

/** Runs the startup state machine after the DI graph is built, and stops it on shutdown. */
@Injectable()
export class CacheSyncLifecycle implements OnApplicationBootstrap, OnModuleDestroy {
  constructor(
    @Inject(AUTHZ_BOOTSTRAP) private readonly boot: CacheBootstrap | null,
    @Inject(AUTHZ_OPTIONS) private readonly opts: CreateAuthzOptions,
  ) {}
  async onApplicationBootstrap(): Promise<void> {
    if (!this.boot) return;
    await this.boot.start();
    this.boot.startSeedRetry();
    this.boot.startReconciler(this.opts.reconcileIntervalMs ?? 300000);
  }
  async onModuleDestroy(): Promise<void> {
    this.boot?.stop();
  }
}

@Module({
  providers: [
    {
      provide: AUTHZ_BOOTSTRAP,
      useFactory: (opts: CreateAuthzOptions, cache: PermissionCache, metrics: Metrics): CacheBootstrap | null => {
        const userAuthEnabled = Boolean(opts.userIssuer || opts.userJwksUri || opts.audience || opts.roleServiceUrl);
        if (!userAuthEnabled) return null; // SERVICE-ONLY mode
        const events = opts.kafkaBrokers?.length
          ? new KafkaCacheEventHandler({
              brokers: opts.kafkaBrokers, updatesTopic: opts.roleUpdatesTopic,
              deleteTopic: opts.roleDeleteTopic, publishTopic: opts.publishRolesTopic,
              groupId: opts.kafkaGroupId, clientId: opts.kafkaClientId,
              logger: { warn: (m) => console.warn(m) },
              onSkippedEvent: () => metrics.inc(METRIC.roleEventSkipped),
            })
          : undefined;
        return new CacheBootstrap(
          cache,
          new HttpRoleServiceClient({
            baseUrl: opts.roleServiceUrl!,
            connectTimeoutMs: opts.roleServiceConnectTimeout ?? 5000,
            readTimeoutMs: opts.roleServiceReadTimeout ?? 5000,
          }),
          new DiskCache(opts.diskCachePath ?? "authorization-cache.json"),
          events,
          { metrics, logger: { warn: (m) => console.warn(m) } },
        );
      },
      inject: [AUTHZ_OPTIONS, AUTHZ_CACHE, AUTHZ_METRICS],
    },
    CacheSyncLifecycle,
  ],
  exports: [AUTHZ_BOOTSTRAP],
})
export class CacheSyncModule {}
```

> Note: `START` ordering — `decideRequest` reads the cache the bootstrap populates; `onApplicationBootstrap` runs before Nest starts listening, matching the Express path which awaits `boot.start()` before `app.listen`. The Kafka handler `onSkippedEvent`/seed/reconciler semantics are copied verbatim from `create-authz.ts`.

- [ ] **Step 8: `OutboundModule` (service identity + interceptor + lifecycle)**

```ts
// src/nest/modules/outbound.module.ts
import { Module, Injectable, Inject, OnModuleDestroy } from "@nestjs/common";
import { ClientCredentialsProvider } from "../../service-token/provider";
import { Metrics, METRIC } from "../../observability/metrics";
import { ServiceIdentityProvider } from "../../spi";
import { AuthzOutboundInterceptor } from "../outbound.interceptor";
import { CreateAuthzOptions } from "../../bootstrap/create-authz";
import { AUTHZ_OPTIONS, AUTHZ_METRICS, AUTHZ_SERVICE_IDENTITY } from "../authz-options";

@Injectable()
export class OutboundLifecycle implements OnModuleDestroy {
  constructor(@Inject(AUTHZ_SERVICE_IDENTITY) private readonly id: ServiceIdentityProvider | null) {}
  async onModuleDestroy(): Promise<void> {
    const closable = this.id as { close?: () => void } | null;
    if (closable && typeof closable.close === "function") closable.close();
  }
}

@Module({
  providers: [
    {
      provide: AUTHZ_SERVICE_IDENTITY,
      useFactory: async (opts: CreateAuthzOptions, metrics: Metrics): Promise<ServiceIdentityProvider | null> => {
        if (!opts.serviceToken) return null;
        const provider = new ClientCredentialsProvider({
          tokenUrl: opts.serviceToken.tokenUrl, clientId: opts.serviceToken.clientId,
          clientSecret: opts.serviceToken.clientSecret,
          onError: () => metrics.inc(METRIC.serviceTokenFailures), metrics,
        });
        await provider.checkTokenEndpoint();
        return provider;
      },
      inject: [AUTHZ_OPTIONS, AUTHZ_METRICS],
    },
    OutboundLifecycle,
    AuthzOutboundInterceptor,
  ],
  exports: [AUTHZ_SERVICE_IDENTITY, AuthzOutboundInterceptor],
})
export class OutboundModule {}
```

- [ ] **Step 9: Compile-check the modules**

Run: `cd libraries/authz-nestjs; npx tsc -p tsconfig.build.json --noEmit`
Expected: no type errors. Fix any signature drift against the real constructors (e.g. `ClientCredentialsProvider`, `KafkaCacheEventHandler`) before proceeding.

- [ ] **Step 10: Commit**

```bash
git add libraries/authz-nestjs/src/nest/authz-options.ts libraries/authz-nestjs/src/nest/modules
git commit -m "feat(nestjs): add AUTHZ_OPTIONS token and feature modules"
```

---

## Task 5: Root `AuthzModule.forRoot()/forRootAsync()`

**Files:**
- Modify: `src/nest/authz.module.ts`
- Test: `test/authz-module.spec.ts` (extend), `test/modules.spec.ts`

- [ ] **Step 1: Write a failing test for `forRootAsync`**

```ts
// add to test/authz-module.spec.ts
it("forRootAsync resolves options via useFactory and enforces globally", async () => {
  const { Test } = require("@nestjs/testing");
  const { AuthzModule } = require("../src/nest/authz.module");
  const yaml = "rules:\n  - path: /ping\n    method: GET\n    authenticationType: SERVICE\n    allowedServices: [x]\n";
  const moduleRef = await Test.createTestingModule({
    imports: [AuthzModule.forRootAsync({
      useFactory: () => ({
        serviceIssuer: "http://sso", serviceJwksUri: "http://sso/jwks",
        authorizationYaml: yaml,
      }),
    })],
  }).compile();
  expect(moduleRef.get("AUTHZ_ENGINE")).toBeDefined();
  await moduleRef.close();
});
```

- [ ] **Step 2: Run it — expect failure (`forRootAsync` not a function)**

Run: `cd libraries/authz-nestjs; npx jest authz-module -i`
Expected: FAIL.

- [ ] **Step 3: Rewrite `authz.module.ts` to compose the feature modules**

```ts
import { DynamicModule, Global, Module, Provider } from "@nestjs/common";
import { APP_GUARD, APP_INTERCEPTOR } from "@nestjs/core";
import { CreateAuthzOptions } from "../bootstrap/create-authz";
import { AuthzGuard, AuthzGuardDeps } from "./authz.guard";
import { AuthzOutboundInterceptor } from "./outbound.interceptor";
import {
  AUTHZ_OPTIONS, AUTHZ_ENGINE, AUTHZ_CACHE, AUTHZ_METRICS, AUTHZ_AUDIT,
  AUTHZ_VALIDATOR, AUTHZ_USER_AUTH_ENABLED, AuthzModuleAsyncOptions,
} from "./authz-options";
import { ObservabilityModule } from "./modules/observability.module";
import { DecisionEngineModule } from "./modules/decision-engine.module";
import { PermissionCacheModule } from "./modules/permission-cache.module";
import { InboundAuthModule } from "./modules/inbound-auth.module";
import { CacheSyncModule } from "./modules/cache-sync.module";
import { OutboundModule } from "./modules/outbound.module";

const FEATURE_MODULES = [
  ObservabilityModule, PermissionCacheModule, DecisionEngineModule,
  InboundAuthModule, CacheSyncModule, OutboundModule,
];

/** Provider building the global guard from the feature-module providers. */
const guardProvider: Provider = {
  provide: AuthzGuard,
  useFactory: (engine, cache, metrics, validator, audit, userAuthEnabled, opts: CreateAuthzOptions): AuthzGuard => {
    const deps: AuthzGuardDeps = {
      engine, cache, metrics, validator, audit,
      policyEngine: opts.policyEngine, roleResolver: opts.roleResolver, userAuthEnabled,
    };
    return new AuthzGuard(deps);
  },
  inject: [AUTHZ_ENGINE, AUTHZ_CACHE, AUTHZ_METRICS, AUTHZ_VALIDATOR, AUTHZ_AUDIT, AUTHZ_USER_AUTH_ENABLED, AUTHZ_OPTIONS],
};

@Global()
@Module({})
export class AuthzModule {
  static forRoot(options: CreateAuthzOptions): DynamicModule {
    return AuthzModule.build({ provide: AUTHZ_OPTIONS, useValue: options }, []);
  }

  static forRootAsync(async: AuthzModuleAsyncOptions): DynamicModule {
    return AuthzModule.build(
      { provide: AUTHZ_OPTIONS, useFactory: async.useFactory, inject: async.inject ?? [] },
      async.imports ?? [],
    );
  }

  private static build(optionsProvider: Provider, extraImports: any[]): DynamicModule {
    return {
      module: AuthzModule,
      imports: [...extraImports, ...FEATURE_MODULES],
      providers: [
        optionsProvider,
        guardProvider,
        { provide: APP_GUARD, useExisting: AuthzGuard },
        { provide: APP_INTERCEPTOR, useClass: AuthzOutboundInterceptor },
      ],
      exports: [
        AUTHZ_OPTIONS, AUTHZ_ENGINE, AUTHZ_CACHE, AUTHZ_METRICS, AUTHZ_AUDIT,
        AUTHZ_VALIDATOR, AuthzGuard,
      ],
    };
  }
}
```

> The `AUTHZ_OPTIONS` provider must be visible to the feature modules. Since they are imported by `AuthzModule` and `@Global()`, export `AUTHZ_OPTIONS` and ensure each feature module that injects it lists it — simplest: make a tiny `AuthzOptionsModule` that provides+exports `AUTHZ_OPTIONS` and have every feature module `imports: [AuthzOptionsModule]`. Implement that module in `authz-options.ts` consumers if Nest cannot resolve `AUTHZ_OPTIONS` across modules during Step 4.

- [ ] **Step 4: Run the module test — expect PASS**

Run: `cd libraries/authz-nestjs; npx jest authz-module modules -i`
Expected: PASS. If Nest reports `AUTHZ_OPTIONS` unresolved in a feature module, add the `AuthzOptionsModule` shim noted above and re-run.

- [ ] **Step 5: Run the full suite**

Run: `cd libraries/authz-nestjs; npm test`
Expected: PASS, 46 vectors green.

- [ ] **Step 6: Commit**

```bash
git add libraries/authz-nestjs/src/nest libraries/authz-nestjs/test
git commit -m "feat(nestjs): AuthzModule.forRoot/forRootAsync compose feature modules"
```

---

## Task 6: Update the barrel and keep the Express wrapper

**Files:**
- Modify: `src/index.ts`

- [ ] **Step 1: Add the new public exports (keep every existing one)**

Append to the NestJS section of `src/index.ts`:

```ts
// NestJS feature modules + options token (idiomatic adoption)
export {
  AUTHZ_OPTIONS, AUTHZ_ENGINE, AUTHZ_CACHE, AUTHZ_METRICS, AUTHZ_AUDIT,
  AUTHZ_VALIDATOR, AUTHZ_BOOTSTRAP, AUTHZ_SERVICE_IDENTITY, AUTHZ_USER_AUTH_ENABLED,
  AuthzModuleAsyncOptions,
} from "./nest/authz-options";
export { decideRequest, DecideDeps, DecideInput, DecideOutcome } from "./decision-engine/decide";
```

Leave `createAuthz`, `AuthzModule`, `AUTHZ`, `AuthzGuard`, etc. exactly as they are — backward compatible.

- [ ] **Step 2: Build + full suite**

Run: `cd libraries/authz-nestjs; npm run build; npm test`
Expected: build emits `dist/` with no errors; all tests pass.

- [ ] **Step 3: Commit**

```bash
git add libraries/authz-nestjs/src/index.ts
git commit -m "feat(nestjs): export feature modules and decideRequest from barrel"
```

---

## Task 7: Convert nestjs-demo into a real NestJS app

**Files:**
- Create: `tests/demo-services/nestjs-demo/package.json`
- Create: `tests/demo-services/nestjs-demo/src/app.module.ts`, `health.controller.ts`, `orders.controller.ts`, `main.ts`
- Modify: `tests/demo-services/nestjs-demo/authorization.yaml` (add public `GET /health`)
- Delete: `tests/demo-services/nestjs-demo/src/main.js`

- [ ] **Step 1: Add a public rule for `/health` so the global guard allows it**

Add to `authorization.yaml`:

```yaml
  - path: /health
    method: GET
    public: true
```

(Preserves today's behavior where `/health` was registered before the Express middleware and required no credentials.)

- [ ] **Step 2: Add the demo's Nest runtime dependencies**

```json
{
  "name": "nestjs-demo",
  "private": true,
  "scripts": { "start": "node -r ts-node/register src/main.ts" },
  "dependencies": {
    "@nestjs/common": "^11.0.0",
    "@nestjs/core": "^11.0.0",
    "@nestjs/platform-express": "^11.0.0",
    "authz-nestjs": "file:../../../libraries/authz-nestjs",
    "axios": "^1.7.2",
    "reflect-metadata": "^0.2.2",
    "rxjs": "^7.8.1"
  },
  "devDependencies": { "ts-node": "^10.9.2", "typescript": "^5.5.4" }
}
```

- [ ] **Step 3: `app.module.ts` — import `AuthzModule.forRoot` with the demo env mapping**

```ts
import { Module } from "@nestjs/common";
import { AuthzModule } from "authz-nestjs";
import * as path from "path";
import { HealthController } from "./health.controller";
import { OrdersController } from "./orders.controller";

const MOCK = process.env.MOCK_URL || "http://localhost:4000";

@Module({
  imports: [
    AuthzModule.forRoot({
      serviceIssuer: `${MOCK}/sso`, serviceJwksUri: `${MOCK}/sso/jwks`,
      userIssuer: `${MOCK}/auth`, userJwksUri: `${MOCK}/auth/jwks`,
      audience: process.env.API_AUDIENCE || "orders-api",
      roleServiceUrl: MOCK,
      authorizationYamlPath: path.join(__dirname, "..", "authorization.yaml"),
      diskCachePath: process.env.AUTHZ_DISK_CACHE_PATH || "/tmp/authorization-cache.json",
      kafkaBrokers: (process.env.KAFKA_BROKERS || "").split(",").map((s) => s.trim()).filter(Boolean),
      serviceToken: {
        tokenUrl: `${MOCK}/sso/token`,
        clientId: process.env.CLIENT_ID || "nestjs-demo-id",
        clientSecret: process.env.CLIENT_SECRET || "nestjs-demo-secret",
      },
    }),
  ],
  controllers: [HealthController, OrdersController],
})
export class AppModule {}
```

- [ ] **Step 4: `health.controller.ts` — expose health from the injected runtime**

```ts
import { Controller, Get, Inject } from "@nestjs/common";
import { AUTHZ_CACHE, AUTHZ_BOOTSTRAP } from "authz-nestjs";
import { buildHealth } from "authz-nestjs";

@Controller("health")
export class HealthController {
  constructor(
    @Inject(AUTHZ_CACHE) private readonly cache: any,
    @Inject(AUTHZ_BOOTSTRAP) private readonly boot: any,
  ) {}
  @Get()
  health() {
    const h = this.boot
      ? buildHealth(this.cache, this.boot.mode_(), {
          roleServiceLastSync: this.boot.roleServiceLastSync(),
          kafkaConsumerConnected: this.boot.isKafkaConnected(),
        })
      : buildHealth(this.cache, "normal", { roleServiceLastSync: null, kafkaConsumerConnected: false });
    return { ok: true, ...h };
  }
}
```

- [ ] **Step 5: `orders.controller.ts` — same routes/bodies as the old Express demo, outbound via the lib client**

```ts
import { Body, Controller, Get, Param, Post, Req } from "@nestjs/common";
import { AuthzContext } from "authz-nestjs";
import type { RequestContext } from "authz-nestjs";
import axios from "axios";
import { attachOutboundPropagation } from "authz-nestjs";

const DOWNSTREAM = process.env.DOWNSTREAM_URL || "http://localhost:5002";
const downstream = axios.create({ timeout: 5000 });
attachOutboundPropagation(downstream, {}); // service identity attached via the global interceptor's ALS context

@Controller("orders")
export class OrdersController {
  @Get(":id")
  get(@Param("id") id: string, @AuthzContext() ctx: RequestContext) {
    return { id, by: ctx.userId };
  }
  @Get(":id/audit")
  audit(@Param("id") id: string) { return { id, audit: true }; }
  @Post()
  create() { return { created: true }; }
  @Post(":id")
  update(@Param("id") id: string, @AuthzContext() ctx: RequestContext) {
    return { id, updated: true, seenServiceName: ctx?.serviceName || "none",
      seenAuthType: ctx?.authenticationType || "none",
      seenCorrelationId: ctx?.correlationId || "none", seenUserId: ctx?.userId || "none" };
  }
  @Post(":id/forward")
  async forward(@Param("id") id: string, @Body() body: any) {
    try {
      const r = await downstream.post(`${DOWNSTREAM}/orders/${id}`, body ?? {});
      return { forwarded: true, downstreamStatus: r.status, downstream: r.data,
        sentHeaders: {
          hasServiceToken: !!(r.config?.headers?.["X-Service-Token"] || r.config?.headers?.["x-service-token"]),
          hasAuthorization: !!(r.config?.headers?.["Authorization"] || r.config?.headers?.["authorization"]),
          correlationId: r.config?.headers?.["X-Correlation-Id"] || r.config?.headers?.["x-correlation-id"],
          requestId: r.config?.headers?.["X-Request-Id"] || r.config?.headers?.["x-request-id"],
        } };
    } catch (e: any) {
      if (e.response) return { forwarded: false, downstreamStatus: e.response.status, downstream: e.response.data };
      throw e;
    }
  }
}
```

> The old demo also had `POST /internal/reconcile`. Add it as a second controller method or a small `InternalController` mirroring `{ reconciled: true, by: ctx.serviceName }`. Keep the route and body identical so `run.mjs` is unaffected.

- [ ] **Step 6: `main.ts` — bootstrap Nest on the same port, keep OTel init first**

```ts
import "reflect-metadata";
import { initObservability } from "authz-nestjs";
const OTEL_ENV = (process.env.ENV_NAME || process.env.ENVIRONMENT || "drill").toLowerCase();
initObservability({
  enabled: true,
  serviceName: process.env.SERVICE_NAME || "nestjs-demo",
  systemName: process.env.SYSTEM_NAME || process.env.SYSTEM || "auth-library",
  envName: OTEL_ENV as any,
  otelExporterOtlpEndpoint: process.env.OTEL_EXPORTER_OTLP_ENDPOINT,
});

import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const port = process.env.PORT || 5001;
  await app.listen(port);
  console.log(`nestjs-demo (NestJS) listening on :${port}`);
}
bootstrap().catch((e) => { console.error(e); process.exit(1); });
```

- [ ] **Step 7: Delete `src/main.js`**

- [ ] **Step 8: Verify the demo starts and serves locally (mock up)**

Run mock + demo per CLAUDE.md, then `curl http://localhost:5001/health`.
Expected: `{ "ok": true, ... }` with no credentials (public rule), and an authorized `GET /orders/1` behaves exactly as before.

- [ ] **Step 9: Update the e2e Dockerfile/compose entrypoint if it referenced `main.js`**

Check `tests/e2e/docker-compose*.yml` and any nestjs-demo Dockerfile for `src/main.js`/`npm start`; point them at `src/main.ts` (ts-node) or a build step. Adjust verbatim.

- [ ] **Step 10: Commit**

```bash
git add tests/demo-services/nestjs-demo
git commit -m "refactor(demo): convert nestjs-demo to a real NestJS app using AuthzModule"
```

---

## Task 8: Full cross-language e2e parity gate

**Files:** none (verification)

- [ ] **Step 1: Run the full e2e**

Run (from `tests/e2e`): `docker compose up --build -d; node run.mjs; docker compose down -v`
Expected: every matrix scenario passes for both languages with identical outcomes — decision matrix, live Kafka propagation, outbound propagation, audience rejection. This is the ultimate proof the NestJS redesign changed no decision.

- [ ] **Step 2: If any scenario differs, debug with systematic-debugging before adjusting** — a divergence here means the guard/middleware/demo wiring drifted from the core; fix the wiring, not the vectors.

- [ ] **Step 3: Commit any e2e harness adjustments** (entrypoint/path only).

---

## Task 9: Docs

**Files:**
- Modify: `CLAUDE.md` (project-structure + a note that structure is now intentionally framework-idiomatic, parity spine still the invariant)
- Modify: `docs/standards/nestjs-standards.md` if it documents the old `createAuthz`-only adoption.

- [ ] **Step 1: Update the NestJS adoption snippet to `AuthzModule.forRoot/forRootAsync`** and note `createAuthz()` remains for Express hosts.

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md docs/standards/nestjs-standards.md
git commit -m "docs: describe NestJS module-based adoption and idiomatic structure"
```

---

## Self-Review

- **Spec coverage:** shared `decideRequest` core (✓ Task 2) consumed by both guard + middleware (✓ Task 3); feature modules with real providers (✓ Task 4); `forRoot`/`forRootAsync` (✓ Task 5, justified: async is the idiomatic Nest shape, sync kept for tests/static); lifecycle hooks for bootstrap + token timer (✓ Tasks 4.7/4.8); guard as sole Nest decision path via APP_GUARD (✓ Task 5); `createAuthz()` Express wrapper retained (✓ Task 3/6); optional-NestJS core preserved — no decorators on core classes, only `src/nest/` imports `@nestjs/common` (✓ design note + Task 4); demo converted to real Nest app with identical HTTP surface/port (✓ Task 7); vectors + e2e gate (✓ Tasks 5,6,8).
- **Placeholder scan:** none — every new file has complete code; the two soft spots (the `AuthzOptionsModule` shim for cross-module `AUTHZ_OPTIONS`, and the e2e entrypoint path) are explicit conditional steps with concrete actions, not TBDs.
- **Type consistency:** token strings (`AUTHZ_OPTIONS`, `AUTHZ_ENGINE`, …) defined once in `authz-options.ts` and reused; `decideRequest`/`DecideDeps`/`DecideOutcome` signatures match across the core, guard, and middleware; `AuthzGuardDeps` unchanged so the guard's constructor contract is stable.
