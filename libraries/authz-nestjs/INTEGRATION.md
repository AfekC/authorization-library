# authz-nestjs — Integration cookbook

Copy-pasteable wiring for every important way to adopt the library in a service.
Every example is taken from the working demo (`tests/demo-services/nestjs-demo/`), so
it matches the real API. See the [README](README.md) for the config reference and the
full env-var / option tables.

**Mental model:** service auth is always on. Two things vary — whether **user JWTs** are
checked, and where **role→permission** data comes from. That gives three operating modes
([full](#1-nestjs-app--full-mode), [service-only](#4-service-only-mode),
[external source](#5-external-permission-source)). Enforcement is **global** — every route
is authorized by a single `APP_GUARD`; business controllers carry no auth code.

## Contents

1. [NestJS app — full mode](#1-nestjs-app--full-mode)
2. [NestJS app — async config](#2-nestjs-app--async-config)
3. [Express host (non-Nest)](#3-express-host-non-nest)
4. [Service-only mode](#4-service-only-mode)
5. [External permission source](#5-external-permission-source)
6. [authorization.yaml rule shapes](#6-authorizationyaml-rule-shapes)
7. [Reading the validated context](#7-reading-the-validated-context)
8. [Kafka role events](#8-kafka-role-events)
9. [Outbound propagation](#9-outbound-propagation)
10. [Health endpoint](#10-health-endpoint)
11. [Custom auditSink & SPI overrides](#11-custom-auditsink--spi-overrides)

---

## 1. NestJS app — full mode

The idiomatic adoption: one module import. `AuthzModule.forRoot(...)` compiles
`authorization.yaml` (fail-fast), runs the startup state machine (Role Service snapshot →
disk seed → reconciler), and registers the global guard + outbound interceptor. Business
controllers carry **no** authorization code.

```ts
// app.module.ts
import { Module } from "@nestjs/common";
import { AuthzModule } from "authz-nestjs";
import * as path from "path";
import { OrdersController } from "./orders.controller.js";

@Module({
  imports: [
    AuthzModule.forRoot({
      // Service trust roots (always required)
      serviceIssuer: "https://sso.example.com",
      serviceJwksUri: "https://sso.example.com/.well-known/jwks.json",
      // User trust roots (all-or-nothing)
      userIssuer: "https://auth.example.com",
      userJwksUri: "https://auth.example.com/.well-known/jwks.json",
      audience: "orders-api",
      // Permission distribution
      roleServiceUrl: "http://role-service:8080",
      authorizationYamlPath: path.join(__dirname, "..", "authorization.yaml"),
      diskCachePath: "/tmp/authorization-cache.json",
      // Outbound identity (optional — see §9)
      serviceToken: {
        tokenUrl: "https://sso.example.com/token",
        clientId: process.env.CLIENT_ID!,
        clientSecret: process.env.CLIENT_SECRET!,
      },
    }),
  ],
  controllers: [OrdersController],
})
export class AppModule {}
```

`AuthzModule` is `@Global()`, exports the `AUTHZ` runtime token plus the feature-module
providers (cache, bootstrap, metrics, validator, service identity), and stops background
loops on `onModuleDestroy`.

## 2. NestJS app — async config

When configuration comes from `ConfigService`, a secret store, or any async source, use
`forRootAsync`. The factory returns the same options object as `forRoot`.

```ts
import { ConfigModule, ConfigService } from "@nestjs/config";
import { AuthzModule } from "authz-nestjs";

@Module({
  imports: [
    ConfigModule.forRoot(),
    AuthzModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (cfg: ConfigService) => ({
        serviceIssuer: cfg.getOrThrow("SERVICE_ISSUER"),
        serviceJwksUri: cfg.getOrThrow("SERVICE_JWKS_URI"),
        userIssuer: cfg.getOrThrow("USER_ISSUER"),
        userJwksUri: cfg.getOrThrow("USER_JWKS_URI"),
        audience: cfg.getOrThrow("API_AUDIENCE"),
        roleServiceUrl: cfg.getOrThrow("ROLE_SERVICE_URL"),
        authorizationYamlPath: "./authorization.yaml",
      }),
    }),
  ],
})
export class AppModule {}
```

## 3. Express host (non-Nest)

For a plain Express app (no Nest DI), use the env-only `createAuthz()` and mount the
middleware globally. It reads `AUTHZ_*` from `process.env` — see the README
[Configuration](README.md#configuration) table for the variable names.

```ts
import express from "express";
import { createAuthz } from "authz-nestjs";

const app = express();
const authz = await createAuthz(); // reads AUTHZ_* from process.env

app.use(authz.middleware); // global enforcement, no per-route opt-in
// ... your routes; req.authz holds the validated RequestContext on ALLOW ...
```

> `createAuthz()` takes **no arguments** — it is env-only. To pass an options object
> (auditSink, externalPermissionSource, a custom validator…) use `AuthzModule.forRoot(...)`
> (§1) or, outside Nest, `createAuthzFromOptions(opts)`.

## 4. Service-only mode

The user check is fully disabled: `Authorization` bearer tokens are never read, only
`X-Service-Token` is accepted, and only rules with `allowedServices` can ever match. No Role
Service, cache, reconciler, Kafka, or disk cache is started. Select it by **omitting** all
user-auth fields, or **explicitly** with `serviceOnly: true`:

```ts
AuthzModule.forRoot({
  serviceIssuer: "https://sso.example.com",
  serviceJwksUri: "https://sso.example.com/.well-known/jwks.json",
  serviceOnly: true, // explicit — a stray user-auth field now fails fast at startup
  authorizationYamlPath: "./authorization.yaml",
});
```

`serviceOnly: true` cannot be combined with any user-auth field (`userIssuer`,
`userJwksUri`, `audience`, `roleServiceUrl`) or `externalPermissionSource` — doing so is a
startup error rather than a silent mode flip.

## 5. External permission source

Keep the user check **on** but source role→permission data from your own store
(Redis/Infinispan/Postgres) instead of the built-in Role Service + Kafka + disk pipeline.
Set `externalPermissionSource: true` and provide a `roleResolver` (or `policyEngine`):

```ts
AuthzModule.forRoot({
  serviceIssuer: "https://sso.example.com",
  serviceJwksUri: "https://sso.example.com/.well-known/jwks.json",
  userIssuer: "https://auth.example.com",
  userJwksUri: "https://auth.example.com/.well-known/jwks.json",
  audience: "orders-api", // user check stays on; no roleServiceUrl needed
  externalPermissionSource: true,
  roleResolver: {
    // Serve from an in-memory snapshot YOU refresh — the request path must not
    // make a remote call.
    permissionsForRole: (role) => mySnapshot.get(role) ?? new Set(),
  },
});
```

The Role Service fetch, reconciler, seed-retry, disk cache, and Kafka role events are all
disabled; `roleServiceUrl` is not required and `externalPermissionSource` requires a
resolver/engine (omitting both is a startup error).

## 6. authorization.yaml rule shapes

Authorization lives entirely in `authorization.yaml`; business code has no annotations.
Every rule shape (shared 1:1 with the Spring library):

```yaml
rules:
  # Public — no credentials. public:true is mutually exclusive with
  # permissions / decision / allowedServices.
  - path: /health
    methods: [GET]
    public: true

  # USER — role's permissions vs the rule's permissions.
  # decision: ANY (default) = at least one; ALL = every one.
  - path: /orders/**          # ** = any depth, final segment only
    methods: [GET]
    permissions: [READ_ORDER]
    decision: ANY

  - path: /orders/*/audit     # * = exactly one segment
    methods: [GET]
    permissions: [READ_ORDER, ADMIN]
    decision: ALL

  # SERVICE — caller's serviceName must be in allowedServices.
  - path: /internal/reconcile
    methods: [POST]
    allowedServices: [scheduler, batch]

  # USER_AND_SERVICE — both dimensions required (rule has both permissions
  # and allowedServices). "*" = any validly-authenticated service.
  - path: /orders/**
    methods: [POST]
    permissions: [WRITE_ORDER]
    allowedServices: ["*"]
```

Matching is most-specific-wins (literal `2` > `*` `1` > `**` `0`, left to right). No matching
rule → **DENY**. Unknown role → empty permissions → **DENY**. Ambiguous rules are rejected at
startup. See the README and `docs/contracts/config-files.md` for full wildcard scoring.

## 7. Reading the validated context

The global guard builds a `RequestContext` from validated token claims (inbound `X-User-*` /
`X-Role` identity headers are stripped). Read it in a controller with `@AuthzContext()`:

```ts
import { Controller, Get, Param } from "@nestjs/common";
import { AuthzContext } from "authz-nestjs";
import type { RequestContext } from "authz-nestjs";

@Controller("orders")
export class OrdersController {
  @Get(":id")
  get(@Param("id") id: string, @AuthzContext() ctx: RequestContext) {
    return { id, by: ctx.userId, role: ctx.roleId, service: ctx.serviceName };
  }
}
```

## 8. Kafka role events

Incremental role updates arrive over Kafka. The **library owns the consumer** (handler +
per-instance consumer group for broadcast fan-out); the **host owns the connection config**.
Wire it in `main.ts` — this is the one piece `AuthzModule` can't do for you, because it needs
the Nest app instance:

```ts
// main.ts
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module.js";
import { authzKafkaOptions } from "authz-nestjs";

const app = await NestFactory.create(AppModule);

const brokers = (process.env.KAFKA_BROKERS || "").split(",").map((s) => s.trim()).filter(Boolean);
if (brokers.length > 0) {
  app.connectMicroservice(
    authzKafkaOptions({
      brokers,
      schemaRegistryUrl: process.env.SCHEMA_REGISTRY_URL || "http://localhost:8081",
    }),
  );
  await app.startAllMicroservices();
}
await app.listen(3000);
```

There is no `AUTHZ_KAFKA_*` env knob — Kafka is host-wired. The consumer group is generated
per instance so every replica receives every event.

## 9. Outbound propagation

Downstream calls made while handling an authorized request can auto-attach the inbound user
JWT, this service's service token, and the `X-Correlation-Id` / `X-Request-Id` trace headers
(the inbound context flows via `AsyncLocalStorage`). Credential headers are **default-deny**:
they attach only to hosts in the allowlist.

```ts
import { Controller, Inject, Post, Param, Body } from "@nestjs/common";
import { AUTHZ_SERVICE_IDENTITY, attachOutboundPropagation } from "authz-nestjs";
import axios, { AxiosInstance } from "axios";

@Controller("orders")
export class OrdersController {
  private readonly downstream: AxiosInstance;

  constructor(@Inject(AUTHZ_SERVICE_IDENTITY) serviceIdentity: any) {
    this.downstream = axios.create({ timeout: 5000 });
    attachOutboundPropagation(this.downstream, {
      serviceIdentity: serviceIdentity ?? undefined,
      // T19: only attach the user JWT + service token to explicitly trusted hosts.
      allowedHosts: (process.env.AUTHZ_OUTBOUND_ALLOWED_HOSTS || "")
        .split(",").map((s) => s.trim()).filter(Boolean),
    });
  }

  @Post(":id/forward")
  async forward(@Param("id") id: string, @Body() body: any) {
    const r = await this.downstream.post(`https://api.internal/orders/${id}`, body ?? {});
    return { forwarded: true, downstreamStatus: r.status };
  }
}
```

Trace headers are always propagated (they are not credentials). The `Authz` runtime returned
by `createAuthz()` also exposes `attachOutbound(axios)` and `createClient(config)` for the
Express path.

## 10. Health endpoint

Expose cache status/age/mode by injecting the cache + bootstrap providers and calling
`buildHealth`. `/health` is a `public: true` rule (§6), so the guard lets it through with no
credentials:

```ts
import { Controller, Get, Inject } from "@nestjs/common";
import { AUTHZ_CACHE, AUTHZ_BOOTSTRAP, buildHealth } from "authz-nestjs";

@Controller("health")
export class HealthController {
  constructor(
    @Inject(AUTHZ_CACHE) private readonly cache: any,
    @Inject(AUTHZ_BOOTSTRAP) private readonly boot: any,
  ) {}

  @Get()
  health() {
    return this.boot
      ? buildHealth(this.cache, this.boot.mode_(), {
          roleServiceLastSync: this.boot.roleServiceLastSync(),
          kafkaConsumerConnected: false,
        })
      : buildHealth(this.cache, "normal", { roleServiceLastSync: null, kafkaConsumerConnected: false });
  }
}
```

In service-only / external-source mode the bootstrap is absent (the second branch) — cache
fields are not meaningful without the built-in distribution.

## 11. Custom auditSink & SPI overrides

The library owns **no** observability SDK config. Route per-decision audit events into your
telemetry stack with a custom `auditSink`, and swap any SPI seam via the same options object:

```ts
AuthzModule.forRoot({
  serviceIssuer, serviceJwksUri, userIssuer, userJwksUri, audience, roleServiceUrl,
  authorizationYamlPath: "./authorization.yaml",
  auditSink: myOtelAuditSink,    // per-decision events → your logging/telemetry
  validator: myTokenValidator,   // swap JWT validation
  policyEngine: myPolicyEngine,  // replace the whole decision engine
  attributeProvider: myAbac,     // supply ABAC attributes
});
```

SPI seams: `TokenValidator`, `ServiceIdentityProvider`, `RoleResolver`, `PolicyEngine`,
`AttributeProvider`, `AuditSink` — all in `authz-nestjs` exports. The in-process `Metrics`
registry exposes stable counter/gauge names for your service to scrape or mirror.
