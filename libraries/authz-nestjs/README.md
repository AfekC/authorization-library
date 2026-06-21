# authz-nestjs

Config-driven authorization middleware library for Express and NestJS.

## Install

```bash
npm install authz-nestjs
```

From workspace root during development:

```bash
npm install
```

## Quick start (Express)

```ts
import { createAuthz } from "authz-nestjs";

// Reads AUTHZ_* from process.env
const authz = await createAuthz();

app.use(authz.middleware); // global enforcement, no per-route opt-in
```

## Quick start (NestJS)

```ts
// main.ts
const authz = await createAuthz();
app.use(authz.middleware);
```

## Getting Started

1. **Install** the package — see [Install](#install).

2. **Write `authorization.yaml`** — your path → permission / allowed-service
   rules. Authorization lives entirely here; business routes contain no auth code.

3. **Set required `AUTHZ_*` variables** (see [Configuration](#configuration) for
   the full list), then call `createAuthz()`:

   ```ts
   import { createAuthz } from "authz-nestjs";

   const authz = await createAuthz(); // env-only bootstrap
   ```

4. **Enforce globally** — mount the middleware so every route is authorized with
   no per-route opt-in:

   ```ts
   app.use(authz.middleware);
   ```

5. **Tune optional settings** *(only if defaults don't fit)* — see the
   [Configuration](#configuration) table for defaults and descriptions.

6. **Enable outbound identity** *(optional)* — see
   [Configuration](#configuration) for the required env vars.

## Operating modes

Service auth is always on. What varies is **whether user JWTs are checked** and
**where role→permission data comes from**:

| Mode | How to select | User JWTs | Role→permission source | Built-in distribution (Role Service + Kafka + disk) |
|---|---|---|---|---|
| **Full** (default) | set the user-auth fields + `roleServiceUrl` | validated | library's Role Service + Kafka + disk pipeline | **on** |
| **Service-only** (user check disabled) | omit all user-auth fields, or set `serviceOnly: true` to make it explicit | **ignored** — `Authorization` bearer tokens are never read | n/a (no roles) | **off** |
| **External source** | set user-auth fields + `externalPermissionSource: true` + a `roleResolver`/`policyEngine` | validated | **your** resolver, backed by your store (Redis/Infinispan/Postgres) | **off** |

- **Service-only mode** = the user check is fully disabled. With no user-auth
  block, only `X-Service-Token` is accepted and only rules with `allowedServices`
  can ever match; any rule requiring user `permissions` always denies. No Role
  Service, cache, reconciler, Kafka, or disk cache is started. Use this for
  service-to-service-only APIs that never see an end-user JWT. Set
  `serviceOnly: true` to select this mode **explicitly** — a stray user-auth
  value then fails fast instead of silently switching to full mode.
  `serviceOnly` cannot be combined with any user-auth field or
  `externalPermissionSource`.
- **External source mode** keeps the user check **on** but replaces the built-in
  role distribution — see [External permission source](#external-permission-source).
  `roleServiceUrl` is not required.

## Configuration

`createAuthz()` reads `AUTHZ_*` environment variables from `process.env`.
For parity with Spring's `authz.*` property binding, the names follow Spring
relaxed binding.

### Service auth (always active)

| Env var | Required | Default | Description |
|---|---|---|---|
| `AUTHZ_SERVICE_ISSUER` | yes | — | Issuer of service tokens (validated against the `iss` claim) |
| `AUTHZ_SERVICE_JWKS_URI` | yes | — | JWKS endpoint for service-token signature verification |
| `AUTHZ_SERVICE_TOKEN_USE_CLAIM` | no | `"token_use"` | JWT claim name inspected to identify a service token |
| `AUTHZ_SERVICE_TOKEN_USE_VALUE` | no | `"service"` | Expected value of the service-token-use claim |
| `AUTHZ_AUTHORIZATION_YAML` | one-of | — | Inline YAML content (alternative to path) |
| `AUTHZ_AUTHORIZATION_YAML_PATH` | one-of | — | Path to `authorization.yaml` on disk |
| `AUTHZ_CLOCK_SKEW_SECONDS` | no | `5` | Clock-skew tolerance (seconds) for JWT `exp`/`nbf` validation |
| `AUTHZ_SERVICE_ONLY` | no | `false` | `true`/`1` selects [service-only mode](#operating-modes) explicitly; rejects any user-auth var at startup |

### User auth (optional; all-or-nothing)

User auth is **all-or-nothing**. Setting any field below means **all** of them must be set (validated at startup). Omitting the whole block disables the user check entirely — the library runs in **service-only mode** (see [Operating modes](#operating-modes)): `Authorization` bearer tokens are ignored, only `X-Service-Token` is accepted, only `allowedServices` rules can match, and no role-permission machinery (Role Service, cache, reconciler, Kafka, disk) is started.

> To keep the user check **on** but feed permissions from your own store instead of the Role Service, see [External permission source](#external-permission-source) — set `externalPermissionSource: true` and omit `AUTHZ_ROLE_SERVICE_URL`.

| Env var | Required | Default | Description |
|---|---|---|---|
| `AUTHZ_USER_ISSUER` | when configured | — | Issuer of user JWTs (validated against the `iss` claim) |
| `AUTHZ_USER_JWKS_URI` | when configured | — | JWKS endpoint for user JWT signature verification |
| `AUTHZ_USER_AUDIENCE` | when configured | — | Expected `aud` claim in user JWTs |
| `AUTHZ_ROLE_SERVICE_URL` | when configured | — | Base URL of the Role Service for full role-map fetches |
| `AUTHZ_RECONCILE_INTERVAL_MS` | no | `300000` | Interval (ms) for unconditional full role-map re-fetch from Role Service |
| `AUTHZ_ROLE_SERVICE_CONNECT_TIMEOUT` | no | `5000` | Role Service HTTP connect timeout (ms) |
| `AUTHZ_ROLE_SERVICE_READ_TIMEOUT` | no | `5000` | Role Service HTTP read timeout (ms) |
| `AUTHZ_DISK_CACHE_PATH` | no | `"authorization-cache.json"` | Path to on-disk role cache file used as seed fallback when Role Service is unreachable at startup |
| `AUTHZ_KAFKA_BROKERS` | no | `""` | Comma-separated Kafka brokers; empty disables Kafka (snapshot + reconciler only) |
| `AUTHZ_ROLE_UPDATES_TOPIC` | no | `"role-updates"` | Kafka topic carrying role UPSERT events |
| `AUTHZ_ROLE_DELETE_TOPIC` | no | `"role-delete"` | Kafka topic carrying role DELETE events |
| `AUTHZ_PUBLISH_ROLES_TOPIC` | no | `"publish-roles"` | Kafka topic that triggers a forced full re-fetch |
| `AUTHZ_KAFKA_GROUP_ID` | no | `"authz-cache-sync"` | Kafka consumer group prefix (UUID appended per instance) |
| `AUTHZ_KAFKA_CLIENT_ID` | no | `"authz-cache-sync"` | Kafka consumer client ID |

### Outbound identity (optional)

| Env var | Required | Default | Description |
|---|---|---|---|
| `AUTHZ_TOKEN_URL` | when outbound identity | — | SSO/OIDC token endpoint issuing service tokens via `client_credentials` |
| `AUTHZ_CLIENT_ID` | presence enables | — | This service's OAuth2 client identifier |
| `AUTHZ_CLIENT_SECRET` | when outbound identity | — | This service's OAuth2 client secret (inject from your secret store) |

Absent variables are omitted so library defaults apply. Required-field validation
is performed by `createAuthz` (fail-fast at startup).

## Observability

The library owns **no** observability SDK configuration — that is a service
concern. It exposes two framework-agnostic seams:

- an in-process `Metrics` registry (`authz.metrics`) with stable counter/gauge
  names, which your service can scrape or mirror to its own exporter;
- a pluggable `AuditSink` SPI (default `LoggingAuditSink`). Supply your own
  `auditSink` to route per-decision events into your logging/telemetry stack.

To emit OTLP traces, Prometheus metrics, or structured logs, initialize your
observability SDK (e.g. OpenTelemetry) in your **service** entrypoint and, if you
want decision events in it, pass an `auditSink` that forwards to it:

```ts
const authz = await createAuthz({ auditSink: myOtelAuditSink });
```

## SPI extension points

- `TokenValidator` — swap JWT validation logic
- `ServiceIdentityProvider` — custom outbound token acquisition
- `RoleResolver` — resolve role to permission set
- `PolicyEngine` — replace the entire decision engine
- `AuditSink` — custom audit event handler
- `AttributeProvider` — supply ABAC attributes

### External permission source

To source permissions from your own store (Redis/Infinispan/Postgres) instead of
the built-in Role Service + Kafka + disk pipeline, set
`externalPermissionSource: true` and provide a `roleResolver` (or `policyEngine`):

```ts
await createAuthz({
  // ...user/service trust roots (no roleServiceUrl needed)...
  externalPermissionSource: true,
  roleResolver: { permissionsForRole: (role) => mySnapshot.get(role) ?? new Set() },
});
```

User-JWT validation stays enabled; the Role Service fetch, reconciler,
seed-retry, disk cache, and Kafka role events are all disabled. Keep the
resolver backed by an **in-memory** snapshot you refresh yourself — the request
path must not make a remote call.

## Testing

```bash
npm install
npm test
```

## Build

```bash
npm run build
```
