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

## Configuration

`createAuthz()` reads `AUTHZ_*` environment variables from `process.env`.
For parity with Spring's `authz.*` property binding, the names follow Spring
relaxed binding — e.g. `authz.user-issuer` → `AUTHZ_USER_ISSUER`:

| Env var | Required | Default | Description |
|---|---|---|---|
| `AUTHZ_USER_ISSUER` | yes | — | Issuer of user JWTs (validated against the `iss` claim) |
| `AUTHZ_USER_JWKS_URI` | yes | — | JWKS endpoint for user JWT signature verification |
| `AUTHZ_SERVICE_ISSUER` | yes | — | Issuer of service tokens (validated against the `iss` claim) |
| `AUTHZ_SERVICE_JWKS_URI` | yes | — | JWKS endpoint for service-token signature verification |
| `AUTHZ_AUDIENCE` | yes | — | Expected `aud` claim in user JWTs |
| `AUTHZ_ROLE_SERVICE_URL` | yes | — | Base URL of the Role Service for full role-map fetches |
| `AUTHZ_AUTHORIZATION_YAML` | one-of | — | Inline YAML content (alternative to path) |
| `AUTHZ_AUTHORIZATION_YAML_PATH` | one-of | — | Path to `authorization.yaml` on disk |
| `AUTHZ_CLOCK_SKEW_SECONDS` | no | `5` | Clock-skew tolerance (seconds) for JWT `exp`/`nbf` validation |
| `AUTHZ_RECONCILE_INTERVAL_MS` | no | `300000` | Interval (ms) for unconditional full role-map re-fetch from Role Service |
| `AUTHZ_ROLE_SERVICE_CONNECT_TIMEOUT` | no | `5000` | Role Service HTTP connect timeout (ms) |
| `AUTHZ_ROLE_SERVICE_READ_TIMEOUT` | no | `5000` | Role Service HTTP read timeout (ms) |
| `AUTHZ_DISK_CACHE_PATH` | no | `"authorization-cache.json"` | Path to on-disk role cache file used as seed fallback when Role Service is unreachable at startup |
| `AUTHZ_SERVICE_TOKEN_USE_CLAIM` | no | `"token_use"` | JWT claim name inspected to identify a service token |
| `AUTHZ_SERVICE_TOKEN_USE_VALUE` | no | `"service"` | Expected value of the service-token-use claim |
| `AUTHZ_KAFKA_BROKERS` | no | `""` | Comma-separated Kafka brokers; empty disables Kafka (snapshot + reconciler only) |
| `AUTHZ_ROLE_UPDATES_TOPIC` | no | `"role-updates"` | Kafka topic carrying role UPSERT events |
| `AUTHZ_ROLE_DELETE_TOPIC` | no | `"role-delete"` | Kafka topic carrying role DELETE events |
| `AUTHZ_PUBLISH_ROLES_TOPIC` | no | `"publish-roles"` | Kafka topic that triggers a forced full re-fetch |
| `AUTHZ_KAFKA_GROUP_ID` | no | `"authz-cache-sync"` | Kafka consumer group prefix (UUID appended per instance) |
| `AUTHZ_KAFKA_CLIENT_ID` | no | `"authz-cache-sync"` | Kafka consumer client ID |
| `AUTHZ_TOKEN_URL` | when outbound identity | — | SSO/OIDC token endpoint issuing service tokens via `client_credentials` |
| `AUTHZ_CLIENT_ID` | presence enables | — | This service's OAuth2 client identifier |
| `AUTHZ_CLIENT_SECRET` | when outbound identity | — | This service's OAuth2 client secret (inject from your secret store) |

Absent variables are omitted so library defaults apply. Required-field validation
is performed by `createAuthz` (fail-fast at startup).

## Observability

The library can route audit logs, metrics, and authorization spans through the
local in-house package `@hatraa/otel-ts`. In this repo it is consumed from the
vendored tarball:

```json
"@hatraa/otel-ts": "file:./vendor/hatraa-otel-ts-7.0.11.tgz"
```

For full HTTP/Nest auto-instrumentation, initialize it before loading Express,
NestJS, or HTTP clients:

```ts
import { initObservability, createAuthz } from "authz-nestjs";

initObservability({
  enabled: true,
  serviceName: "orders-api",
  systemName: "auth-library",
  envName: "drill",
  otelExporterOtlpEndpoint: "http://localhost:4317",
});

const authz = await createAuthz({ observability: { enabled: true } });
```

Env-only bootstrap also supports:

| Env var | Required | Default | Description |
|---|---|---|---|
| `AUTHZ_OTEL_ENABLED` | no | `false` | Truthy value enables the o11y bridge in `createAuthz()` |
| `AUTHZ_OTEL_SERVICE_NAME` | when enabled | `authz` | OTel service name |
| `AUTHZ_OTEL_SYSTEM_NAME` | when enabled | `authz` | OTel `system` resource attribute |
| `AUTHZ_OTEL_ENV_NAME` | when enabled | `live` | One of `drill`, `live`, `global` |
| `AUTHZ_OTEL_EXPORTER_OTLP_ENDPOINT` | no | SDK default | OTLP/gRPC traces endpoint |

When enabled:

- audit events use `otelLogger`;
- the existing authz counters/gauges are exposed via the o11y Prometheus reader
  (default `:9464/metrics`);
- the middleware decision path is wrapped in an `authz.request` span.

### Local in-house observability package

This repo consumes the in-house Node observability SDK from a vendored tarball:
`libraries/authz-nestjs/vendor/hatraa-otel-ts-7.0.11.tgz`. That allows
`authz-nestjs` to use the local `o11y-node` package without publishing it to npm.

To refresh the vendored package from a local `o11y-node` checkout:

PowerShell:
```powershell
tests\scripts\install-o11y-node.ps1 -O11yNodeDir C:\path\to\o11y-node
```

Bash:
```bash
tests/scripts/install-o11y-node.sh /path/to/o11y-node
```

Then re-run `npm install` in `libraries/authz-nestjs`.

## SPI extension points

- `TokenValidator` — swap JWT validation logic
- `ServiceIdentityProvider` — custom outbound token acquisition
- `RoleResolver` — resolve role to permission set
- `PolicyEngine` — replace the entire decision engine
- `AuditSink` — custom audit event handler
- `AttributeProvider` — supply ABAC attributes

## Testing

```bash
npm install
npm test
```

## Build

```bash
npm run build
```
