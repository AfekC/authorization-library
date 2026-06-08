# authz-spring-boot

Spring Boot auto-configuration library for config-driven authorization.

## Add dependency

```xml
<dependency>
  <groupId>com.example</groupId>
  <artifactId>authz-spring-boot</artifactId>
  <version>0.1.0</version>
</dependency>
```

## Getting Started

1. **Add the dependency** (above) to your Spring Boot 3 application. No wiring
   code is needed — auto-configuration registers the global enforcement filter.

2. **Provide `authorization.yaml`** on the classpath (the default
   `authz.config-location` is `classpath:authorization.yaml`), or point
   `authz.config-location` at any Spring resource (e.g. `file:/etc/app/authorization.yaml`).
   Your path → permission / allowed-service rules live entirely here.

3. **Set the required `authz.*` properties** in `application.yaml` (see
   [Configuration](#configuration) for the full list). Each is mandatory and
   fails fast at startup if missing:

   ```yaml
   authz:
     user-issuer: https://auth.example.com
     user-jwks-uri: https://auth.example.com/.well-known/jwks.json
     service-issuer: https://sso.example.com
     service-jwks-uri: https://sso.example.com/.well-known/jwks.json
     audience: my-app
     role-service-url: http://role-service:8080
   ```

4. **Tune optional properties** *(only if defaults don't fit)* — see the
   [Configuration](#configuration) table for defaults.

5. **Enable outbound identity** *(optional)* — see
   [Configuration](#configuration) for the required properties.

6. **Start the app.** Every request is now enforced globally — no per-route opt-in.

## Configuration

All properties go in `application.yaml` under the `authz.*` namespace. They are
also bindable as `AUTHZ_*` environment variables (Spring relaxed binding — e.g.
`authz.user-issuer` → `AUTHZ_USER_ISSUER`).

| Property | Required | Default | Description |
|---|---|---|---|
| `authz.user-issuer` | yes | — | Issuer (`iss`) your user JWTs must carry |
| `authz.user-jwks-uri` | yes | — | JWKS endpoint for user-JWT signature verification |
| `authz.service-issuer` | yes | — | Issuer (`iss`) your service tokens must carry |
| `authz.service-jwks-uri` | yes | — | JWKS endpoint for service-token signature verification |
| `authz.audience` | yes | — | Expected JWT audience (`aud`) for this service |
| `authz.role-service-url` | yes | — | Authoritative Role Service base URL |
| `authz.config-location` | no | `classpath:authorization.yaml` | Spring resource location of `authorization.yaml` |
| `authz.clock-skew-seconds` | no | `5` | Clock-skew tolerance (seconds) for JWT `exp`/`nbf` checks |
| `authz.jwks-timeout-ms` | no | `5000` | HTTP timeout (ms) for JWKS fetches during token validation |
| `authz.role-service-connect-timeout` | no | `5000` | Role Service HTTP connect timeout (ms) |
| `authz.role-service-read-timeout` | no | `5000` | Role Service HTTP read timeout (ms) |
| `authz.reconcile-interval-ms` | no | `300000` | Periodic reconciler interval (ms). Seed-retry uses a separate 2s/4s/8s backoff. |
| `authz.disk-cache-path` | no | `authorization-cache.json` | On-disk role-cache file used as seed fallback at startup |
| `authz.service-token-use-claim` | no | `token_use` | JWT claim inspected to identify a service token |
| `authz.service-token-use-value` | no | `service` | Expected value of the service-token-use claim |
| `authz.kafka-brokers` | no | *(empty)* | Kafka brokers for incremental role events; empty disables Kafka |
| `authz.role-updates-topic` | no | `role-updates` | Kafka topic carrying role UPSERT events |
| `authz.role-delete-topic` | no | `role-delete` | Kafka topic carrying role DELETE events |
| `authz.publish-roles-topic` | no | `publish-roles` | Kafka topic that triggers a forced full re-fetch |
| `authz.kafka-group-id` | no | `authz-cache-sync` | Kafka consumer group prefix (UUID appended per instance) |
| `authz.kafka-client-id` | no | `authz-cache-sync` | Kafka consumer client ID prefix |
| `authz.untrusted-header-prefixes` | no | *(empty)* | Extra inbound header-name prefixes to strip |
| `authz.untrusted-header-exact` | no | *(empty)* | Extra exact inbound header names to strip |
| `authz.token-url` | when outbound identity | — | SSO/OIDC token endpoint for `client_credentials` grant |
| `authz.client-id` | presence enables | — | This service's OAuth2 client identifier |
| `authz.client-secret` | when outbound identity | — | This service's OAuth2 client secret (inject from secret store) |
| `authz.token-endpoint-timeout-ms` | no | `5000` | HTTP timeout (ms) for token-endpoint calls |
| `authz.token-refresh-check-interval-ms` | no | `30000` | Interval (ms) for checking cached token lifetime |

## Key beans

The auto-configuration registers:

- **`AuthorizationEngine`** — compiled rule engine
- **`PermissionCache`** — in-memory role → permissions store
- **`AuthzFilter`** — global servlet filter (all requests)
- **`Metrics`** — Micrometer counters and gauges
- **`RoleServiceClient`** — HTTP client for the Role Service
- **`DiskCache`** — local file fallback for the role cache
- **`AuditSink`** — logging audit event handler

## Testing

```bash
tests/scripts/mvn.sh libraries/authz-spring-boot test
```

## Build from source

The library builds with Maven against JDK 21. This repo ships no host JDK, so the
build runs in a `maven:3-eclipse-temurin-21` Docker image via the wrapper scripts:

```bash
# Linux/macOS
tests/scripts/mvn.sh libraries/authz-spring-boot clean install

# Windows (PowerShell)
tests\scripts\mvn.ps1 -ModuleDir libraries/authz-spring-boot clean install
```

With a local JDK 21 + Maven installed, run `mvn clean install` directly instead.
