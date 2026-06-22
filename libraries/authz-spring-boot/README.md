# authz-spring-boot

Spring Boot auto-configuration library for config-driven authorization.

> **Integrating into a service?** The [Integration cookbook](INTEGRATION.md) has full,
> copy-pasteable wiring for every case — all three modes, Kafka, outbound propagation,
> context reading, custom AuditSink, and SPI override beans. This README is the config
> reference.

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
   [Configuration](#configuration) for the full list). Service auth is always
   required; user auth is an optional add-on block:

   ```yaml
   authz:
     # Service auth (always required)
     service-issuer: https://sso.example.com
     service-jwks-uri: https://sso.example.com/.well-known/jwks.json

     # User auth (optional; all-or-nothing — omit to run in service-only mode)
     user:
       issuer: https://auth.example.com
       jwks-uri: https://auth.example.com/.well-known/jwks.json
       audience: my-app
     role-service-url: http://role-service:8080
   ```

   When the user-auth block is omitted, the user check is fully disabled and the
   library runs in **service-only mode** (see [Operating modes](#operating-modes)):
   `Authorization` bearer tokens are ignored, only `X-Service-Token` is accepted,
   only `allowedServices` rules can match, and no role-permission machinery (Role
   Service, cache, reconciler, Kafka, disk) is activated.

4. **Tune optional properties** *(only if defaults don't fit)* — see the
   [Configuration](#configuration) table for defaults.

5. **Enable outbound identity** *(optional)* — see
   [Configuration](#configuration) for the required properties.

6. **Start the app.** Every request is now enforced globally — no per-route opt-in.

> Full runnable wiring (dependency + `application.properties` + a context-reading
> controller): [§1 full mode](INTEGRATION.md#1-full-mode) in the Integration cookbook.

## Observability

The library owns **no** observability SDK configuration — that is a service
concern. It exposes two framework-agnostic seams:

- audit logs use the `AUTHZ` logger via a pluggable `Spi.AuditSink`
  (default `LoggingAuditSink`); register your own `AuditSink` bean to route
  per-decision events into your telemetry stack;
- the in-process `Metrics` registry keeps stable counters/gauges for health and
  tests, and **auto-mirrors to Micrometer** when a `MeterRegistry` bean is on the
  classpath (e.g. via `spring-boot-starter-actuator`). `micrometer-core` is an
  optional dependency, so the binding activates only when the service provides a
  registry.

Configure tracing/metrics/log export (OTLP, Prometheus, etc.) in your **service**
using Spring Boot Actuator / your chosen observability starter. Bean example:
[§8 custom AuditSink & Micrometer](INTEGRATION.md#8-custom-auditsink--micrometer).

## Operating modes

Service auth is always on. What varies is **whether user JWTs are checked** and
**where role→permission data comes from**:

| Mode | How to select | User JWTs | Role→permission source | Built-in distribution (Role Service + Kafka + disk) |
|---|---|---|---|---|
| **Full** (default) | set `authz.user.*` + `authz.role-service-url` | validated | library's Role Service + Kafka + disk pipeline | **on** |
| **Service-only** (user check disabled) | omit the whole `authz.user` block (and `role-service-url`), or set `authz.service-only=true` to make it explicit | **ignored** — `Authorization` bearer tokens are never read | n/a (no roles) | **off** |
| **External source** | set `authz.user.*` + `authz.external-permission-source=true` + a `Spi.RoleResolver` bean | validated | **your** resolver, backed by your store (Redis/Infinispan/Postgres) | **off** |

- **Service-only mode** = the user check is fully disabled. With no user-auth
  block, only `X-Service-Token` is accepted and only rules with `allowedServices`
  can ever match; any rule requiring user `permissions` always denies. The
  `@Conditional(OnUserAuthEnabled)` machinery (`CacheBootstrap`, Kafka listener,
  health, cache-backed resolver) is not created at all. Set
  `authz.service-only=true` to select this mode **explicitly** — a stray
  user-auth property then fails fast at startup instead of silently switching to
  full mode. It cannot be combined with any `authz.user.*` property,
  `authz.role-service-url`, or `authz.external-permission-source`.
- **External source mode** keeps the user check **on** but replaces the built-in
  role distribution — see [External permission source](#external-permission-source).
  `authz.role-service-url` is not required.

> Runnable examples: [§2 service-only](INTEGRATION.md#2-service-only-mode),
> [§3 external permission source](INTEGRATION.md#3-external-permission-source) in the
> Integration cookbook.

## Configuration

All properties go in `application.yaml` under the `authz.*` namespace. They are
also bindable as `AUTHZ_*` environment variables (Spring relaxed binding).

### Service auth (always active)

| Property | Required | Default | Description |
|---|---|---|---|
| `authz.service-issuer` | yes | — | Issuer (`iss`) your service tokens must carry |
| `authz.service-jwks-uri` | yes | — | JWKS endpoint for service-token signature verification |
| `authz.config-location` | no | `classpath:authorization.yaml` | Spring resource location of `authorization.yaml` |
| `authz.clock-skew-seconds` | no | `5` | Clock-skew tolerance (seconds) for JWT `exp`/`nbf` checks |
| `authz.jwks-timeout-ms` | no | `5000` | HTTP timeout (ms) for JWKS fetches during token validation |
| `authz.service-token-use-claim` | no | `token_use` | JWT claim inspected to identify a service token |
| `authz.service-token-use-value` | no | `service` | Expected value of the service-token-use claim |
| `authz.service-token-audience` | no | *(empty)* | When set, service tokens must carry this value in their `aud` claim (T5). Blank = no audience check. |
| `authz.service-only` | no | `false` | `true` selects [service-only mode](#operating-modes) explicitly; rejects any user-auth property at startup |
| `authz.untrusted-header-prefixes` | no | *(empty)* | Extra inbound header-name prefixes to strip |
| `authz.untrusted-header-exact` | no | *(empty)* | Extra exact inbound header names to strip |

### User auth (optional; all-or-nothing)

User auth is **all-or-nothing**. Setting any field below means **all** of them must be set (validated at startup). Omitting the whole `authz.user` block disables the user check entirely — the library runs in **service-only mode** (see [Operating modes](#operating-modes)): `Authorization` bearer tokens are ignored, only `X-Service-Token` is accepted, and only `allowedServices` rules can match.

> To keep the user check **on** but feed permissions from your own store instead of the Role Service, set `authz.external-permission-source=true`, provide a `Spi.RoleResolver` bean, and omit `authz.role-service-url` — see [External permission source](#external-permission-source).

| Property | Required | Default | Description |
|---|---|---|---|
| `authz.user.issuer` | when configured | — | Issuer (`iss`) your user JWTs must carry |
| `authz.user.jwks-uri` | when configured | — | JWKS endpoint for user-JWT signature verification |
| `authz.user.audience` | when configured | — | Expected JWT audience (`aud`) for user JWTs |
| `authz.role-service-url` | when user auth on, **unless** external source | — | Authoritative Role Service base URL |
| `authz.external-permission-source` | no | `false` | Disable built-in role distribution; supply a `Spi.RoleResolver` bean instead (see [External permission source](#external-permission-source)) |
| `authz.role-service-connect-timeout` | no | `5000` | Role Service HTTP connect timeout (ms) |
| `authz.role-service-read-timeout` | no | `5000` | Role Service HTTP read timeout (ms) |
| `authz.reconcile-interval-ms` | no | `300000` | Periodic reconciler interval (ms). Seed-retry uses a separate 2s/4s/8s backoff. |
| `authz.disk-cache-path` | no | `authorization-cache.json` | On-disk role-cache file used as seed fallback at startup |
| `authz.kafka.role-updates-topic` | no | `role-updates` | Kafka topic carrying role UPSERT events |
| `authz.kafka.role-delete-topic` | no | `role-delete` | Kafka topic carrying role DELETE events |
| `authz.kafka.publish-roles-topic` | no | `publish-roles` | Kafka topic that triggers a forced full re-fetch |

> Kafka **connection** config (brokers, consumer group, deserializer, schema registry) is owned by the host service via `spring.kafka.consumer.*`. The library only owns the topic names above; consumer groups are generated per-instance (UUID suffix) for broadcast fan-out. Full `application.properties` block: [§6 Kafka role events](INTEGRATION.md#6-kafka-role-events).

### Outbound identity (optional)

| Property | Required | Default | Description |
|---|---|---|---|
| `authz.token-url` | when outbound identity | — | SSO/OIDC token endpoint for `client_credentials` grant |
| `authz.client-id` | presence enables | — | This service's OAuth2 client identifier |
| `authz.client-secret` | when outbound identity | — | This service's OAuth2 client secret (inject from secret store) |
| `authz.token-endpoint-timeout-ms` | no | `5000` | HTTP timeout (ms) for token-endpoint calls |
| `authz.token-refresh-check-interval-ms` | no | `30000` | Interval (ms) for checking cached token lifetime |

> Propagation wiring (`RestTemplateBuilder`/`RestClient` auto-interceptor, trusted hosts):
> [§7 outbound propagation & identity](INTEGRATION.md#7-outbound-propagation--identity).

## Key beans

The auto-configuration registers:

- **`AuthorizationEngine`** — compiled rule engine
- **`PermissionCache`** — in-memory role → permissions store
- **`AuthzFilter`** — global servlet filter (all requests)
- **`Metrics`** — Micrometer counters and gauges
- **`RoleServiceClient`** — HTTP client for the Role Service
- **`DiskCache`** — local file fallback for the role cache
- **`AuditSink`** — logging audit event handler

Override any of these (and the other SPI seams) with your own `@Bean` —
[§9 SPI override beans](INTEGRATION.md#9-spi-override-beans). Custom audit + Micrometer:
[§8 custom AuditSink & Micrometer](INTEGRATION.md#8-custom-auditsink--micrometer).

### External permission source

To source permissions from your own store (Redis/Infinispan/Postgres) instead of
the built-in Role Service + Kafka + disk pipeline, set
`authz.external-permission-source=true` and supply a `Spi.RoleResolver` bean:

```java
@Bean
Spi.RoleResolver roleResolver() {
    return role -> mySnapshot.getOrDefault(role, Set.of());
}
```

User-JWT validation stays enabled; the `CacheBootstrap` (Role Service fetch,
reconciler, seed-retry, disk cache) and the Kafka role-event listener are not
created, and `authz.role-service-url` is not required. Keep the resolver backed
by an **in-memory** snapshot you refresh yourself — the request path must not
make a remote call. Full example:
[§3 external permission source](INTEGRATION.md#3-external-permission-source).

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
