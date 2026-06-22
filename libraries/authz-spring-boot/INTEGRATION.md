# authz-spring-boot — Integration cookbook

Copy-pasteable wiring for every important way to adopt the library in a service.
Every example is taken from the working demo (`tests/demo-services/spring-demo/`), so it
matches the real auto-configuration. See the [README](README.md) for the full `authz.*`
property reference.

**Mental model:** service auth is always on. Two things vary — whether **user JWTs** are
checked, and where **role→permission** data comes from. That gives three operating modes
([full](#1-full-mode), [service-only](#2-service-only-mode),
[external source](#3-external-permission-source)). Enforcement is **global** — a servlet
filter authorizes every request; business controllers carry no auth code and need no
annotations.

## Contents

1. [Full mode](#1-full-mode)
2. [Service-only mode](#2-service-only-mode)
3. [External permission source](#3-external-permission-source)
4. [authorization.yaml rule shapes](#4-authorizationyaml-rule-shapes)
5. [Reading the validated context](#5-reading-the-validated-context)
6. [Kafka role events](#6-kafka-role-events)
7. [Outbound propagation & identity](#7-outbound-propagation--identity)
8. [Custom AuditSink & Micrometer](#8-custom-auditsink--micrometer)
9. [SPI override beans](#9-spi-override-beans)

---

## 1. Full mode

Add the dependency — auto-configuration registers the global filter, the rule engine, the
cache, and the startup state machine (Role Service snapshot → disk seed → reconciler). No
wiring code; configuration is properties only.

```xml
<dependency>
  <groupId>com.example</groupId>
  <artifactId>authz-spring-boot</artifactId>
  <version>0.1.0</version>
</dependency>
```

```properties
# application.properties — the only wiring needed.
# authorization.yaml is on the classpath by default (authz.config-location).

# Service auth (always required)
authz.service-issuer=https://sso.example.com
authz.service-jwks-uri=https://sso.example.com/.well-known/jwks.json

# User auth (all-or-nothing). Omit this block + role-service-url for service-only mode (§2).
authz.user.issuer=https://auth.example.com
authz.user.jwks-uri=https://auth.example.com/.well-known/jwks.json
authz.user.audience=orders-api
authz.role-service-url=http://role-service:8080

# Outbound identity (optional — see §7)
authz.token-url=https://sso.example.com/token
authz.client-id=${CLIENT_ID}
authz.client-secret=${CLIENT_SECRET}
```

Every `authz.*` property is also bindable as an `AUTHZ_*` environment variable (Spring
relaxed binding). Your `@SpringBootApplication` main class needs no changes.

## 2. Service-only mode

The user check is fully disabled: `Authorization` bearer tokens are ignored, only
`X-Service-Token` is accepted, and only rules with `allowedServices` can match. The
`@Conditional(OnUserAuthEnabled)` machinery (cache bootstrap, Kafka listener, health,
cache-backed resolver) is never created. Select it by **omitting** the `authz.user.*` block
(and `authz.role-service-url`), or **explicitly**:

```properties
authz.service-issuer=https://sso.example.com
authz.service-jwks-uri=https://sso.example.com/.well-known/jwks.json
authz.service-only=true
```

`authz.service-only=true` fails fast at startup if combined with any `authz.user.*` property,
`authz.role-service-url`, or `authz.external-permission-source` — no silent mode flip.

## 3. External permission source

Keep the user check **on** but source role→permission data from your own store
(Redis/Infinispan/Postgres) instead of the built-in Role Service + Kafka + disk pipeline. Set
the flag and supply a `Spi.RoleResolver` bean:

```properties
authz.service-issuer=https://sso.example.com
authz.service-jwks-uri=https://sso.example.com/.well-known/jwks.json
authz.user.issuer=https://auth.example.com
authz.user.jwks-uri=https://auth.example.com/.well-known/jwks.json
authz.user.audience=orders-api
authz.external-permission-source=true
# authz.role-service-url is NOT required in this mode
```

```java
import com.example.authz.spi.Spi;
import java.util.Set;

@Configuration
class AuthzConfig {
    @Bean
    Spi.RoleResolver roleResolver(MySnapshot snapshot) {
        // Serve from an in-memory snapshot YOU refresh — the request path must
        // not make a remote call.
        return role -> snapshot.getOrDefault(role, Set.of());
    }
}
```

The `CacheBootstrap` (Role Service fetch, reconciler, seed-retry, disk cache) and the Kafka
role-event listener are not created.

## 4. authorization.yaml rule shapes

Authorization lives entirely in `authorization.yaml`; controllers carry no annotations. The
rule shapes are shared 1:1 with the NestJS library:

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

  # USER_AND_SERVICE — both dimensions required. "*" = any authenticated service.
  - path: /orders/**
    methods: [POST]
    permissions: [WRITE_ORDER]
    allowedServices: ["*"]
```

Matching is most-specific-wins (literal `2` > `*` `1` > `**` `0`, left to right). No matching
rule → **DENY**. Unknown role → empty permissions → **DENY**. Ambiguous rules are rejected at
startup. See `docs/contracts/config-files.md` for full wildcard scoring.

## 5. Reading the validated context

The global filter builds a `RequestContext` from validated token claims (inbound `X-User-*` /
`X-Role` identity headers are stripped) and stashes it as a request attribute. Read it with
`AuthorizationFilter.CONTEXT_ATTR`:

```java
import com.example.authz.context.RequestContext;
import com.example.authz.web.AuthorizationFilter;
import jakarta.servlet.http.HttpServletRequest;

@RestController
public class OrdersController {
    @GetMapping("/orders/{id}")
    public Map<String, Object> getOrder(@PathVariable String id, HttpServletRequest req) {
        RequestContext ctx = (RequestContext) req.getAttribute(AuthorizationFilter.CONTEXT_ATTR);
        return Map.of(
                "id", id,
                "by", ctx != null && ctx.userId() != null ? ctx.userId() : "unknown",
                "service", ctx != null ? ctx.serviceName() : "none");
    }
}
```

## 6. Kafka role events

Incremental role updates arrive over Kafka. The **library owns the listener** (`@KafkaListener`
beans + a per-instance consumer group for broadcast fan-out); the **host owns the connection
config** via `spring.kafka.consumer.*`. Set the topic names and the connection in
`application.properties` — do **not** set a group id:

```properties
# Topic names for the library's @KafkaListener beans (library owns the consumer)
authz.kafka.role-updates-topic=role-updates
authz.kafka.role-delete-topic=role-delete
authz.kafka.publish-roles-topic=publish-roles

# Connection config — owned by the host service
spring.kafka.bootstrap-servers=${KAFKA_BROKERS:localhost:9092}
spring.kafka.consumer.key-deserializer=org.apache.kafka.common.serialization.StringDeserializer
spring.kafka.consumer.value-deserializer=io.confluent.kafka.serializers.KafkaAvroDeserializer
spring.kafka.consumer.auto-offset-reset=latest
spring.kafka.consumer.properties.schema.registry.url=${SCHEMA_REGISTRY_URL:http://localhost:8081}
# group-id is NOT set — the library generates a unique group per instance.
```

A `publish-roles` event triggers a full Role Service re-fetch (fail-open). The periodic
reconciler heals any missed/out-of-order events.

## 7. Outbound propagation & identity

Set the outbound-identity properties (§1) and the auto-configured `OutboundPropagationInterceptor`
is applied to any `RestTemplate`/`RestClient` built from the Spring-provided builder. Calls made
while handling an authorized request auto-attach the user JWT, this service's service token, and
the `X-Correlation-Id` / `X-Request-Id` trace headers.

```java
@RestController
public class OrdersController {
    private final RestTemplate restTemplate;

    public OrdersController(RestTemplateBuilder builder) {
        // The builder applies the auto-configured OutboundPropagationInterceptor.
        this.restTemplate = builder.build();
    }

    @PostMapping("/orders/{id}/forward")
    public Map<String, Object> forward(@PathVariable String id) {
        var resp = restTemplate.postForEntity("https://api.internal/orders/" + id, null, Map.class);
        return Map.of("forwarded", true, "downstreamStatus", resp.getStatusCode().value());
    }
}
```

Credential headers (user JWT + service token) are attached only to trusted downstream hosts;
trace headers are always propagated. The outbound token is cached with proactive refresh
(`authz.token-refresh-check-interval-ms`).

## 8. Custom AuditSink & Micrometer

The library owns **no** observability SDK config. Audit logs use the `AUTHZ` logger via a
pluggable `Spi.AuditSink` (default `LoggingAuditSink`) — register your own bean to route
per-decision events into your telemetry stack:

```java
@Bean
Spi.AuditSink auditSink(MyTelemetry telemetry) {
    return event -> telemetry.record(event);
}
```

The in-process `Metrics` registry keeps stable counters/gauges and **auto-mirrors to
Micrometer** when a `MeterRegistry` bean is on the classpath (e.g. via
`spring-boot-starter-actuator`). `micrometer-core` is an optional dependency, so the binding
activates only when your service provides a registry. Configure OTLP/Prometheus export with
Actuator in your service.

## 9. SPI override beans

Every extensibility seam is an interface on `com.example.authz.spi.Spi`. Register a `@Bean` to
swap an implementation without touching auth logic — auto-configuration backs off when you
provide your own:

```java
@Bean Spi.TokenValidator tokenValidator() { return myValidator; }
@Bean Spi.PolicyEngine policyEngine() { return myEngine; }
@Bean Spi.AttributeProvider attributeProvider() { return myAbac; }
```

Seams: `TokenValidator`, `ServiceIdentityProvider`, `RoleResolver`, `PolicyEngine`,
`AttributeProvider`, `RoleServiceClient`, `AuditSink`.
