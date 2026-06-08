# spring-demo — using `authz-spring-boot`

This demo shows the **simplest possible** adoption: the library is a Spring Boot
**auto-configuration**, so there is *no* authorization wiring code in the demo at
all. The only Java files are the application class and the business controller.

## The entire integration

**1. Add the dependency** (`pom.xml`):

```xml
<dependency>
  <groupId>com.example.authz</groupId>
  <artifactId>authz-spring-boot</artifactId>
  <version>0.1.0</version>
</dependency>
```

**2. Add `authorization.yaml`** on the classpath
([`src/main/resources/authorization.yaml`](src/main/resources/authorization.yaml)).

**3. Set the `authz.*` properties**
([`application.properties`](src/main/resources/application.properties)):

```properties
# Required: trust roots + Role Service
authz.user-issuer=${MOCK_URL}/auth
authz.user-jwks-uri=${MOCK_URL}/auth/jwks
authz.service-issuer=${MOCK_URL}/sso
authz.service-jwks-uri=${MOCK_URL}/sso/jwks
authz.audience=orders-api
authz.role-service-url=${MOCK_URL}

# Optional: live Kafka role events (omit to use snapshot + reconciler only)
authz.kafka-brokers=${KAFKA_BROKERS:}
authz.role-updates-topic=role-updates
authz.role-delete-topic=role-delete
authz.publish-roles-topic=publish-roles

# Optional: outbound service identity for downstream calls
authz.token-url=${MOCK_URL}/sso/token
authz.client-id=spring-demo-id
authz.client-secret=spring-demo-secret

# Optional tuning (defaults shown)
authz.reconcile-interval-ms=5000
authz.service-token-use-claim=token_use
authz.service-token-use-value=service
authz.clock-skew-seconds=5
authz.disk-cache-path=authorization-cache.json
```

That's it. The auto-configuration (`AuthzAutoConfiguration`) creates and wires, all as
`@ConditionalOnMissingBean`:

- the decision engine (compiled from `authorization.yaml`, fail-fast);
- the permission cache + `CacheBootstrap` — Role Service snapshot, disk-seed fallback,
  **Kafka consumer** (when `authz.kafka-brokers` is set), and a periodic **reconciler**;
- the JWKS `TokenValidator` — user-JWT signature/issuer/**audience**, service-token `token_use`;
- `Metrics` and an `AuthzHealth` indicator;
- an optional outbound `ServiceIdentityProvider` (when `authz.client-id` is set), plus
  `RestClientCustomizer`/`RestTemplateCustomizer` beans that **auto-attach** propagation headers
  (user JWT, service token, correlation/request ids) to any app-built `RestClient`/`RestTemplate`;
- the **global servlet filter** (`/*`).

> Kafka support requires `spring-kafka` on the classpath — the demo's `pom.xml` includes it.
> Outbound auto-propagation covers `RestClient` and `RestTemplate` (both use a
> `ClientHttpRequestInterceptor`); `WebClient`/WebFlux is not bundled.

## Business code stays clean

[`OrdersController`](src/main/java/com/example/demo/OrdersController.java) has no
authorization annotations. The validated context is available either as a request
attribute or, preferably, by injecting the **request-scoped** `AuthzRequestContext`
bean:

```java
// As a request attribute:
RequestContext ctx = (RequestContext) req.getAttribute(AuthorizationFilter.CONTEXT_ATTR);

// Or injected (request-scoped) — also exposes the raw user JWT for outbound use:
@Autowired AuthzRequestContext authz;   // authz.context(), authz.userJwt()
```

Every `authz.*` bean is `@ConditionalOnMissingBean`, so you can override any piece
(e.g. supply your own `Spi.TokenValidator`) without forking the library.

## Run

```
# requires a JDK 21 + Maven, or use scripts/mvn.(sh|ps1) for Docker
scripts/mvn.sh demo-services/spring-demo spring-boot:run
```

Or use the full stack in [`tests/e2e`](../../tests/e2e).
