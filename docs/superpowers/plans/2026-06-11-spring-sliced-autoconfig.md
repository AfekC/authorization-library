# Spring Boot Sliced Auto-Configuration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the monolithic `AuthzAutoConfiguration` with six cohesive, ordered `@AutoConfiguration` slices under a `com.example.authz.autoconfigure` package, with zero change to any authorization decision.

**Architecture:** Move every `@Bean` from the single 400-line config into per-concern slices (Core, InboundAuth, CacheSync, Outbound, Observability, WebSecurity). Beans keep their exact bodies, conditions, and `@ConditionalOnMissingBean`. Ordering is made explicit via `@AutoConfiguration(after/before)`. The six classes are registered in the `.imports` file. `AuthorizationFilter` remains the single decision site (parity linchpin — no second decision path is introduced).

**Tech Stack:** Java 21, Spring Boot 3.x auto-configuration, Maven via Docker (`tests/scripts/mvn.ps1`), JUnit 5.

**Parity gate (run after every task):**
`tests\scripts\mvn.ps1 -ModuleDir libraries/authz-spring-boot test` must stay green, with special attention to `SharedVectorsTest` (the 46 vectors) and `AuthzAutoConfigurationTest`.

---

## File Structure

Created (all in `libraries/authz-spring-boot/src/main/java/com/example/authz/autoconfigure/`):
- `AuthzCoreAutoConfiguration.java` — properties, config validator, engine, cache
- `InboundAuthAutoConfiguration.java` — token validator, header sanitizer, request-scoped context
- `CacheSyncAutoConfiguration.java` — Kafka handler, cache bootstrap, health, role resolver (`@Conditional OnUserAuthEnabled`)
- `OutboundAutoConfiguration.java` — service identity, propagation interceptor, RestClient/RestTemplate customizers
- `ObservabilityAutoConfiguration.java` — metrics, micrometer binding, o11y compat util, audit sink
- `WebSecurityAutoConfiguration.java` — authorization filter, security filter chain
- `OnUserAuthEnabled.java` — the shared `Condition` (extracted from the old nested class)
- `package-info.java`

Moved:
- `com/example/authz/boot/AuthzProperties.java` → `com/example/authz/autoconfigure/AuthzProperties.java`

Modified:
- `src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` — list the six slices
- Test files that import `com.example.authz.boot.*` — repoint to `autoconfigure`

Deleted:
- `com/example/authz/boot/AuthzAutoConfiguration.java`
- `com/example/authz/boot/package-info.java` (after move)

---

## Task 1: Pin current behavior (characterization baseline)

**Files:**
- Test: existing suite (no new file)

- [ ] **Step 1: Run the full Spring suite and record the green baseline**

Run: `tests\scripts\mvn.ps1 -ModuleDir libraries/authz-spring-boot test`
Expected: BUILD SUCCESS. Note the test count (especially `SharedVectorsTest` vector count = 46) so later tasks can confirm no test silently disappears.

- [ ] **Step 2: List every reference to the `boot` package so nothing is missed**

Run (Grep tool): pattern `com\.example\.authz\.boot` across `libraries/authz-spring-boot`.
Expected: matches in `AuthzAutoConfiguration.java`, `AuthzProperties.java`, the `.imports` file, and any test (e.g. `AuthzAutoConfigurationTest`, `ModulesTest`). Record the list — these are the call sites Task 8 must update.

- [ ] **Step 3: Commit the baseline note (plan only, no code yet)**

No commit needed if nothing changed; proceed.

---

## Task 2: Extract `OnUserAuthEnabled` and `AuthzProperties` into `autoconfigure`

**Files:**
- Create: `.../autoconfigure/OnUserAuthEnabled.java`
- Create: `.../autoconfigure/package-info.java`
- Move: `.../boot/AuthzProperties.java` → `.../autoconfigure/AuthzProperties.java`

- [ ] **Step 1: Create the package-info**

```java
package com.example.authz.autoconfigure;
```
(with the file's standard Javadoc header matching the other `package-info.java` files in this module.)

- [ ] **Step 2: Extract the `OnUserAuthEnabled` condition to its own top-level class**

```java
package com.example.authz.autoconfigure;

import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Matches when user auth is enabled (FULL mode, §0.5). Gates the entire
 * role-permission machinery so it is absent in SERVICE-ONLY mode.
 */
public class OnUserAuthEnabled implements Condition {
    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        AuthzProperties p = Binder.get(context.getEnvironment())
                .bind("authz", AuthzProperties.class)
                .orElseGet(AuthzProperties::new);
        return p.isUserAuthEnabled();
    }
}
```

- [ ] **Step 3: Move `AuthzProperties.java` and change its package line**

Move the file to `.../autoconfigure/AuthzProperties.java` and change `package com.example.authz.boot;` → `package com.example.authz.autoconfigure;`. Body unchanged.

- [ ] **Step 4: Compile-only check (will fail until slices exist — that's expected)**

Run: `tests\scripts\mvn.ps1 -ModuleDir libraries/authz-spring-boot test-compile`
Expected: FAIL — `AuthzAutoConfiguration` still references the now-moved `AuthzProperties` and the old nested condition. This is fixed in Tasks 3–7. Do not commit yet.

---

## Task 3: `AuthzCoreAutoConfiguration` (properties, validator, engine, cache)

**Files:**
- Create: `.../autoconfigure/AuthzCoreAutoConfiguration.java`

- [ ] **Step 1: Create the slice with the Core beans moved verbatim**

```java
package com.example.authz.autoconfigure;

import com.example.authz.cache.PermissionCache;
import com.example.authz.config.YamlLoader;
import com.example.authz.engine.AuthorizationEngine;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.Resource;

import java.net.URI;
import java.nio.charset.StandardCharsets;

/**
 * Core authorization beans: properties binding, fail-fast config validation,
 * the compiled decision engine, and the in-memory permission cache. Ordered
 * first so every other slice can depend on these.
 */
@AutoConfiguration
@EnableConfigurationProperties(AuthzProperties.class)
public class AuthzCoreAutoConfiguration {

    @Bean
    ConfigValidator authzConfigValidator(AuthzProperties props) {
        return new ConfigValidator(props);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthorizationEngine authorizationEngine(AuthzProperties props, ApplicationContext ctx)
            throws Exception {
        Resource resource = ctx.getResource(props.getConfigLocation());
        String yaml = new String(resource.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        return YamlLoader.load(yaml); // fail-fast on config error
    }

    @Bean
    @ConditionalOnMissingBean
    public PermissionCache permissionCache() {
        return new PermissionCache();
    }

    /** Fail-fast validation of authz.* properties (moved verbatim from AuthzAutoConfiguration). */
    static class ConfigValidator {
        ConfigValidator(AuthzProperties props) {
            if (props.getServiceIssuer() == null || props.getServiceIssuer().isBlank())
                throw new com.example.authz.config.ConfigException("authz.service-issuer must be configured");
            requireHttpUrl(props.getServiceIssuer(), "authz.service-issuer");

            if (props.getServiceJwksUri() == null || props.getServiceJwksUri().isBlank())
                throw new com.example.authz.config.ConfigException("authz.service-jwks-uri must be configured");
            requireHttpUrl(props.getServiceJwksUri(), "authz.service-jwks-uri");

            if (props.isUserAuthEnabled()) {
                if (props.getUserIssuer() == null || props.getUserIssuer().isBlank())
                    throw new com.example.authz.config.ConfigException(
                            "authz.user.issuer must be configured when user auth is enabled");
                requireHttpUrl(props.getUserIssuer(), "authz.user.issuer");

                if (props.getUserJwksUri() == null || props.getUserJwksUri().isBlank())
                    throw new com.example.authz.config.ConfigException(
                            "authz.user.jwks-uri must be configured when user auth is enabled");
                requireHttpUrl(props.getUserJwksUri(), "authz.user.jwks-uri");

                if (props.getAudience() == null || props.getAudience().isBlank())
                    throw new com.example.authz.config.ConfigException(
                            "authz.user.audience must be configured when user auth is enabled");

                if (props.getRoleServiceUrl() == null || props.getRoleServiceUrl().isBlank())
                    throw new com.example.authz.config.ConfigException(
                            "authz.role-service-url must be configured when user auth is enabled");
                requireHttpUrl(props.getRoleServiceUrl(), "authz.role-service-url");
            }

            if (props.getTokenUrl() != null && !props.getTokenUrl().isBlank()) {
                requireHttpUrl(props.getTokenUrl(), "authz.token-url");
            }
        }

        private static void requireHttpUrl(String value, String propertyName) {
            try {
                URI uri = URI.create(value);
                String scheme = uri.getScheme();
                if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
                    throw new com.example.authz.config.ConfigException(
                            propertyName + " must be a valid http/https URL, got: " + value);
                }
            } catch (IllegalArgumentException e) {
                throw new com.example.authz.config.ConfigException(
                        propertyName + " must be a valid http/https URL, got: " + value);
            }
        }
    }
}
```

- [ ] **Step 2: Do not run yet** — the old `AuthzAutoConfiguration` still defines these beans, so wait until Task 7 deletes it to avoid duplicate-bean conflicts during the move. Proceed to Task 4.

---

## Task 4: `InboundAuthAutoConfiguration` (validator, sanitizer, request context)

**Files:**
- Create: `.../autoconfigure/InboundAuthAutoConfiguration.java`

- [ ] **Step 1: Create the slice with the inbound beans moved verbatim**

```java
package com.example.authz.autoconfigure;

import com.example.authz.context.HeaderSanitizer;
import com.example.authz.spi.Spi;
import com.example.authz.web.AuthzRequestContext;
import com.example.authz.web.NimbusJwksTokenValidator;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.web.context.annotation.RequestScope;

import java.util.List;

/**
 * Inbound authentication beans: the JWKS token validator (audience + token_use),
 * the untrusted-header sanitizer, and the request-scoped authenticated context.
 */
@AutoConfiguration(after = AuthzCoreAutoConfiguration.class)
public class InboundAuthAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public Spi.TokenValidator authzTokenValidator(AuthzProperties props) {
        if (!props.isUserAuthEnabled()) {
            return NimbusJwksTokenValidator.serviceOnly(
                    props.getServiceIssuer(), props.getServiceJwksUri(),
                    props.getServiceTokenUseClaim(), props.getServiceTokenUseValue(),
                    props.getClockSkewSeconds(), props.getJwksTimeoutMs());
        }
        return new NimbusJwksTokenValidator(
                props.getUserIssuer(), props.getUserJwksUri(),
                props.getServiceIssuer(), props.getServiceJwksUri(),
                props.getAudience(), props.getServiceTokenUseClaim(), props.getServiceTokenUseValue(),
                props.getClockSkewSeconds(), props.getJwksTimeoutMs());
    }

    @Bean
    @RequestScope
    @ConditionalOnMissingBean
    public AuthzRequestContext authzRequestContext() {
        AuthzRequestContext current = AuthzRequestContext.current();
        return current != null ? current : new AuthzRequestContext(null, null);
    }

    @Bean
    @ConditionalOnMissingBean
    public HeaderSanitizer authzHeaderSanitizer(AuthzProperties props) {
        List<String> prefixes = props.getUntrustedHeaderPrefixes();
        List<String> exact = props.getUntrustedHeaderExact();
        if ((prefixes == null || prefixes.isEmpty()) && (exact == null || exact.isEmpty())) {
            return new HeaderSanitizer();
        }
        return new HeaderSanitizer(
            prefixes != null ? prefixes : List.of(),
            exact != null ? exact : List.of());
    }
}
```

---

## Task 5: `CacheSyncAutoConfiguration` (Kafka, bootstrap, health, resolver)

**Files:**
- Create: `.../autoconfigure/CacheSyncAutoConfiguration.java`

- [ ] **Step 1: Create the slice (all beans gated by `OnUserAuthEnabled`, moved verbatim)**

```java
package com.example.authz.autoconfigure;

import com.example.authz.cache.PermissionCache;
import com.example.authz.observability.AuthzHealth;
import com.example.authz.observability.Metrics;
import com.example.authz.spi.Spi;
import com.example.authz.sync.CacheBootstrap;
import com.example.authz.sync.DiskCache;
import com.example.authz.sync.HttpRoleServiceClient;
import com.example.authz.sync.KafkaCacheEventHandler;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;

import java.nio.file.Path;

/**
 * Role-permission distribution machinery (FULL mode only, §0.5): Kafka consumer,
 * the startup state machine (snapshot -> seed fallback -> subscribe -> reconcile),
 * the cache health indicator, and the default cache-backed role resolver.
 */
@AutoConfiguration(after = AuthzCoreAutoConfiguration.class)
public class CacheSyncAutoConfiguration {

    @Bean
    @Conditional(OnUserAuthEnabled.class)
    @ConditionalOnMissingBean(Spi.CacheEventHandler.class)
    public Spi.CacheEventHandler authzKafkaEventHandler(AuthzProperties props) {
        if (props.getKafkaBrokers() == null || props.getKafkaBrokers().isEmpty()) {
            return null;
        }
        return new KafkaCacheEventHandler(props.getKafkaBrokers(),
                props.getRoleUpdatesTopic(), props.getRoleDeleteTopic(),
                props.getPublishRolesTopic(), props.getKafkaGroupId(), props.getKafkaClientId());
    }

    @Bean(destroyMethod = "stop")
    @Conditional(OnUserAuthEnabled.class)
    @ConditionalOnMissingBean
    public CacheBootstrap cacheBootstrap(PermissionCache cache, Metrics metrics, AuthzProperties props,
                                         ObjectProvider<Spi.CacheEventHandler> events) {
        CacheBootstrap boot = new CacheBootstrap(
                cache,
                new HttpRoleServiceClient(
                    props.getRoleServiceUrl(),
                    props.getRoleServiceConnectTimeout(),
                    props.getRoleServiceReadTimeout()),
                new DiskCache(Path.of(props.getDiskCachePath())),
                events.getIfAvailable(),
                metrics);
        CacheBootstrap.Mode mode = boot.start();
        boot.startSeedRetry();
        boot.startReconciler(props.getReconcileIntervalMs());
        org.slf4j.LoggerFactory.getLogger(CacheSyncAutoConfiguration.class)
                .info("authz cache started in {} mode", mode);
        return boot;
    }

    @Bean
    @Conditional(OnUserAuthEnabled.class)
    @ConditionalOnMissingBean
    public AuthzHealth authzHealth(PermissionCache cache, CacheBootstrap bootstrap) {
        return new AuthzHealth(cache, bootstrap);
    }

    @Bean
    @Conditional(OnUserAuthEnabled.class)
    @ConditionalOnMissingBean
    public Spi.RoleResolver authzRoleResolver(PermissionCache cache) {
        return cache::permissionsForRole;
    }
}
```

---

## Task 6: `OutboundAutoConfiguration` and `ObservabilityAutoConfiguration`

**Files:**
- Create: `.../autoconfigure/OutboundAutoConfiguration.java`
- Create: `.../autoconfigure/ObservabilityAutoConfiguration.java`

- [ ] **Step 1: Create `OutboundAutoConfiguration` (service identity + customizers, verbatim)**

```java
package com.example.authz.autoconfigure;

import com.example.authz.observability.Metrics;
import com.example.authz.outbound.ClientCredentialsServiceIdentityProvider;
import com.example.authz.outbound.OutboundPropagationInterceptor;
import com.example.authz.spi.Spi;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.client.RestClientCustomizer;
import org.springframework.boot.web.client.RestTemplateCustomizer;
import org.springframework.context.annotation.Bean;

/**
 * Outbound identity and propagation (architecture §9/§12): OAuth2 client-credentials
 * service token (when configured) plus RestClient/RestTemplate interceptor wiring.
 */
@AutoConfiguration(after = ObservabilityAutoConfiguration.class)
public class OutboundAutoConfiguration {

    @Bean(destroyMethod = "stop")
    @ConditionalOnProperty(name = "authz.client-id")
    @ConditionalOnMissingBean(Spi.ServiceIdentityProvider.class)
    public Spi.ServiceIdentityProvider authzServiceIdentity(AuthzProperties props, Metrics metrics) {
        var provider = new ClientCredentialsServiceIdentityProvider(
            props.getTokenUrl(), props.getClientId(), props.getClientSecret(),
            (int) props.getTokenEndpointTimeoutMs())
            .onError(e -> metrics.inc(Metrics.SERVICE_TOKEN_FAILURES))
            .withMetrics(metrics);
        provider.probeTokenEndpoint();
        provider.startProactiveRefresh(props.getTokenRefreshCheckIntervalMs());
        return provider;
    }

    @Bean
    @ConditionalOnMissingBean
    public OutboundPropagationInterceptor authzOutboundInterceptor(
            ObjectProvider<Spi.ServiceIdentityProvider> serviceIdentityProvider) {
        return new OutboundPropagationInterceptor(serviceIdentityProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnBean(OutboundPropagationInterceptor.class)
    public RestClientCustomizer authzRestClientCustomizer(OutboundPropagationInterceptor interceptor) {
        return builder -> builder.requestInterceptor(interceptor);
    }

    @Bean
    @ConditionalOnBean(OutboundPropagationInterceptor.class)
    public RestTemplateCustomizer authzRestTemplateCustomizer(OutboundPropagationInterceptor interceptor) {
        return restTemplate -> restTemplate.getInterceptors().add(interceptor);
    }
}
```

- [ ] **Step 2: Create `ObservabilityAutoConfiguration` (metrics, micrometer, o11y compat, audit sink, verbatim)**

Move `authzMetrics()`, the nested `MicrometerMetricsBinding`, the nested `O11yCompatibilityBinding`, and `authzAuditSink()` here. Preserve the existing o11y ordering constraint by putting it on this slice:

```java
package com.example.authz.autoconfigure;

import com.example.authz.audit.LoggingAuditSink;
import com.example.authz.observability.Metrics;
import com.example.authz.spi.Spi;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Observability beans: the in-process Metrics registry, optional Micrometer
 * mirroring, the o11y-lib compatibility util, and the default audit sink.
 * Declared before the in-house ObservabilityAutoConfiguration so the Metrics
 * bean exists when that starter wires its registry.
 */
@AutoConfiguration(after = AuthzCoreAutoConfiguration.class,
        beforeName = "idf.hatraa.ObservabilityAutoConfiguration")
public class ObservabilityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public Metrics authzMetrics() {
        return new Metrics();
    }

    @Bean
    @ConditionalOnMissingBean
    public Spi.AuditSink authzAuditSink() {
        return new LoggingAuditSink();
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(io.micrometer.core.instrument.MeterRegistry.class)
    static class MicrometerMetricsBinding {
        @Bean
        InitializingBean authzMetricsMicrometerBinder(
                Metrics metrics,
                ObjectProvider<io.micrometer.core.instrument.MeterRegistry> registry) {
            return () -> {
                io.micrometer.core.instrument.MeterRegistry reg = registry.getIfAvailable();
                if (reg != null) {
                    java.util.concurrent.ConcurrentHashMap<String, io.micrometer.core.instrument.Counter> counters =
                            new java.util.concurrent.ConcurrentHashMap<>();
                    java.util.concurrent.ConcurrentHashMap<String, java.util.concurrent.atomic.AtomicLong> gauges =
                            new java.util.concurrent.ConcurrentHashMap<>();
                    metrics.addSink(new Metrics.Sink() {
                        @Override
                        public void incrementCounter(String name) {
                            counters.computeIfAbsent(name, reg::counter).increment();
                        }
                        @Override
                        public void setGauge(String name, long value) {
                            java.util.concurrent.atomic.AtomicLong holder = gauges.computeIfAbsent(name, k -> {
                                java.util.concurrent.atomic.AtomicLong a = new java.util.concurrent.atomic.AtomicLong();
                                io.micrometer.core.instrument.Gauge
                                        .builder(name, a, java.util.concurrent.atomic.AtomicLong::doubleValue)
                                        .register(reg);
                                return a;
                            });
                            holder.set(value);
                        }
                    });
                }
            };
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "idf.hatraa.util.ConfigurationUtil")
    static class O11yCompatibilityBinding {
        @Bean
        @ConditionalOnMissingBean
        idf.hatraa.util.ConfigurationUtil authzO11yConfigurationUtil() {
            return new idf.hatraa.util.ConfigurationUtil();
        }
    }
}
```

---

## Task 7: `WebSecurityAutoConfiguration` + delete the monolith

**Files:**
- Create: `.../autoconfigure/WebSecurityAutoConfiguration.java`
- Delete: `.../boot/AuthzAutoConfiguration.java`, `.../boot/package-info.java`

- [ ] **Step 1: Create `WebSecurityAutoConfiguration` (filter + chain + remaining SPI defaults, verbatim)**

This slice must come last (it consumes engine, cache, validator, audit, metrics, sanitizer, and touches `CacheBootstrap` for init ordering). It also carries the `PolicyEngine`/`AttributeProvider` defaults.

```java
package com.example.authz.autoconfigure;

import com.example.authz.cache.PermissionCache;
import com.example.authz.context.HeaderSanitizer;
import com.example.authz.engine.AuthorizationEngine;
import com.example.authz.observability.Metrics;
import com.example.authz.spi.Spi;
import com.example.authz.sync.CacheBootstrap;
import com.example.authz.web.AuthorizationFilter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Global enforcement: the authorization filter and the Spring Security chain that
 * installs it for every request. Ordered last so all collaborators exist.
 * AuthorizationFilter remains the single decision site (parity linchpin).
 */
@AutoConfiguration(after = {
        InboundAuthAutoConfiguration.class,
        CacheSyncAutoConfiguration.class,
        OutboundAutoConfiguration.class,
        ObservabilityAutoConfiguration.class })
public class WebSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public Spi.PolicyEngine authzPolicyEngine() {
        return null;
    }

    @Bean
    @ConditionalOnMissingBean
    public Spi.AttributeProvider authzAttributeProvider() {
        return ctx -> java.util.Map.of();
    }

    @Bean
    public AuthorizationFilter authzFilter(
            AuthorizationEngine engine, PermissionCache cache, Spi.TokenValidator validator,
            Spi.AuditSink audit, Metrics metrics, AuthzProperties props,
            ObjectProvider<CacheBootstrap> bootstrap, HeaderSanitizer headerSanitizer) {
        bootstrap.getIfAvailable(); // enforce init order: cache populated before filter serves
        return new AuthorizationFilter(engine, cache, validator, audit, metrics,
                headerSanitizer, null, null, props.isUserAuthEnabled());
    }

    @Bean
    public SecurityFilterChain authzSecurityFilterChain(HttpSecurity http,
                                                        AuthorizationFilter authzFilter) throws Exception {
        http
            .securityMatcher("/**")
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .addFilterBefore(authzFilter, UsernamePasswordAuthenticationFilter.class)
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }
}
```

- [ ] **Step 2: Delete the monolith and its package-info**

Delete `.../boot/AuthzAutoConfiguration.java` and `.../boot/package-info.java`. The `boot` package should now be empty (remove the directory).

---

## Task 8: Register the slices and repoint references

**Files:**
- Modify: `src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`
- Modify: test files importing `com.example.authz.boot.*` (from Task 1 Step 2 list)

- [ ] **Step 1: Replace the `.imports` contents with the six slices**

```
com.example.authz.autoconfigure.AuthzCoreAutoConfiguration
com.example.authz.autoconfigure.InboundAuthAutoConfiguration
com.example.authz.autoconfigure.CacheSyncAutoConfiguration
com.example.authz.autoconfigure.ObservabilityAutoConfiguration
com.example.authz.autoconfigure.OutboundAutoConfiguration
com.example.authz.autoconfigure.WebSecurityAutoConfiguration
```

- [ ] **Step 2: Repoint every test import**

For each file from Task 1 Step 2, change `com.example.authz.boot.AuthzProperties` → `com.example.authz.autoconfigure.AuthzProperties` and `com.example.authz.boot.AuthzAutoConfiguration` → the relevant slice (tests that loaded the whole config via `AutoConfigurations.of(AuthzAutoConfiguration.class)` should load `AuthzCoreAutoConfiguration.class, InboundAuthAutoConfiguration.class, CacheSyncAutoConfiguration.class, ObservabilityAutoConfiguration.class, OutboundAutoConfiguration.class, WebSecurityAutoConfiguration.class`). If `ModulesTest` asserts on the `boot` package name, update it to `autoconfigure`.

- [ ] **Step 3: Run the full suite**

Run: `tests\spring\..\scripts\mvn.ps1 -ModuleDir libraries/authz-spring-boot test`
(i.e. `tests\scripts\mvn.ps1 -ModuleDir libraries/authz-spring-boot test`)
Expected: BUILD SUCCESS, same test count as Task 1, `SharedVectorsTest` still 46 vectors green.

- [ ] **Step 4: Commit**

```powershell
git add libraries/authz-spring-boot
git commit -m "refactor(spring): split AuthzAutoConfiguration into ordered slices

Move every bean from the monolithic AuthzAutoConfiguration into six cohesive
@AutoConfiguration classes under com.example.authz.autoconfigure (Core,
InboundAuth, CacheSync, Outbound, Observability, WebSecurity) with explicit
ordering. Behavior unchanged; all unit tests and the 46 shared vectors pass.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 9: Verify the e2e parity gate (Spring side)

**Files:** none (verification only)

- [ ] **Step 1: Build the spring-demo against the sliced config**

Run: `tests\scripts\mvn.ps1 -ModuleDir tests/demo-services/spring-demo -q -DskipTests package`
Expected: BUILD SUCCESS — the demo resolves all six slices from the `.imports` file with no code change.

- [ ] **Step 2: Run the full cross-language e2e (nestjs-demo still Express here — unaffected)**

Run (from `tests/e2e`): `docker compose up --build -d; node run.mjs; docker compose down -v`
Expected: all matrix scenarios pass for both languages with identical outcomes. This confirms the Spring restructure changed no decision.

- [ ] **Step 3: Commit any demo build adjustments only if needed** (none expected).

---

## Self-Review

- **Spec coverage:** Six slices (✓ spec table), `autoconfigure` package move (✓), `.imports` ordering (✓), `AuthorizationFilter` stays single decision site (✓ Task 7 note), `@ConditionalOnMissingBean` preserved on every overridable bean (✓), o11y `beforeName` constraint preserved (✓ Task 6 Step 2), vectors + e2e gate (✓ Tasks 8–9).
- **Placeholder scan:** none — every bean body is reproduced verbatim from the source.
- **Type consistency:** bean names unchanged (`authzMetrics`, `authzFilter`, `cacheBootstrap`, …); `OnUserAuthEnabled` is now a public top-level class referenced by `@Conditional(OnUserAuthEnabled.class)` in CacheSync.
