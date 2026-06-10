package com.example.authz.boot;

import com.example.authz.audit.LoggingAuditSink;
import com.example.authz.cache.PermissionCache;
import com.example.authz.config.YamlLoader;
import com.example.authz.context.HeaderSanitizer;
import com.example.authz.engine.AuthorizationEngine;
import com.example.authz.observability.AuthzHealth;
import com.example.authz.observability.Metrics;
import com.example.authz.outbound.ClientCredentialsServiceIdentityProvider;
import com.example.authz.outbound.OutboundPropagationInterceptor;
import com.example.authz.spi.Spi;
import com.example.authz.sync.CacheBootstrap;
import com.example.authz.sync.DiskCache;
import com.example.authz.sync.HttpRoleServiceClient;
import com.example.authz.sync.KafkaCacheEventHandler;
import com.example.authz.web.AuthorizationFilter;
import com.example.authz.web.AuthzRequestContext;
import com.example.authz.web.NimbusJwksTokenValidator;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestClientCustomizer;
import org.springframework.boot.web.client.RestTemplateCustomizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.io.Resource;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.web.context.annotation.RequestScope;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

/**
 * Auto-configures the authorization library from `authz.*` properties: decision
 * engine, permission cache (startup state machine + Kafka + reconciler), JWKS
 * token validator (audience + token_use), metrics, health, audit sink, optional
 * outbound identity provider, and the global enforcement filter. Every bean is
 * @ConditionalOnMissingBean so an app can override any of them.
 */
@AutoConfiguration(beforeName = "idf.hatraa.ObservabilityAutoConfiguration")
@EnableConfigurationProperties(AuthzProperties.class)
public class AuthzAutoConfiguration {

    @Bean
    ConfigValidator authzConfigValidator(AuthzProperties props) {
        return new ConfigValidator(props);
    }

    /**
     * Matches when user auth is enabled (FULL mode, §0.5). Gates the entire
     * role-permission machinery (cache bootstrap, Kafka consumer, reconciler,
     * health, role resolver) so it is absent in SERVICE-ONLY mode. Binds the
     * {@code authz.*} properties from the environment (relaxed binding) and
     * delegates to {@link AuthzProperties#isUserAuthEnabled()}.
     */
    static class OnUserAuthEnabled implements Condition {
        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            AuthzProperties p = Binder.get(context.getEnvironment())
                    .bind("authz", AuthzProperties.class)
                    .orElseGet(AuthzProperties::new);
            return p.isUserAuthEnabled();
        }
    }

    static class ConfigValidator {
        ConfigValidator(AuthzProperties props) {
            // Service auth is ALWAYS required (both modes).
            if (props.getServiceIssuer() == null || props.getServiceIssuer().isBlank())
                throw new com.example.authz.config.ConfigException("authz.service-issuer must be configured");
            requireHttpUrl(props.getServiceIssuer(), "authz.service-issuer");

            if (props.getServiceJwksUri() == null || props.getServiceJwksUri().isBlank())
                throw new com.example.authz.config.ConfigException("authz.service-jwks-uri must be configured");
            requireHttpUrl(props.getServiceJwksUri(), "authz.service-jwks-uri");

            // User auth is OPTIONAL and all-or-nothing (§0.5, §3.3). When any
            // user-auth field is present, every required field must be present.
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

            // tokenUrl is optional — validate only when present (Q4)
            if (props.getTokenUrl() != null && !props.getTokenUrl().isBlank()) {
                requireHttpUrl(props.getTokenUrl(), "authz.token-url");
            }
        }

        /**
         * Parses the value as a URI and asserts it has an http or https scheme.
         * Throws {@link com.example.authz.config.ConfigException} on any parse
         * error or non-http/https scheme — consistent with fail-fast startup style.
         */
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

    @Bean
    @ConditionalOnMissingBean
    public Metrics authzMetrics() {
        return new Metrics();
    }

    /**
     * Mirrors the authz {@link Metrics} counters/gauges onto a Micrometer
     * {@code MeterRegistry} when one is present (e.g. brought by the in-house
     * o11y starter or Spring Boot Actuator), so they appear on the Prometheus
     * scrape endpoint. Guarded by {@code @ConditionalOnClass} so consumers
     * without Micrometer are unaffected — the registry types are only loaded
     * when this nested config is processed.
     */
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

    /**
     * o11y-lib's auto-configuration expects this utility bean but the library
     * declares it as a component outside the consuming application's scan path.
     * Provide it when o11y-lib is present so local-only consumers do not need to
     * add an extra component scan.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "idf.hatraa.util.ConfigurationUtil")
    static class O11yCompatibilityBinding {
        @Bean
        @ConditionalOnMissingBean
        idf.hatraa.util.ConfigurationUtil authzO11yConfigurationUtil() {
            return new idf.hatraa.util.ConfigurationUtil();
        }
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

    /** Kafka consumer for incremental role events (only in FULL mode, when brokers configured). */
    @Bean
    @Conditional(OnUserAuthEnabled.class)
    @ConditionalOnMissingBean(Spi.CacheEventHandler.class)
    public Spi.CacheEventHandler authzKafkaEventHandler(AuthzProperties props) {
        if (props.getKafkaBrokers() == null || props.getKafkaBrokers().isEmpty()) {
            return null; // no Kafka configured -> snapshot + reconciler only
        }
        return new KafkaCacheEventHandler(props.getKafkaBrokers(),
                props.getRoleUpdatesTopic(), props.getRoleDeleteTopic(),
                props.getPublishRolesTopic(), props.getKafkaGroupId(), props.getKafkaClientId());
    }

    /** Startup state machine: snapshot -> seed fallback -> subscribe -> reconcile (FULL mode only). */
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
        CacheBootstrap.Mode mode = boot.start(); // snapshot, else seed from disk
        boot.startSeedRetry(); // 2s/4s/8s backoff until SEED→NORMAL
        boot.startReconciler(props.getReconcileIntervalMs());
        org.slf4j.LoggerFactory.getLogger(AuthzAutoConfiguration.class)
                .info("authz cache started in {} mode", mode);
        return boot;
    }

    /** Cache health indicator (FULL mode only — §10.3). */
    @Bean
    @Conditional(OnUserAuthEnabled.class)
    @ConditionalOnMissingBean
    public AuthzHealth authzHealth(PermissionCache cache, CacheBootstrap bootstrap) {
        return new AuthzHealth(cache, bootstrap);
    }

    @Bean
    @ConditionalOnMissingBean
    public Spi.TokenValidator authzTokenValidator(AuthzProperties props) {
        if (!props.isUserAuthEnabled()) {
            // SERVICE-ONLY mode (§0.5): no user-JWT decoder, no audience requirement.
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

    /** Request-scoped view of the authenticated context (architecture §12.1). */
    @Bean
    @RequestScope
    @ConditionalOnMissingBean
    public AuthzRequestContext authzRequestContext() {
        AuthzRequestContext current = AuthzRequestContext.current();
        return current != null ? current : new AuthzRequestContext(null, null);
    }

    @Bean
    @ConditionalOnMissingBean
    public Spi.AuditSink authzAuditSink() {
        return new LoggingAuditSink();
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

    /** Outbound identity (only when client credentials are configured). */
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
        // Start the background proactive-refresh scheduler so the token is
        // refreshed at ~70% of its lifetime (parity with NestJS, which arms a
        // proactive timer on every acquisition). destroyMethod="stop" shuts the
        // scheduler down cleanly on context close.
        provider.startProactiveRefresh(props.getTokenRefreshCheckIntervalMs());
        return provider;
    }

    /**
     * Outbound auto-propagation (architecture §9/§12): registered only when an
     * outbound identity exists. Customizers add the interceptor to app-built
     * {@code RestClient} and {@code RestTemplate} instances.
     */
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

    /** Role resolver (FULL mode only — §11). */
    @Bean
    @Conditional(OnUserAuthEnabled.class)
    @ConditionalOnMissingBean
    public Spi.RoleResolver authzRoleResolver(PermissionCache cache) {
        return cache::permissionsForRole;
    }

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
        // Touch the bootstrap (FULL mode only) to enforce init order: the cache is
        // populated before the filter serves. Absent in SERVICE-ONLY mode.
        bootstrap.getIfAvailable();
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
