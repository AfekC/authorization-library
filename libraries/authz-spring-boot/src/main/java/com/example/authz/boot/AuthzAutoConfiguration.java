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
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
import org.springframework.core.io.Resource;
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
@AutoConfiguration
@EnableConfigurationProperties(AuthzProperties.class)
public class AuthzAutoConfiguration {

    @Bean
    ConfigValidator authzConfigValidator(AuthzProperties props) {
        return new ConfigValidator(props);
    }

    static class ConfigValidator {
        ConfigValidator(AuthzProperties props) {
            // Each property: presence check first (existing style), then Q4 URL well-formedness.
            // Pairing them keeps the error message consistent with the property that failed.
            if (props.getUserIssuer() == null || props.getUserIssuer().isBlank())
                throw new com.example.authz.config.ConfigException("authz.user-issuer must be configured");
            requireHttpUrl(props.getUserIssuer(), "authz.user-issuer");

            if (props.getUserJwksUri() == null || props.getUserJwksUri().isBlank())
                throw new com.example.authz.config.ConfigException("authz.user-jwks-uri must be configured");
            requireHttpUrl(props.getUserJwksUri(), "authz.user-jwks-uri");

            if (props.getServiceIssuer() == null || props.getServiceIssuer().isBlank())
                throw new com.example.authz.config.ConfigException("authz.service-issuer must be configured");
            requireHttpUrl(props.getServiceIssuer(), "authz.service-issuer");

            if (props.getServiceJwksUri() == null || props.getServiceJwksUri().isBlank())
                throw new com.example.authz.config.ConfigException("authz.service-jwks-uri must be configured");
            requireHttpUrl(props.getServiceJwksUri(), "authz.service-jwks-uri");

            if (props.getRoleServiceUrl() == null || props.getRoleServiceUrl().isBlank())
                throw new com.example.authz.config.ConfigException("authz.role-service-url must be configured");
            requireHttpUrl(props.getRoleServiceUrl(), "authz.role-service-url");

            if (props.getAudience() == null || props.getAudience().isBlank())
                throw new com.example.authz.config.ConfigException("authz.audience must be configured");

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

    /** Kafka consumer for incremental role events (only when brokers configured). */
    @Bean
    @ConditionalOnMissingBean(Spi.CacheEventHandler.class)
    public Spi.CacheEventHandler authzKafkaEventHandler(AuthzProperties props) {
        if (props.getKafkaBrokers() == null || props.getKafkaBrokers().isEmpty()) {
            return null; // no Kafka configured -> snapshot + reconciler only
        }
        return new KafkaCacheEventHandler(props.getKafkaBrokers(),
                props.getRoleUpdatesTopic(), props.getRoleDeleteTopic(),
                props.getPublishRolesTopic(), props.getKafkaGroupId(), props.getKafkaClientId());
    }

    /** Startup state machine: snapshot -> seed fallback -> subscribe -> reconcile. */
    @Bean
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
        boot.startReconciler(props.getReconcileIntervalMs());
        org.slf4j.LoggerFactory.getLogger(AuthzAutoConfiguration.class)
                .info("authz cache started in {} mode (v{})", mode, cache.version());
        return boot;
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthzHealth authzHealth(PermissionCache cache, CacheBootstrap bootstrap) {
        return new AuthzHealth(cache, bootstrap);
    }

    @Bean
    @ConditionalOnMissingBean
    public Spi.TokenValidator authzTokenValidator(AuthzProperties props) {
        return new NimbusJwksTokenValidator(
                props.getUserIssuer(), props.getUserJwksUri(),
                props.getServiceIssuer(), props.getServiceJwksUri(),
                props.getAudience(), props.getServiceTokenUseClaim(), props.getServiceTokenUseValue(),
                props.getClockSkewSeconds());
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
    @Bean
    @ConditionalOnProperty(name = "authz.client-id")
    @ConditionalOnMissingBean(Spi.ServiceIdentityProvider.class)
    public Spi.ServiceIdentityProvider authzServiceIdentity(AuthzProperties props, Metrics metrics) {
        var provider = new ClientCredentialsServiceIdentityProvider(
                props.getTokenUrl(), props.getClientId(), props.getClientSecret(),
                (int) props.getTokenEndpointTimeoutMs())
                .onError(e -> metrics.inc(Metrics.SERVICE_TOKEN_FAILURES));
        provider.probeTokenEndpoint();
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

    @Bean
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
            Spi.AuditSink audit, Metrics metrics, CacheBootstrap bootstrap) {
        // bootstrap param enforces init order: cache is populated before serving.
        return new AuthorizationFilter(engine, cache, validator, audit, metrics);
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
