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

            // Explicit SERVICE-ONLY mode is mutually exclusive with any user-auth config.
            if (props.isServiceOnly()) {
                boolean anyUserAuth = notBlank(props.getUserIssuer()) || notBlank(props.getUserJwksUri())
                        || notBlank(props.getAudience()) || notBlank(props.getRoleServiceUrl())
                        || props.isExternalPermissionSource();
                if (anyUserAuth)
                    throw new com.example.authz.config.ConfigException(
                            "authz.service-only cannot be combined with user-auth properties or authz.external-permission-source");
            }

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

                // External-source mode (§0.5b) owns its own permission lookups, so
                // the Role Service URL is unused and not required.
                if (!props.isExternalPermissionSource()) {
                    if (props.getRoleServiceUrl() == null || props.getRoleServiceUrl().isBlank())
                        throw new com.example.authz.config.ConfigException(
                                "authz.role-service-url must be configured when user auth is enabled");
                    requireHttpUrl(props.getRoleServiceUrl(), "authz.role-service-url");
                }
            }

            if (props.getTokenUrl() != null && !props.getTokenUrl().isBlank()) {
                requireHttpUrl(props.getTokenUrl(), "authz.token-url");
            }
        }

        private static boolean notBlank(String s) { return s != null && !s.isBlank(); }

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
