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
