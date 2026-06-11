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
