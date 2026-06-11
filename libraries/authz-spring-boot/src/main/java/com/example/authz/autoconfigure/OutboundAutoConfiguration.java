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
