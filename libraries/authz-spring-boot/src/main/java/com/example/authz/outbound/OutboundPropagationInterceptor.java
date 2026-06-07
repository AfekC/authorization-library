package com.example.authz.outbound;

import com.example.authz.spi.Spi;
import com.example.authz.web.AuthzRequestContext;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import java.io.IOException;
import java.util.Map;

/**
 * Auto-propagation for outbound calls made while handling an authorized request
 * (architecture §9/§12): attaches the user JWT, a fresh service token (when available),
 * and the correlation/request ids via {@link OutboundHeaders}. Works for both
 * {@code RestTemplate} and {@code RestClient} (both use this interceptor type).
 * Headers already present on the outgoing request are preserved. No-op outside an
 * authorized request.
 *
 * <p>Gap G14: {@code serviceIdentity} may be {@code null} (e.g. when {@code authz.client-id}
 * is not configured and {@code AuthzAutoConfiguration} does not create the provider bean).
 * In that case the interceptor still propagates the user JWT and correlation ids — only
 * {@code X-Service-Token} is omitted. The decoupling of the interceptor bean from the
 * {@code @ConditionalOnProperty(authz.client-id)} guard is DEFERRED to the controller
 * to wire in AuthzAutoConfiguration.
 *
 * <p>Gap G4: service token acquisition failures are handled fail-open inside
 * {@link OutboundHeaders#build} — the interceptor itself never throws due to token issues.
 */
public class OutboundPropagationInterceptor implements ClientHttpRequestInterceptor {

    /** May be null when no client-id is configured (gap G14). */
    private final Spi.ServiceIdentityProvider serviceIdentity;

    /**
     * Creates an interceptor with a service identity provider.
     * Pass {@code null} to propagate only user JWT + correlation ids (gap G14).
     */
    public OutboundPropagationInterceptor(Spi.ServiceIdentityProvider serviceIdentity) {
        this.serviceIdentity = serviceIdentity;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body,
                                        ClientHttpRequestExecution execution) throws IOException {
        AuthzRequestContext current = AuthzRequestContext.current();
        if (current != null && current.context() != null) {
            // serviceIdentity may be null — OutboundHeaders handles that case (G14 / G4).
            Map<String, String> headers =
                    OutboundHeaders.build(current.context(), current.userJwt(), serviceIdentity);
            headers.forEach((name, value) -> {
                if (!request.getHeaders().containsKey(name)) request.getHeaders().add(name, value);
            });
        }
        return execution.execute(request, body);
    }
}
