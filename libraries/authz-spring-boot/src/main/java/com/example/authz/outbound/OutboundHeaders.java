package com.example.authz.outbound;

import com.example.authz.context.RequestContext;
import com.example.authz.spi.Spi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds the headers to attach to an outbound call (architecture §9): propagate
 * the user JWT (if the inbound request had one), conditionally attach a fresh service
 * token (if a provider is available and acquisition succeeds), and forward the
 * correlation/request ids. Mirrors the NestJS buildOutboundHeaders.
 *
 * <p>Gap F4/G5: {@code X-Service-Token} is only attached when a
 * {@link Spi.ServiceIdentityProvider} is present and returns a token successfully.
 * Callers that have no service identity configured simply omit the header.
 *
 * <p>Gap G4: if the provider throws (e.g. SSO unreachable after retries), the error
 * is logged as a warning and the header is omitted rather than propagating the
 * exception. Downstream still receives the user JWT and correlation ids.
 *
 * <p>Gap G14: passing {@code null} for {@code serviceIdentity} is legal — user JWT
 * and correlation id propagation proceeds without any service-token header.
 */
public final class OutboundHeaders {
    private static final Logger log = LoggerFactory.getLogger(OutboundHeaders.class);

    private OutboundHeaders() {}

    /**
     * Builds outbound propagation headers.
     *
     * @param ctx             the current request context (provides correlation/request ids)
     * @param userJwt         the raw user JWT from the inbound request, or {@code null}
     * @param serviceIdentity the service identity provider, or {@code null} when not configured
     * @return mutable map of headers to attach; never {@code null}
     */
    public static Map<String, String> build(RequestContext ctx, String userJwt,
                                            Spi.ServiceIdentityProvider serviceIdentity) {
        Map<String, String> headers = new LinkedHashMap<>();

        // User JWT propagation (works even with no service identity — gap G14).
        if (userJwt != null && !userJwt.isBlank()) {
            headers.put("Authorization", "Bearer " + userJwt);
        }

        // X-Service-Token: conditional on provider availability and successful acquisition.
        // Fail-open on acquisition error — gaps F4 / G5 / G4.
        if (serviceIdentity != null) {
            try {
                String token = serviceIdentity.getServiceToken();
                if (token != null && !token.isBlank()) {
                    headers.put("X-Service-Token", token);
                }
            } catch (Exception e) {
                log.warn("authz: service token acquisition failed for outbound call (fail-open, " +
                        "X-Service-Token omitted): {}", e.getMessage());
            }
        }

        headers.put("X-Correlation-Id", ctx.correlationId());
        headers.put("X-Request-Id", ctx.requestId());
        return headers;
    }
}
