package com.example.authz.web;

import com.example.authz.config.ConfigException;
import com.example.authz.spi.Spi;
import idf.hatraa.annotation.Span;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * JWKS-backed token validator using Spring Security's NimbusJwtDecoder.
 *
 * <p>User tokens: algorithm (RS256/ES256 only, alg:none rejected) + signature
 * (against the Auth Service's JWKS) + issuer + audience (MANDATORY — a blank
 * {@code audience} is rejected at construction time as a configuration error) +
 * expiration + not-before (§2.2).
 *
 * <p>Service tokens: algorithm + signature (against SSO JWKS) + issuer +
 * expiration + not-before + configurable {@code token_use} claim (§2.3, always
 * enforced — a blank {@code serviceTokenUseClaim} defaults to {@code "token_use"}).
 *
 * <p>JWKS fetches (initial load and unknown-{@code kid} refresh) use an HTTP
 * client with an explicit connect+read timeout ({@code jwksTimeoutMs}, default
 * 5000ms) so a slow/hung JWKS endpoint cannot block token validation on the
 * request path indefinitely — a JWKS that does not respond within the timeout
 * fails validation closed (the request is denied), with no silent per-request
 * retry on the hot path. Matches the NestJS validator's configurable timeout.
 */
public class NimbusJwksTokenValidator implements Spi.TokenValidator {

    /** Pinned allow-list matching NestJS defaults (§2.2, B2/G2). */
    private static final SignatureAlgorithm[] ALLOWED_ALGORITHMS = {
            SignatureAlgorithm.RS256, SignatureAlgorithm.ES256
    };

    private final JwtDecoder userDecoder;
    private final JwtDecoder serviceDecoder;
    private final String serviceTokenUseClaim;
    private final String serviceTokenUseValue;

    /** Default JWKS fetch timeout (ms) when not specified. */
    private static final long DEFAULT_JWKS_TIMEOUT_MS = 5000;

    public NimbusJwksTokenValidator(String userIssuer, String userJwksUri,
                                    String serviceIssuer, String serviceJwksUri,
                                    String audience, String serviceTokenUseClaim,
                                    String serviceTokenUseValue) {
        this(userIssuer, userJwksUri, serviceIssuer, serviceJwksUri,
                audience, serviceTokenUseClaim, serviceTokenUseValue, 5);
    }

    public NimbusJwksTokenValidator(String userIssuer, String userJwksUri,
                                    String serviceIssuer, String serviceJwksUri,
                                    String audience, String serviceTokenUseClaim,
                                    String serviceTokenUseValue, long clockSkewSeconds) {
        this(userIssuer, userJwksUri, serviceIssuer, serviceJwksUri,
                audience, serviceTokenUseClaim, serviceTokenUseValue, clockSkewSeconds,
                DEFAULT_JWKS_TIMEOUT_MS);
    }

    /**
     * SERVICE-ONLY mode factory (§0.5): builds a validator that verifies service
     * tokens only. There is no user-JWT decoder and audience is not required;
     * {@link #validateUserToken(String)} is never called because the filter
     * ignores the {@code Authorization} header in service-only mode.
     */
    public static NimbusJwksTokenValidator serviceOnly(
            String serviceIssuer, String serviceJwksUri,
            String serviceTokenUseClaim, String serviceTokenUseValue,
            long clockSkewSeconds, long jwksTimeoutMs) {
        return new NimbusJwksTokenValidator(serviceIssuer, serviceJwksUri,
                serviceTokenUseClaim, serviceTokenUseValue, clockSkewSeconds, jwksTimeoutMs);
    }

    /** Service-only constructor: no user decoder, no audience requirement. */
    private NimbusJwksTokenValidator(String serviceIssuer, String serviceJwksUri,
                                     String serviceTokenUseClaim, String serviceTokenUseValue,
                                     long clockSkewSeconds, long jwksTimeoutMs) {
        String effectiveClaim = (serviceTokenUseClaim == null || serviceTokenUseClaim.isBlank())
                ? "token_use"
                : serviceTokenUseClaim;
        Duration skew = Duration.ofSeconds(clockSkewSeconds);
        RestOperations jwksHttp = jwksRestOperations(jwksTimeoutMs);
        this.userDecoder = null;
        this.serviceDecoder = serviceDecoder(serviceJwksUri, serviceIssuer, skew, jwksHttp);
        this.serviceTokenUseClaim = effectiveClaim;
        this.serviceTokenUseValue = serviceTokenUseValue;
    }

    public NimbusJwksTokenValidator(String userIssuer, String userJwksUri,
                                    String serviceIssuer, String serviceJwksUri,
                                    String audience, String serviceTokenUseClaim,
                                    String serviceTokenUseValue, long clockSkewSeconds,
                                    long jwksTimeoutMs) {
        // A4/G1: audience is required — fail fast at construction time
        if (audience == null || audience.isBlank()) {
            throw new ConfigException(
                    "authz.audience must be configured: audience validation is mandatory " +
                    "and cannot be skipped. Set authz.audience to the expected JWT audience value.");
        }
        // C7/G3: blank serviceTokenUseClaim defaults to "token_use" so the check is always enforced
        String effectiveClaim = (serviceTokenUseClaim == null || serviceTokenUseClaim.isBlank())
                ? "token_use"
                : serviceTokenUseClaim;

        Duration skew = Duration.ofSeconds(clockSkewSeconds);
        RestOperations jwksHttp = jwksRestOperations(jwksTimeoutMs);
        this.userDecoder = userDecoder(userJwksUri, userIssuer, audience, skew, jwksHttp);
        this.serviceDecoder = serviceDecoder(serviceJwksUri, serviceIssuer, skew, jwksHttp);
        this.serviceTokenUseClaim = effectiveClaim;
        this.serviceTokenUseValue = serviceTokenUseValue;
    }

    /**
     * HTTP client used to fetch JWKS, with an explicit connect+read timeout so a
     * slow/hung JWKS endpoint cannot hang token validation on the request path.
     */
    private static RestOperations jwksRestOperations(long timeoutMs) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        int t = (int) Math.max(1, timeoutMs);
        factory.setConnectTimeout(t);
        factory.setReadTimeout(t);
        return new RestTemplate(factory);
    }

    /**
     * Build a decoder pinned to RS256/ES256, with issuer + audience + exp + nbf validators.
     */
    private static NimbusJwtDecoder userDecoder(String jwksUri, String issuer,
                                                String audience, Duration skew,
                                                RestOperations jwksHttp) {
        // B2/G2: pin to the safe allow-list; NimbusJwtDecoder rejects any other alg header
        NimbusJwtDecoder d = NimbusJwtDecoder.withJwkSetUri(jwksUri)
                .jwsAlgorithm(ALLOWED_ALGORITHMS[0])
                .jwsAlgorithm(ALLOWED_ALGORITHMS[1])
                .restOperations(jwksHttp)
                .build();

        OAuth2TokenValidator<Jwt> timestamps = new JwtTimestampValidator(skew);
        OAuth2TokenValidator<Jwt> nbf = new NbfValidator(skew);
        OAuth2TokenValidator<Jwt> iss = new JwtIssuerValidator(issuer);
        // A4/G1: audience validator is always added (audience guaranteed non-blank by constructor)
        OAuth2TokenValidator<Jwt> aud = new JwtClaimValidator<List<String>>(
                "aud", a -> a != null && a.contains(audience));

        d.setJwtValidator(new DelegatingOAuth2TokenValidator<>(timestamps, nbf, iss, aud));
        return d;
    }

    /**
     * Build a decoder pinned to RS256/ES256, with issuer + exp + nbf validators.
     * No audience check for service tokens (§2.3).
     */
    private static NimbusJwtDecoder serviceDecoder(String jwksUri, String issuer, Duration skew,
                                                   RestOperations jwksHttp) {
        NimbusJwtDecoder d = NimbusJwtDecoder.withJwkSetUri(jwksUri)
                .jwsAlgorithm(ALLOWED_ALGORITHMS[0])
                .jwsAlgorithm(ALLOWED_ALGORITHMS[1])
                .restOperations(jwksHttp)
                .build();
        d.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(skew), new NbfValidator(skew), new JwtIssuerValidator(issuer)));
        return d;
    }

    @Override
    @Span(name = "authz.validate_user_token")
    public Map<String, Object> validateUserToken(String jwt) {
        if (userDecoder == null) {
            throw new IllegalStateException("user auth is disabled (service-only mode)");
        }
        try {
            return userDecoder.decode(jwt).getClaims();
        } catch (JwtException e) {
            // G12: preserve the original exception as the cause with a descriptive message
            throw new RuntimeException("invalid user token: " + e.getMessage(), e);
        }
    }

    @Override
    @Span(name = "authz.validate_service_token")
    public Map<String, Object> validateServiceToken(String jwt) {
        try {
            Map<String, Object> claims = serviceDecoder.decode(jwt).getClaims();
            // C7/G3: token_use check is ALWAYS enforced (serviceTokenUseClaim is never blank here)
            if (!serviceTokenUseValue.equals(String.valueOf(claims.get(serviceTokenUseClaim)))) {
                throw new RuntimeException("service token rejected: claim \"" + serviceTokenUseClaim
                        + "\" must equal \"" + serviceTokenUseValue + "\" but was \""
                        + claims.get(serviceTokenUseClaim) + "\"");
            }
            return claims;
        } catch (JwtException e) {
            // G12: preserve the original exception as the cause with a descriptive message
            throw new RuntimeException("invalid service token: " + e.getMessage(), e);
        }
    }

    // -------------------------------------------------------------------------
    // A6 — nbf (not-before) validator
    // -------------------------------------------------------------------------

    /**
     * Validates the {@code nbf} (not-before) claim with clock-skew tolerance (§2.2/A6).
     *
     * <p>Spring Security's {@link JwtTimestampValidator} only validates {@code exp}.
     * This validator ensures that a token whose {@code nbf} is more than {@code skew}
     * seconds in the future is rejected. Tokens without an {@code nbf} claim pass
     * (the claim is optional per RFC 7519 §4.1.5).
     */
    private static final class NbfValidator implements OAuth2TokenValidator<Jwt> {

        private final Duration clockSkew;

        NbfValidator(Duration clockSkew) {
            this.clockSkew = clockSkew;
        }

        @Override
        public OAuth2TokenValidatorResult validate(Jwt jwt) {
            Instant nbf = jwt.getNotBefore();
            if (nbf == null) {
                // nbf is optional; absence means "valid now"
                return OAuth2TokenValidatorResult.success();
            }
            Instant now = Clock.systemUTC().instant();
            // Token is not yet valid if nbf - skew > now
            if (nbf.minus(clockSkew).isAfter(now)) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                        "invalid_token",
                        "Token is not yet valid: nbf=" + nbf + " (clock skew=" + clockSkew + ")",
                        null));
            }
            return OAuth2TokenValidatorResult.success();
        }
    }
}
