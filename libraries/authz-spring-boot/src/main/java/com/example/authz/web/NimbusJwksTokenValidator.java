package com.example.authz.web;

import com.example.authz.config.ConfigException;
import com.example.authz.spi.Spi;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.JWSVerifierFactory;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.*;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * JWKS-backed token validator using Spring Security's NimbusJwtDecoder.
 *
 * <p>User tokens: algorithm (EdDSA/Ed25519 only, alg:none rejected) + signature
 * (against the Auth Service's JWKS) + issuer + audience (MANDATORY — a blank
 * {@code audience} is rejected at construction time as a configuration error) +
 * expiration + not-before (§2.2).
 *
 * <p>Service tokens: algorithm (EdDSA/Ed25519 only) + signature (against SSO
 * JWKS) + issuer + expiration + not-before + configurable {@code token_use} claim
 * (§2.3, always enforced — a blank {@code serviceTokenUseClaim} defaults to
 * {@code "token_use"}) + optional audience check (off by default; enabled by
 * supplying a non-blank {@code serviceTokenAudience} via
 * {@code authz.service-token-audience}).
 *
 * <p>Algorithm pinning: the JWKS JWKSource is configured with
 * {@link JWSAlgorithmFamilyJWSKeySelector} using {@link JWSAlgorithm.Family#ED}
 * so only OKP/Ed25519 EdDSA keys are accepted. RS256 and ES256 are explicitly
 * dropped — the provider re-platformed to Ed25519 (T1).
 *
 * <p>JWKS fetches (initial load and unknown-{@code kid} refresh) use an HTTP
 * client with an explicit connect+read timeout ({@code jwksTimeoutMs}, default
 * 5000ms) so a slow/hung JWKS endpoint cannot block token validation on the
 * request path indefinitely — a JWKS that does not respond within the timeout
 * fails validation closed (the request is denied), with no silent per-request
 * retry on the hot path. Matches the NestJS validator's configurable timeout.
 */
public class NimbusJwksTokenValidator implements Spi.TokenValidator {

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

    public NimbusJwksTokenValidator(String userIssuer, String userJwksUri,
                                    String serviceIssuer, String serviceJwksUri,
                                    String audience, String serviceTokenUseClaim,
                                    String serviceTokenUseValue, long clockSkewSeconds,
                                    long jwksTimeoutMs) {
        this(userIssuer, userJwksUri, serviceIssuer, serviceJwksUri,
                audience, serviceTokenUseClaim, serviceTokenUseValue, clockSkewSeconds,
                jwksTimeoutMs, null);
    }

    /**
     * Full constructor with optional service-token audience (T5).
     *
     * @param serviceTokenAudience when non-blank, the service-token decoder additionally
     *                             enforces that the {@code aud} claim contains this value;
     *                             {@code null} or blank disables the check (default / off).
     */
    public NimbusJwksTokenValidator(String userIssuer, String userJwksUri,
                                    String serviceIssuer, String serviceJwksUri,
                                    String audience, String serviceTokenUseClaim,
                                    String serviceTokenUseValue, long clockSkewSeconds,
                                    long jwksTimeoutMs, String serviceTokenAudience) {
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
        this.userDecoder = userDecoder(userJwksUri, userIssuer, audience, skew, jwksTimeoutMs);
        // T5: build service decoder with optional audience enforcement
        boolean hasServiceAud = serviceTokenAudience != null && !serviceTokenAudience.isBlank();
        this.serviceDecoder = hasServiceAud
                ? serviceDecoder(serviceJwksUri, serviceIssuer, serviceTokenAudience, skew, jwksTimeoutMs)
                : serviceDecoder(serviceJwksUri, serviceIssuer, skew, jwksTimeoutMs);
        this.serviceTokenUseClaim = effectiveClaim;
        this.serviceTokenUseValue = serviceTokenUseValue;
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
        return serviceOnly(serviceIssuer, serviceJwksUri,
                serviceTokenUseClaim, serviceTokenUseValue,
                clockSkewSeconds, jwksTimeoutMs, null);
    }

    /**
     * SERVICE-ONLY mode factory with optional service-token audience (T5).
     */
    public static NimbusJwksTokenValidator serviceOnly(
            String serviceIssuer, String serviceJwksUri,
            String serviceTokenUseClaim, String serviceTokenUseValue,
            long clockSkewSeconds, long jwksTimeoutMs, String serviceTokenAudience) {
        return new NimbusJwksTokenValidator(serviceIssuer, serviceJwksUri,
                serviceTokenUseClaim, serviceTokenUseValue,
                clockSkewSeconds, jwksTimeoutMs, serviceTokenAudience);
    }

    /** Service-only constructor: no user decoder, no user-audience requirement. */
    private NimbusJwksTokenValidator(String serviceIssuer, String serviceJwksUri,
                                     String serviceTokenUseClaim, String serviceTokenUseValue,
                                     long clockSkewSeconds, long jwksTimeoutMs,
                                     String serviceTokenAudience) {
        String effectiveClaim = (serviceTokenUseClaim == null || serviceTokenUseClaim.isBlank())
                ? "token_use"
                : serviceTokenUseClaim;
        Duration skew = Duration.ofSeconds(clockSkewSeconds);
        this.userDecoder = null;
        boolean hasServiceAud = serviceTokenAudience != null && !serviceTokenAudience.isBlank();
        this.serviceDecoder = hasServiceAud
                ? serviceDecoder(serviceJwksUri, serviceIssuer, serviceTokenAudience, skew, jwksTimeoutMs)
                : serviceDecoder(serviceJwksUri, serviceIssuer, skew, jwksTimeoutMs);
        this.serviceTokenUseClaim = effectiveClaim;
        this.serviceTokenUseValue = serviceTokenUseValue;
    }

    // -------------------------------------------------------------------------
    // Decoder builders — use Nimbus DefaultJWTProcessor directly so EdDSA (OKP)
    // keys can be selected, bypassing Spring Security's SignatureAlgorithm enum
    // which covers RSA/EC families only.
    // -------------------------------------------------------------------------

    /**
     * Build a user-token decoder with issuer + audience + exp + nbf validators.
     * Verification is generic (see {@link #decoder}): the provider signs user
     * tokens EdDSA today, but the algorithm is driven by the JWKS key, not pinned.
     */
    private static NimbusJwtDecoder userDecoder(String jwksUri, String issuer,
                                                String audience, Duration skew,
                                                long jwksTimeoutMs) {
        NimbusJwtDecoder d = decoder(jwksUri, jwksTimeoutMs);

        // issuer + audience + exp + nbf validators
        OAuth2TokenValidator<Jwt> timestamps = new JwtTimestampValidator(skew);
        OAuth2TokenValidator<Jwt> nbf = new NbfValidator(skew);
        OAuth2TokenValidator<Jwt> iss = new JwtIssuerValidator(issuer);
        // A4/G1: audience validator always added (audience guaranteed non-blank by constructor)
        OAuth2TokenValidator<Jwt> aud = new JwtClaimValidator<List<String>>(
                "aud", a -> a != null && a.contains(audience));

        d.setJwtValidator(new DelegatingOAuth2TokenValidator<>(timestamps, nbf, iss, aud));
        return d;
    }

    /**
     * Build an RS256 service-token decoder with issuer + exp + nbf validators.
     * No audience check (default service-token path, §2.3).
     */
    private static NimbusJwtDecoder serviceDecoder(String jwksUri, String issuer, Duration skew,
                                                   long jwksTimeoutMs) {
        NimbusJwtDecoder d = decoder(jwksUri, jwksTimeoutMs);
        d.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(skew), new NbfValidator(skew),
                new JwtIssuerValidator(issuer)));
        return d;
    }

    /**
     * Build an RS256 service-token decoder with issuer + audience + exp + nbf validators.
     * Used when optional service-token audience check is enabled (T5,
     * {@code authz.service-token-audience}).
     */
    private static NimbusJwtDecoder serviceDecoder(String jwksUri, String issuer, String audience,
                                                   Duration skew, long jwksTimeoutMs) {
        NimbusJwtDecoder d = decoder(jwksUri, jwksTimeoutMs);
        OAuth2TokenValidator<Jwt> aud = new JwtClaimValidator<List<String>>(
                "aud", a -> a != null && a.contains(audience));
        d.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(skew), new NbfValidator(skew),
                new JwtIssuerValidator(issuer), aud));
        return d;
    }

    /**
     * Core factory: build a generic {@link NimbusJwtDecoder} backed by a remote
     * JWKS URI. Verification is algorithm-agnostic — the signature algorithm is
     * driven by the JWKS key that matches the token's {@code kid} (RS256/ES* for
     * SSO service tokens, EdDSA for provider user tokens), not pinned per token
     * type. {@code alg:none} is always rejected (DefaultJWTProcessor requires a
     * key + verifier).
     *
     * <p>Nimbus does the actual decoding/verification via its own verifiers
     * (RSASSAVerifier / ECDSAVerifier / Ed25519Verifier). The only glue is
     * {@link GenericJwsKeySelector}, which fetches OKP keys straight from the JWK
     * source because Nimbus's stock {@code KeyConverter.toJavaKeys()} drops
     * OctetKeyPair; RSA/EC keys go through the stock selector unchanged.
     *
     * <p>The JWKS source is built with a connect+read timeout so a slow JWKS
     * endpoint cannot block validation indefinitely.
     */
    private static NimbusJwtDecoder decoder(String jwksUri, long jwksTimeoutMs) {
        URL url;
        try {
            url = new URL(jwksUri);
        } catch (MalformedURLException e) {
            throw new ConfigException("Invalid JWKS URI: " + jwksUri);
        }

        // Build remote JWK source with explicit HTTP connect+read timeout via
        // DefaultResourceRetriever so a slow JWKS endpoint cannot hang validation.
        int timeoutMs = (int) Math.max(1, jwksTimeoutMs);
        var retriever = new DefaultResourceRetriever(timeoutMs, timeoutMs);
        var jwkSource = JWKSourceBuilder
                .<SecurityContext>create(url, retriever)
                .retrying(false)
                .build();

        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        // Accept "JWT" type (standard) and null type (omitted typ header)
        processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(
                JOSEObjectType.JWT, null));
        processor.setJWSKeySelector(new GenericJwsKeySelector<>(jwkSource));
        processor.setJWSVerifierFactory(new EdDsaAwareJWSVerifierFactory());

        return new NimbusJwtDecoder(processor);
    }

    @Override
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
    // EdDSA-aware JWSVerifierFactory
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // Generic key selection (RSA / EC / EdDSA), driven by the JWKS key
    //
    // RSA and EC keys flow through Nimbus's stock JWSVerificationKeySelector. OKP
    // (Ed25519) keys need a small detour: Nimbus's KeyConverter.toJavaKeys() drops
    // OctetKeyPair (its toKeyPair() throws "Export not supported"), so the stock
    // selector returns no key for EdDSA. GenericJwsKeySelector fetches OKP keys
    // directly from the JWK source and wraps each in an OkpKeyHolder; the paired
    // EdDsaAwareJWSVerifierFactory unwraps it to an OctetKeyPair for Nimbus's own
    // Ed25519Verifier. Nimbus performs all signature verification — this is wiring,
    // not a hand-rolled verifier, and the algorithm is never pinned per token type.
    // -------------------------------------------------------------------------

    /**
     * Carrier that wraps an {@link OctetKeyPair} as a {@link java.security.Key} so it
     * can be returned from {@link JWSKeySelector#selectJWSKeys} (which returns
     * {@code List<? extends java.security.Key>}) without going through
     * {@link com.nimbusds.jose.jwk.KeyConverter#toJavaKeys} (which would drop it).
     */
    static final class OkpKeyHolder implements java.security.Key {
        private final OctetKeyPair okp;
        OkpKeyHolder(OctetKeyPair okp) { this.okp = okp; }
        OctetKeyPair getOctetKeyPair() { return okp; }
        @Override public String getAlgorithm() { return "EdDSA"; }
        @Override public String getFormat() { return "OKP"; }
        @Override public byte[] getEncoded() { return null; } // not used
    }

    /**
     * Generic JWS key selector. EdDSA tokens are matched to OKP keys fetched
     * directly from the JWK source (wrapped in {@link OkpKeyHolder}); RSA and EC
     * tokens are delegated to Nimbus's stock {@link JWSVerificationKeySelector}.
     * The accepted algorithm is whatever the token header declares and the JWKS
     * provides — nothing is pinned to a single algorithm or token type.
     */
    static final class GenericJwsKeySelector<C extends SecurityContext> implements JWSKeySelector<C> {

        private final JWKSource<C> jwkSource;
        private final JWSVerificationKeySelector<C> standard;

        GenericJwsKeySelector(JWKSource<C> jwkSource) {
            this.jwkSource = jwkSource;
            java.util.Set<JWSAlgorithm> rsaEc = new java.util.LinkedHashSet<>();
            rsaEc.addAll(JWSAlgorithm.Family.RSA);
            rsaEc.addAll(JWSAlgorithm.Family.EC);
            this.standard = new JWSVerificationKeySelector<>(rsaEc, jwkSource);
        }

        @Override
        public List<? extends java.security.Key> selectJWSKeys(JWSHeader header, C context)
                throws KeySourceException {
            // EdDSA/OKP: fetch directly and wrap — Nimbus's stock KeyConverter drops OKP.
            if (JWSAlgorithm.Family.ED.contains(header.getAlgorithm())) {
                JWKMatcher matcher = new JWKMatcher.Builder()
                        .keyType(com.nimbusds.jose.jwk.KeyType.OKP)
                        .keyID(header.getKeyID())
                        .keyUses(com.nimbusds.jose.jwk.KeyUse.SIGNATURE, null)
                        .publicOnly(true)
                        .build();
                List<JWK> jwks;
                try {
                    jwks = jwkSource.get(new JWKSelector(matcher), context);
                } catch (KeySourceException e) {
                    throw e; // already typed correctly
                } catch (Exception e) {
                    throw new KeySourceException("Failed to retrieve JWKS: " + e.getMessage(), e);
                }
                if (jwks == null || jwks.isEmpty()) {
                    return java.util.Collections.emptyList();
                }
                List<java.security.Key> keys = new java.util.ArrayList<>(jwks.size());
                for (JWK jwk : jwks) {
                    if (jwk instanceof OctetKeyPair okp) {
                        keys.add(new OkpKeyHolder(okp));
                    }
                }
                return keys;
            }
            // RSA/EC (and rejection of alg:none / unknown algs): stock selector.
            return standard.selectJWSKeys(header, context);
        }
    }

    /**
     * JWS verifier factory that routes {@link OkpKeyHolder} carriers (from
     * {@link GenericJwsKeySelector}) to Nimbus's {@link Ed25519Verifier}; all
     * other key types are forwarded to Nimbus's {@link DefaultJWSVerifierFactory}.
     */
    private static final class EdDsaAwareJWSVerifierFactory implements JWSVerifierFactory {

        private final DefaultJWSVerifierFactory delegate = new DefaultJWSVerifierFactory();

        @Override
        public java.util.Set<JWSAlgorithm> supportedJWSAlgorithms() {
            java.util.Set<JWSAlgorithm> algs = new java.util.HashSet<>(delegate.supportedJWSAlgorithms());
            algs.add(JWSAlgorithm.EdDSA);
            return algs;
        }

        @Override
        public com.nimbusds.jose.jca.JCAContext getJCAContext() {
            return delegate.getJCAContext();
        }

        @Override
        public JWSVerifier createJWSVerifier(JWSHeader header, java.security.Key key)
                throws JOSEException {
            if (key instanceof OkpKeyHolder holder) {
                return new Ed25519Verifier(holder.getOctetKeyPair());
            }
            return delegate.createJWSVerifier(header, key);
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
