package com.example.authz;

import com.example.authz.config.ConfigException;
import com.example.authz.web.NimbusJwksTokenValidator;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Direct unit tests for NimbusJwksTokenValidator covering D1/G8 gaps:
 * algorithm pinning, alg:none rejection, issuer, audience, exp/clock-skew,
 * nbf (future token rejected), and service-token token_use discrimination.
 */
class NimbusJwksTokenValidatorTest {

    private static final String ISSUER = "https://auth.example.com";
    private static final String SVC_ISSUER = "https://sso.example.com";
    private static final String AUDIENCE = "my-api";

    private RSAKey rsaKey;
    private ECKey ecKey;
    private HttpServer jwksServer;
    private int jwksPort;

    // Service-token JWKS (same key, different issuer for clarity)
    private RSAKey svcRsaKey;
    private HttpServer svcJwksServer;
    private int svcJwksPort;

    @BeforeEach
    void setUp() throws Exception {
        // Generate RS256 keypair for user tokens
        rsaKey = new RSAKeyGenerator(2048).keyID("rsa-kid-1").generate();
        // Generate ES256 keypair for EC-signed user tokens
        ecKey = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).keyID("ec-kid-1").generate();
        // Generate RS256 keypair for service tokens
        svcRsaKey = new RSAKeyGenerator(2048).keyID("svc-rsa-kid-1").generate();

        // Start JWKS server for user tokens (RSA + EC keys)
        jwksServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        jwksServer.createContext("/.well-known/jwks.json", exchange -> {
            JWKSet jwks = new JWKSet(List.of(rsaKey.toPublicJWK(), ecKey.toPublicJWK()));
            byte[] body = jwks.toString().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        jwksServer.start();
        jwksPort = jwksServer.getAddress().getPort();

        // Start JWKS server for service tokens
        svcJwksServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        svcJwksServer.createContext("/.well-known/jwks.json", exchange -> {
            JWKSet jwks = new JWKSet(svcRsaKey.toPublicJWK());
            byte[] body = jwks.toString().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        svcJwksServer.start();
        svcJwksPort = svcJwksServer.getAddress().getPort();
    }

    @AfterEach
    void tearDown() {
        if (jwksServer != null) jwksServer.stop(0);
        if (svcJwksServer != null) svcJwksServer.stop(0);
    }

    // ---- helpers ----

    private String userJwksUri() {
        return "http://127.0.0.1:" + jwksPort + "/.well-known/jwks.json";
    }

    private String svcJwksUri() {
        return "http://127.0.0.1:" + svcJwksPort + "/.well-known/jwks.json";
    }

    private NimbusJwksTokenValidator validator() {
        return new NimbusJwksTokenValidator(
                ISSUER, userJwksUri(), SVC_ISSUER, svcJwksUri(),
                AUDIENCE, "token_use", "service", 5);
    }

    /** Build a valid RS256 user JWT. */
    private String validUserJwt() throws Exception {
        return userJwtBuilder().build();
    }

    /** Builder-pattern helper for constructing user JWTs with custom fields. */
    private JwtBuilder userJwtBuilder() {
        return new JwtBuilder(rsaKey, JWSAlgorithm.RS256, ISSUER, AUDIENCE);
    }

    /** Build a valid RS256 service JWT with token_use=service. */
    private String validServiceJwt() throws Exception {
        return new JwtBuilder(svcRsaKey, JWSAlgorithm.RS256, SVC_ISSUER, null)
                .claim("token_use", "service")
                .claim("service_name", "scheduler")
                .build();
    }

    // ---- simple builder to construct JWTs programmatically ----

    private static class JwtBuilder {
        private final RSAKey key;
        private final ECKey ecKey;
        private final JWSAlgorithm alg;
        private final String issuer;
        private final String audience;
        private Instant exp = Instant.now().plusSeconds(300);
        private Instant nbf = null;
        private final java.util.HashMap<String, Object> extraClaims = new java.util.HashMap<>();
        private boolean algNone = false;
        private String subject = "user-123";

        JwtBuilder(RSAKey key, JWSAlgorithm alg, String issuer, String audience) {
            this.key = key; this.ecKey = null; this.alg = alg;
            this.issuer = issuer; this.audience = audience;
        }

        JwtBuilder(ECKey ecKey, JWSAlgorithm alg, String issuer, String audience) {
            this.key = null; this.ecKey = ecKey; this.alg = alg;
            this.issuer = issuer; this.audience = audience;
        }

        JwtBuilder exp(Instant exp) { this.exp = exp; return this; }
        JwtBuilder nbf(Instant nbf) { this.nbf = nbf; return this; }
        JwtBuilder algNone() { this.algNone = true; return this; }
        JwtBuilder subject(String s) { this.subject = s; return this; }
        JwtBuilder claim(String k, Object v) { this.extraClaims.put(k, v); return this; }

        String build() throws Exception {
            JWTClaimsSet.Builder cb = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issuer(issuer)
                    .expirationTime(exp != null ? Date.from(exp) : null);
            if (audience != null) cb.audience(audience);
            if (nbf != null) cb.notBeforeTime(Date.from(nbf));
            extraClaims.forEach(cb::claim);
            JWTClaimsSet claims = cb.build();

            if (algNone) {
                // alg:none unsigned JWT
                com.nimbusds.jwt.PlainJWT plain = new com.nimbusds.jwt.PlainJWT(claims);
                return plain.serialize();
            }

            JWSHeader header = new JWSHeader.Builder(alg)
                    .keyID(key != null ? key.getKeyID() : ecKey.getKeyID())
                    .build();
            SignedJWT jwt = new SignedJWT(header, claims);
            if (key != null) {
                jwt.sign(new RSASSASigner(key));
            } else {
                jwt.sign(new ECDSASigner(ecKey));
            }
            return jwt.serialize();
        }
    }

    // ============================================================
    // A4 / G1 — Audience validation is MANDATORY
    // ============================================================

    @Test
    void constructorThrowsConfigExceptionWhenAudienceIsBlank() {
        // A blank audience must fail fast at construction time, not silently skip the check
        assertThrows(ConfigException.class, () ->
                new NimbusJwksTokenValidator(
                        ISSUER, userJwksUri(), SVC_ISSUER, svcJwksUri(),
                        "", "token_use", "service", 5),
                "blank audience must throw ConfigException");
    }

    @Test
    void constructorThrowsConfigExceptionWhenAudienceIsNull() {
        assertThrows(ConfigException.class, () ->
                new NimbusJwksTokenValidator(
                        ISSUER, userJwksUri(), SVC_ISSUER, svcJwksUri(),
                        null, "token_use", "service", 5),
                "null audience must throw ConfigException");
    }

    @Test
    void validateUserToken_acceptsValidTokenWithCorrectAudience() throws Exception {
        Map<String, Object> claims = validator().validateUserToken(validUserJwt());
        assertEquals("user-123", claims.get("sub"));
    }

    @Test
    void validateUserToken_rejectsTokenWithWrongAudience() throws Exception {
        String jwt = userJwtBuilder().build(); // audience = AUDIENCE ("my-api")
        // Build validator expecting a DIFFERENT audience
        NimbusJwksTokenValidator v = new NimbusJwksTokenValidator(
                ISSUER, userJwksUri(), SVC_ISSUER, svcJwksUri(),
                "other-api", "token_use", "service", 5);
        assertThrows(RuntimeException.class, () -> v.validateUserToken(jwt),
                "wrong audience must be rejected");
    }

    @Test
    void validateUserToken_rejectsTokenMissingAudClaim() throws Exception {
        // Build JWT with no audience claim
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("user-123").issuer(ISSUER)
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new RSASSASigner(rsaKey));

        assertThrows(RuntimeException.class, () -> validator().validateUserToken(jwt.serialize()),
                "missing aud claim must be rejected when audience is configured");
    }

    // ============================================================
    // A6 — nbf (not-before) validation
    // ============================================================

    @Test
    void validateUserToken_rejectsFutureNbfToken() throws Exception {
        // nbf 60 seconds in the future (well beyond default 5s skew)
        String jwt = userJwtBuilder().nbf(Instant.now().plusSeconds(60)).build();
        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> validator().validateUserToken(jwt),
                "token with future nbf must be rejected");
        // Cause chain must be preserved (G12)
        assertNotNull(ex.getCause(), "cause must be preserved");
    }

    @Test
    void validateUserToken_acceptsNbfWithinClockSkew() throws Exception {
        // nbf 3 seconds in future, skew is 5 seconds -> must be accepted
        String jwt = userJwtBuilder().nbf(Instant.now().plusSeconds(3)).build();
        assertDoesNotThrow(() -> validator().validateUserToken(jwt),
                "nbf within clock skew must be accepted");
    }

    @Test
    void validateUserToken_acceptsNbfInPast() throws Exception {
        String jwt = userJwtBuilder().nbf(Instant.now().minusSeconds(60)).build();
        assertDoesNotThrow(() -> validator().validateUserToken(jwt));
    }

    @Test
    void validateServiceToken_rejectsFutureNbfToken() throws Exception {
        // Build service JWT with nbf 60s in the future
        String jwt = new JwtBuilder(svcRsaKey, JWSAlgorithm.RS256, SVC_ISSUER, null)
                .claim("token_use", "service")
                .claim("service_name", "scheduler")
                .nbf(Instant.now().plusSeconds(60))
                .build();
        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> validator().validateServiceToken(jwt),
                "service token with future nbf must be rejected");
        assertNotNull(ex.getCause(), "cause must be preserved");
    }

    @Test
    void validateServiceToken_acceptsNbfWithinClockSkew() throws Exception {
        String jwt = new JwtBuilder(svcRsaKey, JWSAlgorithm.RS256, SVC_ISSUER, null)
                .claim("token_use", "service")
                .claim("service_name", "scheduler")
                .nbf(Instant.now().plusSeconds(3))  // within 5s skew
                .build();
        assertDoesNotThrow(() -> validator().validateServiceToken(jwt));
    }

    // ============================================================
    // M4 — NbfValidator precise boundary: just inside / just outside skew
    // ============================================================

    /**
     * M4 — nbf at exactly the clock-skew boundary (nbf = now + skew) must be accepted.
     * NbfValidator condition: nbf.minus(skew).isAfter(now) → reject.
     * At boundary: nbf - skew = now → NOT after now → accept.
     * Documents parity with NestJS jose clockTolerance behavior.
     */
    @Test
    void m4_userNbfAtExactSkewBoundaryIsAccepted() throws Exception {
        // clockSkewSeconds = 5 in validator(); nbf = now + 5s → nbf - 5s = now → accept
        String jwt = userJwtBuilder().nbf(Instant.now().plusSeconds(5)).build();
        assertDoesNotThrow(() -> validator().validateUserToken(jwt),
                "M4: nbf exactly at the clock-skew boundary must be accepted (nbf - skew = now)");
    }

    /**
     * M4 — nbf just beyond the clock-skew boundary (nbf = now + skew + 2s) must be rejected.
     * NbfValidator condition: nbf.minus(skew).isAfter(now) → reject.
     * At 2 seconds past boundary: nbf - skew = now + 2s → after now → reject.
     * Using 2s margin to avoid test flakiness from execution time.
     */
    @Test
    void m4_userNbfJustBeyondSkewBoundaryIsRejected() throws Exception {
        // nbf = now + skew + 2s → nbf - skew = now + 2s → isAfter(now) → reject
        String jwt = userJwtBuilder().nbf(Instant.now().plusSeconds(7)).build();
        assertThrows(RuntimeException.class, () -> validator().validateUserToken(jwt),
                "M4: nbf beyond the clock-skew boundary must be rejected (nbf - skew > now)");
    }

    /**
     * M4 — service token: nbf at exactly the clock-skew boundary must be accepted.
     * Mirrors the user-token boundary test for service tokens.
     */
    @Test
    void m4_serviceNbfAtExactSkewBoundaryIsAccepted() throws Exception {
        String jwt = new JwtBuilder(svcRsaKey, JWSAlgorithm.RS256, SVC_ISSUER, null)
                .claim("token_use", "service")
                .nbf(Instant.now().plusSeconds(5))  // exactly at 5s skew boundary
                .build();
        assertDoesNotThrow(() -> validator().validateServiceToken(jwt),
                "M4: service token nbf at exact skew boundary must be accepted");
    }

    /**
     * M4 — service token: nbf just beyond the clock-skew boundary must be rejected.
     */
    @Test
    void m4_serviceNbfJustBeyondSkewBoundaryIsRejected() throws Exception {
        String jwt = new JwtBuilder(svcRsaKey, JWSAlgorithm.RS256, SVC_ISSUER, null)
                .claim("token_use", "service")
                .nbf(Instant.now().plusSeconds(7))  // 2s beyond 5s skew boundary
                .build();
        assertThrows(RuntimeException.class, () -> validator().validateServiceToken(jwt),
                "M4: service token nbf beyond skew boundary must be rejected");
    }

    // ============================================================
    // B2 / G2 — Algorithm pinning: RS256 and ES256 only
    // ============================================================

    @Test
    void validateUserToken_rejectsAlgNone() throws Exception {
        String jwt = userJwtBuilder().algNone().build();
        assertThrows(RuntimeException.class, () -> validator().validateUserToken(jwt),
                "alg:none must be rejected");
    }

    @Test
    void validateUserToken_acceptsRS256() throws Exception {
        String jwt = userJwtBuilder().build(); // RS256 by default
        assertDoesNotThrow(() -> validator().validateUserToken(jwt));
    }

    @Test
    void validateUserToken_acceptsES256() throws Exception {
        // Sign with EC key (ES256)
        String jwt = new JwtBuilder(ecKey, JWSAlgorithm.ES256, ISSUER, AUDIENCE).build();
        assertDoesNotThrow(() -> validator().validateUserToken(jwt));
    }

    @Test
    void validateUserToken_rejectsRS384() throws Exception {
        // Generate RS384 key pair and sign with RS384 — must be rejected
        RSAKey rs384Key = new RSAKeyGenerator(2048).keyID("rsa-384-kid").generate();
        // Serve this additional key from JWKS
        HttpServer extra = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        extra.createContext("/.well-known/jwks.json", exchange -> {
            JWKSet jwks = new JWKSet(rs384Key.toPublicJWK());
            byte[] body = jwks.toString().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        extra.start();
        try {
            String extraJwksUri = "http://127.0.0.1:" + extra.getAddress().getPort() + "/.well-known/jwks.json";
            NimbusJwksTokenValidator v = new NimbusJwksTokenValidator(
                    ISSUER, extraJwksUri, SVC_ISSUER, svcJwksUri(),
                    AUDIENCE, "token_use", "service", 5);

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS384).keyID(rs384Key.getKeyID()).build();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("u1").issuer(ISSUER).audience(AUDIENCE)
                    .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                    .build();
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new com.nimbusds.jose.crypto.RSASSASigner(rs384Key));

            assertThrows(RuntimeException.class, () -> v.validateUserToken(jwt.serialize()),
                    "RS384 must be rejected by algorithm pinning");
        } finally {
            extra.stop(0);
        }
    }

    // ============================================================
    // C7 / G3 — serviceTokenUseClaim: blank defaults to "token_use", always enforced
    // ============================================================

    @Test
    void constructorWithBlankServiceTokenUseClaimDefaultsToTokenUse() throws Exception {
        // Blank serviceTokenUseClaim must behave as "token_use", not disable the check
        NimbusJwksTokenValidator v = new NimbusJwksTokenValidator(
                ISSUER, userJwksUri(), SVC_ISSUER, svcJwksUri(),
                AUDIENCE, "", "service", 5);
        // A valid service JWT with token_use=service must pass
        assertDoesNotThrow(() -> v.validateServiceToken(validServiceJwt()),
                "valid token_use=service must pass even when claim name was configured as blank");
    }

    @Test
    void serviceTokenUseCheckAlwaysEnforced_wrongValue() throws Exception {
        // A service JWT with wrong token_use must be rejected regardless of claim name config
        String jwt = new JwtBuilder(svcRsaKey, JWSAlgorithm.RS256, SVC_ISSUER, null)
                .claim("token_use", "user")  // wrong value
                .build();
        assertThrows(RuntimeException.class, () -> validator().validateServiceToken(jwt),
                "wrong token_use value must be rejected");
    }

    @Test
    void serviceTokenUseCheckAlwaysEnforced_missingClaim() throws Exception {
        // A service JWT with no token_use claim must be rejected
        String jwt = new JwtBuilder(svcRsaKey, JWSAlgorithm.RS256, SVC_ISSUER, null)
                .claim("service_name", "scheduler")
                .build(); // no token_use claim
        assertThrows(RuntimeException.class, () -> validator().validateServiceToken(jwt),
                "missing token_use claim must be rejected");
    }

    @Test
    void serviceTokenUseCheckAlwaysEnforced_blankClaimNameStillRejectsWrongValue() throws Exception {
        // Blank claim config -> defaults to "token_use" -> wrong value still rejected
        NimbusJwksTokenValidator v = new NimbusJwksTokenValidator(
                ISSUER, userJwksUri(), SVC_ISSUER, svcJwksUri(),
                AUDIENCE, "", "service", 5);
        String jwt = new JwtBuilder(svcRsaKey, JWSAlgorithm.RS256, SVC_ISSUER, null)
                .claim("token_use", "user") // wrong value
                .build();
        assertThrows(RuntimeException.class, () -> v.validateServiceToken(jwt),
                "blank claimName config must default to token_use and still reject wrong value");
    }

    // ============================================================
    // Issuer validation
    // ============================================================

    @Test
    void validateUserToken_rejectsWrongIssuer() throws Exception {
        String jwt = userJwtBuilder().build();
        NimbusJwksTokenValidator v = new NimbusJwksTokenValidator(
                "https://other-issuer.example.com", userJwksUri(),
                SVC_ISSUER, svcJwksUri(), AUDIENCE, "token_use", "service", 5);
        assertThrows(RuntimeException.class, () -> v.validateUserToken(jwt),
                "wrong issuer must be rejected");
    }

    // ============================================================
    // Expiry + clock skew
    // ============================================================

    @Test
    void validateUserToken_rejectsExpiredToken() throws Exception {
        String jwt = userJwtBuilder().exp(Instant.now().minusSeconds(60)).build();
        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> validator().validateUserToken(jwt),
                "expired token must be rejected");
        // G12: cause must be preserved
        assertNotNull(ex.getCause(), "cause must be preserved on expiry rejection");
    }

    @Test
    void validateUserToken_acceptsTokenExpiredWithinClockSkew() throws Exception {
        // Token expired 3 seconds ago, skew is 5 seconds -> must be accepted
        String jwt = userJwtBuilder().exp(Instant.now().minusSeconds(3)).build();
        assertDoesNotThrow(() -> validator().validateUserToken(jwt),
                "token expired within clock skew tolerance must be accepted");
    }

    // ============================================================
    // G12 — Exception cause preservation
    // ============================================================

    @Test
    void validateUserToken_expiredExceptionPreservesCause() throws Exception {
        String jwt = userJwtBuilder().exp(Instant.now().minusSeconds(60)).build();
        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> validator().validateUserToken(jwt));
        assertNotNull(ex.getCause(), "original JwtException must be the cause");
        assertTrue(ex.getMessage().contains("invalid user token"),
                "message must describe user token failure");
    }

    @Test
    void validateServiceToken_expiredExceptionPreservesCause() throws Exception {
        String jwt = new JwtBuilder(svcRsaKey, JWSAlgorithm.RS256, SVC_ISSUER, null)
                .claim("token_use", "service")
                .exp(Instant.now().minusSeconds(60))
                .build();
        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> validator().validateServiceToken(jwt));
        assertNotNull(ex.getCause(), "original JwtException must be the cause");
        assertTrue(ex.getMessage().contains("invalid service token"),
                "message must describe service token failure");
    }

    @Test
    void validateUserToken_malformedJwtPreservesCause() {
        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> validator().validateUserToken("not.a.jwt"));
        assertNotNull(ex.getCause(), "malformed JWT cause must be preserved");
    }

    // ============================================================
    // Service token: valid path
    // ============================================================

    @Test
    void validateServiceToken_acceptsValidServiceToken() throws Exception {
        Map<String, Object> claims = validator().validateServiceToken(validServiceJwt());
        assertEquals("service", String.valueOf(claims.get("token_use")));
        assertEquals("scheduler", String.valueOf(claims.get("service_name")));
    }

    // ============================================================
    // 3-arg constructor (no clock-skew arg) still requires audience
    // ============================================================

    @Test
    void threeArgConstructorRequiresAudience() {
        assertThrows(ConfigException.class, () ->
                new NimbusJwksTokenValidator(
                        ISSUER, userJwksUri(), SVC_ISSUER, svcJwksUri(),
                        "", "token_use", "service"));
    }
}
