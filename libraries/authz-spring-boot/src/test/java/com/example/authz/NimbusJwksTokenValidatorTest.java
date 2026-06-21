package com.example.authz;

import com.example.authz.config.ConfigException;
import com.example.authz.web.NimbusJwksTokenValidator;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
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
 * algorithm pinning (EdDSA/Ed25519 only, RS256/ES256 rejected), alg:none
 * rejection, issuer, audience, exp/clock-skew, nbf (future token rejected),
 * service-token token_use discrimination, and optional service-token audience
 * check (T5).
 *
 * <p>Ed25519 keys are generated via Nimbus {@link OctetKeyPairGenerator}
 * (backed by Google Tink, added as a test-scope dependency since Nimbus 9.x
 * hard-wires Tink in {@code Ed25519Signer}).
 */
class NimbusJwksTokenValidatorTest {

    private static final String ISSUER = "https://auth.example.com";
    private static final String SVC_ISSUER = "https://sso.example.com";
    private static final String AUDIENCE = "my-api";

    /** Ed25519 keypair for user tokens (T1: EdDSA only). */
    private OctetKeyPair ed25519UserKey;
    /** Ed25519 keypair for service tokens. */
    private OctetKeyPair ed25519SvcKey;

    private HttpServer jwksServer;
    private int jwksPort;
    private HttpServer svcJwksServer;
    private int svcJwksPort;

    @BeforeEach
    void setUp() throws Exception {
        // Generate Ed25519 keypairs via Nimbus OctetKeyPairGenerator (uses Google Tink)
        ed25519UserKey = new OctetKeyPairGenerator(com.nimbusds.jose.jwk.Curve.Ed25519)
                .keyID("ed-user-kid-1").generate();
        ed25519SvcKey = new OctetKeyPairGenerator(com.nimbusds.jose.jwk.Curve.Ed25519)
                .keyID("ed-svc-kid-1").generate();

        // JWKS server for user tokens (Ed25519 public key)
        jwksServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        jwksServer.createContext("/.well-known/jwks.json", exchange -> {
            JWKSet jwks = new JWKSet(ed25519UserKey.toPublicJWK());
            byte[] body = jwks.toString().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        jwksServer.start();
        jwksPort = jwksServer.getAddress().getPort();

        // JWKS server for service tokens (Ed25519 public key)
        svcJwksServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        svcJwksServer.createContext("/.well-known/jwks.json", exchange -> {
            JWKSet jwks = new JWKSet(ed25519SvcKey.toPublicJWK());
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

    /** Build a valid EdDSA user JWT. */
    private String validUserJwt() throws Exception {
        return userJwtBuilder().build();
    }

    /** Builder-pattern helper for user JWTs with custom fields. */
    private JwtBuilder userJwtBuilder() {
        return new JwtBuilder(ed25519UserKey, ISSUER, AUDIENCE);
    }

    /** Build a valid EdDSA service JWT with token_use=service. */
    private String validServiceJwt() throws Exception {
        return new JwtBuilder(ed25519SvcKey, SVC_ISSUER, null)
                .claim("token_use", "service")
                .claim("service_name", "scheduler")
                .build();
    }

    // ---- Ed25519 JWT builder ----

    private static class JwtBuilder {
        private final OctetKeyPair key;
        private final String issuer;
        private final String audience;
        private Instant exp = Instant.now().plusSeconds(300);
        private Instant nbf = null;
        private final java.util.HashMap<String, Object> extraClaims = new java.util.HashMap<>();
        private boolean algNone = false;
        private String subject = "user-123";

        JwtBuilder(OctetKeyPair key, String issuer, String audience) {
            this.key = key;
            this.issuer = issuer;
            this.audience = audience;
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
                com.nimbusds.jwt.PlainJWT plain = new com.nimbusds.jwt.PlainJWT(claims);
                return plain.serialize();
            }

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                    .keyID(key.getKeyID())
                    .build();
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new Ed25519Signer(key));
            return jwt.serialize();
        }
    }

    // ============================================================
    // A4 / G1 — Audience validation is MANDATORY
    // ============================================================

    @Test
    void constructorThrowsConfigExceptionWhenAudienceIsBlank() {
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
        NimbusJwksTokenValidator v = new NimbusJwksTokenValidator(
                ISSUER, userJwksUri(), SVC_ISSUER, svcJwksUri(),
                "other-api", "token_use", "service", 5);
        assertThrows(RuntimeException.class, () -> v.validateUserToken(validUserJwt()),
                "wrong audience must be rejected");
    }

    @Test
    void validateUserToken_rejectsTokenMissingAudClaim() throws Exception {
        // Build JWT with no audience claim using raw Nimbus
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("user-123").issuer(ISSUER)
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .keyID(ed25519UserKey.getKeyID()).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new Ed25519Signer(ed25519UserKey));

        assertThrows(RuntimeException.class, () -> validator().validateUserToken(jwt.serialize()),
                "missing aud claim must be rejected when audience is configured");
    }

    // ============================================================
    // A6 — nbf (not-before) validation
    // ============================================================

    @Test
    void validateUserToken_rejectsFutureNbfToken() throws Exception {
        String jwt = userJwtBuilder().nbf(Instant.now().plusSeconds(60)).build();
        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> validator().validateUserToken(jwt),
                "token with future nbf must be rejected");
        assertNotNull(ex.getCause(), "cause must be preserved");
    }

    @Test
    void validateUserToken_acceptsNbfWithinClockSkew() throws Exception {
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
        String jwt = new JwtBuilder(ed25519SvcKey, SVC_ISSUER, null)
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
        String jwt = new JwtBuilder(ed25519SvcKey, SVC_ISSUER, null)
                .claim("token_use", "service")
                .claim("service_name", "scheduler")
                .nbf(Instant.now().plusSeconds(3))
                .build();
        assertDoesNotThrow(() -> validator().validateServiceToken(jwt));
    }

    // ============================================================
    // M4 — NbfValidator precise boundary: just inside / just outside skew
    // ============================================================

    @Test
    void m4_userNbfAtExactSkewBoundaryIsAccepted() throws Exception {
        String jwt = userJwtBuilder().nbf(Instant.now().plusSeconds(5)).build();
        assertDoesNotThrow(() -> validator().validateUserToken(jwt),
                "M4: nbf exactly at the clock-skew boundary must be accepted (nbf - skew = now)");
    }

    @Test
    void m4_userNbfJustBeyondSkewBoundaryIsRejected() throws Exception {
        String jwt = userJwtBuilder().nbf(Instant.now().plusSeconds(7)).build();
        assertThrows(RuntimeException.class, () -> validator().validateUserToken(jwt),
                "M4: nbf beyond the clock-skew boundary must be rejected (nbf - skew > now)");
    }

    @Test
    void m4_serviceNbfAtExactSkewBoundaryIsAccepted() throws Exception {
        String jwt = new JwtBuilder(ed25519SvcKey, SVC_ISSUER, null)
                .claim("token_use", "service")
                .nbf(Instant.now().plusSeconds(5))
                .build();
        assertDoesNotThrow(() -> validator().validateServiceToken(jwt),
                "M4: service token nbf at exact skew boundary must be accepted");
    }

    @Test
    void m4_serviceNbfJustBeyondSkewBoundaryIsRejected() throws Exception {
        String jwt = new JwtBuilder(ed25519SvcKey, SVC_ISSUER, null)
                .claim("token_use", "service")
                .nbf(Instant.now().plusSeconds(7))
                .build();
        assertThrows(RuntimeException.class, () -> validator().validateServiceToken(jwt),
                "M4: service token nbf beyond skew boundary must be rejected");
    }

    // ============================================================
    // T1 — Generic verification: the algorithm is driven by the JWKS key matched
    // by the token's kid (EdDSA for provider user tokens, RS256 for SSO service
    // tokens). alg:none and tokens with no matching key are rejected.
    // ============================================================

    @Test
    void validateUserToken_rejectsAlgNone() throws Exception {
        String jwt = userJwtBuilder().algNone().build();
        assertThrows(RuntimeException.class, () -> validator().validateUserToken(jwt),
                "alg:none must be rejected");
    }

    @Test
    void validateUserToken_acceptsEdDSA() throws Exception {
        String jwt = validUserJwt(); // EdDSA by construction
        assertDoesNotThrow(() -> validator().validateUserToken(jwt),
                "T1: EdDSA user token must be accepted");
    }

    @Test
    void validateUserToken_acceptsRS256_whenJwksServesMatchingKey() throws Exception {
        // Generic verification: when the user JWKS serves the RSA key that signed the
        // token, an RS256 user token verifies. (Algorithm is not pinned; in production
        // the provider JWKS serves only EdDSA, so RS256 user tokens have no key to match.)
        RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("rsa-reject-kid").generate();

        // Serve this RSA key from a fresh JWKS server (not the Ed25519 server)
        HttpServer rsaServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        rsaServer.createContext("/.well-known/jwks.json", exchange -> {
            JWKSet jwks = new JWKSet(rsaKey.toPublicJWK());
            byte[] body = jwks.toString().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        rsaServer.start();
        try {
            String rsaJwksUri = "http://127.0.0.1:" + rsaServer.getAddress().getPort() + "/.well-known/jwks.json";
            NimbusJwksTokenValidator v = new NimbusJwksTokenValidator(
                    ISSUER, rsaJwksUri, SVC_ISSUER, svcJwksUri(),
                    AUDIENCE, "token_use", "service", 5);

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("u1").issuer(ISSUER).audience(AUDIENCE)
                    .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                    .build();
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new RSASSASigner(rsaKey));

            assertDoesNotThrow(() -> v.validateUserToken(jwt.serialize()),
                    "Generic verification: RS256 accepted when the JWKS serves the matching RSA key");
        } finally {
            rsaServer.stop(0);
        }
    }

    @Test
    void validateServiceToken_acceptsRS256() throws Exception {
        // Service tokens are issued by SSO/Keycloak and signed RS256 — they must verify.
        RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("svc-rsa-reject").generate();

        HttpServer rsaSvcServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        rsaSvcServer.createContext("/.well-known/jwks.json", exchange -> {
            JWKSet jwks = new JWKSet(rsaKey.toPublicJWK());
            byte[] body = jwks.toString().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        rsaSvcServer.start();
        try {
            String rsaSvcJwksUri = "http://127.0.0.1:" + rsaSvcServer.getAddress().getPort() + "/.well-known/jwks.json";
            NimbusJwksTokenValidator v = new NimbusJwksTokenValidator(
                    ISSUER, userJwksUri(), SVC_ISSUER, rsaSvcJwksUri,
                    AUDIENCE, "token_use", "service", 5);

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("svc-1").issuer(SVC_ISSUER)
                    .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                    .claim("token_use", "service")
                    .build();
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new RSASSASigner(rsaKey));

            assertDoesNotThrow(() -> v.validateServiceToken(jwt.serialize()),
                    "Service tokens are RS256 (SSO) — must be accepted");
        } finally {
            rsaSvcServer.stop(0);
        }
    }

    // ============================================================
    // C7 / G3 — serviceTokenUseClaim: blank defaults to "token_use", always enforced
    // ============================================================

    @Test
    void constructorWithBlankServiceTokenUseClaimDefaultsToTokenUse() throws Exception {
        NimbusJwksTokenValidator v = new NimbusJwksTokenValidator(
                ISSUER, userJwksUri(), SVC_ISSUER, svcJwksUri(),
                AUDIENCE, "", "service", 5);
        assertDoesNotThrow(() -> v.validateServiceToken(validServiceJwt()),
                "valid token_use=service must pass even when claim name was configured as blank");
    }

    @Test
    void serviceTokenUseCheckAlwaysEnforced_wrongValue() throws Exception {
        String jwt = new JwtBuilder(ed25519SvcKey, SVC_ISSUER, null)
                .claim("token_use", "user")
                .build();
        assertThrows(RuntimeException.class, () -> validator().validateServiceToken(jwt),
                "wrong token_use value must be rejected");
    }

    @Test
    void serviceTokenUseCheckAlwaysEnforced_missingClaim() throws Exception {
        String jwt = new JwtBuilder(ed25519SvcKey, SVC_ISSUER, null)
                .claim("service_name", "scheduler")
                .build();
        assertThrows(RuntimeException.class, () -> validator().validateServiceToken(jwt),
                "missing token_use claim must be rejected");
    }

    @Test
    void serviceTokenUseCheckAlwaysEnforced_blankClaimNameStillRejectsWrongValue() throws Exception {
        NimbusJwksTokenValidator v = new NimbusJwksTokenValidator(
                ISSUER, userJwksUri(), SVC_ISSUER, svcJwksUri(),
                AUDIENCE, "", "service", 5);
        String jwt = new JwtBuilder(ed25519SvcKey, SVC_ISSUER, null)
                .claim("token_use", "user")
                .build();
        assertThrows(RuntimeException.class, () -> v.validateServiceToken(jwt),
                "blank claimName config must default to token_use and still reject wrong value");
    }

    // ============================================================
    // T5 — Optional service-token audience check
    // ============================================================

    /**
     * T5 — When no service-token audience is configured (default), service tokens
     * without an {@code aud} claim are accepted (backward-compat).
     */
    @Test
    void t5_serviceAudienceNotConfigured_acceptsTokenWithoutAud() throws Exception {
        NimbusJwksTokenValidator v = new NimbusJwksTokenValidator(
                ISSUER, userJwksUri(), SVC_ISSUER, svcJwksUri(),
                AUDIENCE, "token_use", "service", 5, 5000, null);
        String jwt = new JwtBuilder(ed25519SvcKey, SVC_ISSUER, null)
                .claim("token_use", "service").build();
        assertDoesNotThrow(() -> v.validateServiceToken(jwt),
                "T5: without serviceTokenAudience config, tokens lacking aud must be accepted");
    }

    /**
     * T5 — When service-token audience is configured, a token carrying that audience is accepted.
     */
    @Test
    void t5_serviceAudienceConfigured_acceptsTokenWithMatchingAud() throws Exception {
        NimbusJwksTokenValidator v = new NimbusJwksTokenValidator(
                ISSUER, userJwksUri(), SVC_ISSUER, svcJwksUri(),
                AUDIENCE, "token_use", "service", 5, 5000, "internal-services");
        String jwt = new JwtBuilder(ed25519SvcKey, SVC_ISSUER, "internal-services")
                .claim("token_use", "service").build();
        assertDoesNotThrow(() -> v.validateServiceToken(jwt),
                "T5: service token with matching aud must be accepted");
    }

    /**
     * T5 — When service-token audience is configured, a token with a wrong audience is rejected.
     */
    @Test
    void t5_serviceAudienceConfigured_rejectsTokenWithWrongAud() throws Exception {
        NimbusJwksTokenValidator v = new NimbusJwksTokenValidator(
                ISSUER, userJwksUri(), SVC_ISSUER, svcJwksUri(),
                AUDIENCE, "token_use", "service", 5, 5000, "internal-services");
        String jwt = new JwtBuilder(ed25519SvcKey, SVC_ISSUER, "other-audience")
                .claim("token_use", "service").build();
        assertThrows(RuntimeException.class, () -> v.validateServiceToken(jwt),
                "T5: service token with wrong aud must be rejected when serviceTokenAudience is set");
    }

    /**
     * T5 — When service-token audience is configured, a token with no aud claim is rejected.
     */
    @Test
    void t5_serviceAudienceConfigured_rejectsTokenWithoutAud() throws Exception {
        NimbusJwksTokenValidator v = new NimbusJwksTokenValidator(
                ISSUER, userJwksUri(), SVC_ISSUER, svcJwksUri(),
                AUDIENCE, "token_use", "service", 5, 5000, "internal-services");
        String jwt = new JwtBuilder(ed25519SvcKey, SVC_ISSUER, null)
                .claim("token_use", "service").build();
        assertThrows(RuntimeException.class, () -> v.validateServiceToken(jwt),
                "T5: service token missing aud must be rejected when serviceTokenAudience is set");
    }

    /**
     * T5 — Blank serviceTokenAudience behaves as disabled (off by default).
     */
    @Test
    void t5_blankServiceAudience_behavesAsDisabled() throws Exception {
        NimbusJwksTokenValidator v = new NimbusJwksTokenValidator(
                ISSUER, userJwksUri(), SVC_ISSUER, svcJwksUri(),
                AUDIENCE, "token_use", "service", 5, 5000, "");
        String jwt = new JwtBuilder(ed25519SvcKey, SVC_ISSUER, null)
                .claim("token_use", "service").build();
        assertDoesNotThrow(() -> v.validateServiceToken(jwt),
                "T5: blank serviceTokenAudience must disable the audience check");
    }

    // ============================================================
    // Issuer validation
    // ============================================================

    @Test
    void validateUserToken_rejectsWrongIssuer() throws Exception {
        NimbusJwksTokenValidator v = new NimbusJwksTokenValidator(
                "https://other-issuer.example.com", userJwksUri(),
                SVC_ISSUER, svcJwksUri(), AUDIENCE, "token_use", "service", 5);
        assertThrows(RuntimeException.class, () -> v.validateUserToken(validUserJwt()),
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
        assertNotNull(ex.getCause(), "cause must be preserved on expiry rejection");
    }

    @Test
    void validateUserToken_acceptsTokenExpiredWithinClockSkew() throws Exception {
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
        String jwt = new JwtBuilder(ed25519SvcKey, SVC_ISSUER, null)
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
