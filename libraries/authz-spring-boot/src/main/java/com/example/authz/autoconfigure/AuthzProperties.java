package com.example.authz.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/** Configuration for the authorization library. Bind under the `authz` prefix. */
@ConfigurationProperties(prefix = "authz")
public class AuthzProperties {
    /** Location of authorization.yaml (Spring resource string). */
    private String configLocation = "classpath:authorization.yaml";
    /**
     * Optional user-auth block (Auth Service issuer/JWKS + audience). When any
     * field here (or {@link #roleServiceUrl}) is set, the library runs in FULL
     * mode and all user-auth fields are required (all-or-nothing, validated at
     * startup). When the whole block is absent, the library runs in
     * SERVICE-ONLY mode (§0.5): user JWTs are ignored and the role-permission
     * machinery is disabled.
     */
    private final User user = new User();
    /** SSO/OIDC issuer + JWKS (service tokens). */
    private String serviceIssuer;
    private String serviceJwksUri;
    /**
     * Explicit SERVICE-ONLY mode (§0.5). When true, user JWTs are ignored and
     * the role-permission machinery is disabled — the same effect as omitting the
     * {@code authz.user} block, but stated explicitly so a stray user-auth value
     * can't silently flip the service into FULL mode. It is a startup error to
     * combine this with any user-auth property or {@link #externalPermissionSource}.
     */
    private boolean serviceOnly = false;

    /** Nested user-auth configuration, bound under {@code authz.user.*}. */
    public static class User {
        /** Auth Service issuer (user JWTs). */
        private String issuer;
        /** Auth Service JWKS URI (user JWTs). */
        private String jwksUri;
        /**
         * Expected audience for user JWTs. REQUIRED when user auth is enabled —
         * a blank value with user auth otherwise configured is a fail-fast
         * startup error. Matches NestJS behaviour where audience is mandatory.
         */
        private String audience = "";

        public String getIssuer() { return issuer; }
        public void setIssuer(String v) { this.issuer = v; }
        public String getJwksUri() { return jwksUri; }
        public void setJwksUri(String v) { this.jwksUri = v; }
        public String getAudience() { return audience; }
        public void setAudience(String v) { this.audience = v; }
    }
    /** Claim + value that marks a service token (§2.3). */
    private String serviceTokenUseClaim = "token_use";
    private String serviceTokenUseValue = "service";
    /**
     * Optional expected audience for service tokens (T5). When blank (default),
     * no audience check is performed on service tokens — preserving existing
     * behavior. When set, the service-token decoder enforces that the {@code aud}
     * claim contains this value. Mirrors the NestJS {@code serviceTokenAudience}
     * config option. Config key: {@code authz.service-token-audience}.
     */
    private String serviceTokenAudience = "";
    /** Clock-skew tolerance (seconds) for JWT exp/nbf checks (§2.2). */
    private long clockSkewSeconds = 5;
    /**
     * JWKS fetch HTTP timeout in ms (connect + read) for user/service token
     * validation (default 5000). A slow/hung JWKS endpoint must not block token
     * validation on the request path indefinitely. Matches the NestJS default.
     */
    private long jwksTimeoutMs = 5000;
    /**
     * External permission source (§0.5b). When true, the built-in role-permission
     * distribution machinery (Role Service snapshot, reconciler, seed-retry, disk
     * cache, Kafka role events) is disabled and the service must supply its own
     * {@code Spi.RoleResolver} bean backed by its store (Redis/Postgres/Infinispan).
     * User-JWT validation stays enabled; {@link #roleServiceUrl} is not required.
     */
    private boolean externalPermissionSource = false;
    /** Authoritative Role Service base URL. */
    private String roleServiceUrl;
    /** Role Service HTTP connect timeout in ms (default 5000). */
    private int roleServiceConnectTimeout = 5000;
    /** Role Service HTTP read timeout in ms (default 5000). */
    private int roleServiceReadTimeout = 5000;
    /** Fallback/seed cache file. */
    private String diskCachePath = "authorization-cache.json";
    /**
     * Topics carrying role UPSERT and DELETE events, plus the forced-refresh trigger topic.
     * These are read by the library's {@code @KafkaListener} beans via SpEL:
     * {@code ${authz.kafka.role-updates-topic:role-updates}} etc.
     * Kafka connection config (brokers, deserializer, schema-registry) is owned by the
     * host service via {@code spring.kafka.consumer.*} properties.
     */
    private String roleUpdatesTopic = "role-updates";
    private String roleDeleteTopic = "role-delete";
    private String publishRolesTopic = "publish-roles";
    /** Periodic reconciler interval in ms (§8.3). Default 5 minutes. */
    private long reconcileIntervalMs = 300000;
    /** Outbound service-token (client-credentials); empty clientId -> disabled. */
    private String tokenUrl;
    private String clientId;
    private String clientSecret;
    /** Token endpoint HTTP timeout in ms (default 5000). */
    private long tokenEndpointTimeoutMs = 5000;
    /**
     * How often (ms) the proactive token-refresh scheduler checks whether the
     * cached service token has passed ~70% of its lifetime (default 30000).
     * Mirrors the NestJS provider, which refreshes proactively in the background
     * so outbound calls near expiry never block on token issuance.
     */
    private long tokenRefreshCheckIntervalMs = 30000;

    /** Additional untrusted header name prefixes (lower-cased). */
    private List<String> untrustedHeaderPrefixes = List.of();

    /** Additional untrusted exact header names (lower-cased). */
    private List<String> untrustedHeaderExact = List.of();

    public String getConfigLocation() { return configLocation; }
    public void setConfigLocation(String v) { this.configLocation = v; }
    public User getUser() { return user; }
    // Flat aliases (relaxed-binding convenience + programmatic ergonomics) that
    // delegate to the nested authz.user.* block.
    public String getUserIssuer() { return user.getIssuer(); }
    public void setUserIssuer(String v) { user.setIssuer(v); }
    public String getUserJwksUri() { return user.getJwksUri(); }
    public void setUserJwksUri(String v) { user.setJwksUri(v); }
    public String getServiceIssuer() { return serviceIssuer; }
    public void setServiceIssuer(String v) { this.serviceIssuer = v; }
    public String getServiceJwksUri() { return serviceJwksUri; }
    public void setServiceJwksUri(String v) { this.serviceJwksUri = v; }
    public String getAudience() { return user.getAudience(); }
    public void setAudience(String v) { user.setAudience(v); }

    /**
     * True when user auth is configured (FULL mode, §0.5). Detected by the
     * presence of any user-auth field; the {@code ConfigValidator} then enforces
     * that all required user-auth fields are present (all-or-nothing). When this
     * is false the library runs in SERVICE-ONLY mode.
     */
    public boolean isUserAuthEnabled() {
        if (serviceOnly) return false; // explicit SERVICE-ONLY mode (§0.5)
        return notBlank(user.getIssuer()) || notBlank(user.getJwksUri())
                || notBlank(user.getAudience()) || notBlank(roleServiceUrl);
    }

    private static boolean notBlank(String s) { return s != null && !s.isBlank(); }
    public boolean isServiceOnly() { return serviceOnly; }
    public void setServiceOnly(boolean v) { this.serviceOnly = v; }
    public boolean isExternalPermissionSource() { return externalPermissionSource; }
    public void setExternalPermissionSource(boolean v) { this.externalPermissionSource = v; }
    public String getServiceTokenUseClaim() { return serviceTokenUseClaim; }
    public void setServiceTokenUseClaim(String v) { this.serviceTokenUseClaim = v; }
    public String getServiceTokenUseValue() { return serviceTokenUseValue; }
    public void setServiceTokenUseValue(String v) { this.serviceTokenUseValue = v; }
    public String getServiceTokenAudience() { return serviceTokenAudience; }
    public void setServiceTokenAudience(String v) { this.serviceTokenAudience = v; }
    public long getClockSkewSeconds() { return clockSkewSeconds; }
    public void setClockSkewSeconds(long v) { this.clockSkewSeconds = v; }
    public long getJwksTimeoutMs() { return jwksTimeoutMs; }
    public void setJwksTimeoutMs(long v) { this.jwksTimeoutMs = v; }
    public String getRoleServiceUrl() { return roleServiceUrl; }
    public void setRoleServiceUrl(String v) { this.roleServiceUrl = v; }
    public int getRoleServiceConnectTimeout() { return roleServiceConnectTimeout; }
    public void setRoleServiceConnectTimeout(int v) { this.roleServiceConnectTimeout = v; }
    public int getRoleServiceReadTimeout() { return roleServiceReadTimeout; }
    public void setRoleServiceReadTimeout(int v) { this.roleServiceReadTimeout = v; }
    public String getDiskCachePath() { return diskCachePath; }
    public void setDiskCachePath(String v) { this.diskCachePath = v; }
    public String getRoleUpdatesTopic() { return roleUpdatesTopic; }
    public void setRoleUpdatesTopic(String v) { this.roleUpdatesTopic = v; }
    public String getRoleDeleteTopic() { return roleDeleteTopic; }
    public void setRoleDeleteTopic(String v) { this.roleDeleteTopic = v; }
    public String getPublishRolesTopic() { return publishRolesTopic; }
    public void setPublishRolesTopic(String v) { this.publishRolesTopic = v; }
    public long getReconcileIntervalMs() { return reconcileIntervalMs; }
    public void setReconcileIntervalMs(long v) { this.reconcileIntervalMs = v; }
    public String getTokenUrl() { return tokenUrl; }
    public void setTokenUrl(String v) { this.tokenUrl = v; }
    public String getClientId() { return clientId; }
    public void setClientId(String v) { this.clientId = v; }
    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String v) { this.clientSecret = v; }
    public long getTokenEndpointTimeoutMs() { return tokenEndpointTimeoutMs; }
    public void setTokenEndpointTimeoutMs(long v) { this.tokenEndpointTimeoutMs = v; }
    public long getTokenRefreshCheckIntervalMs() { return tokenRefreshCheckIntervalMs; }
    public void setTokenRefreshCheckIntervalMs(long v) { this.tokenRefreshCheckIntervalMs = v; }

    public List<String> getUntrustedHeaderPrefixes() { return untrustedHeaderPrefixes; }
    public void setUntrustedHeaderPrefixes(List<String> v) { this.untrustedHeaderPrefixes = v; }

    public List<String> getUntrustedHeaderExact() { return untrustedHeaderExact; }
    public void setUntrustedHeaderExact(List<String> v) { this.untrustedHeaderExact = v; }
}
