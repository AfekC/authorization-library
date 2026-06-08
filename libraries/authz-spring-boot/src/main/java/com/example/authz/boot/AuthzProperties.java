package com.example.authz.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/** Configuration for the authorization library. Bind under the `authz` prefix. */
@ConfigurationProperties(prefix = "authz")
public class AuthzProperties {
    /** Location of authorization.yaml (Spring resource string). */
    private String configLocation = "classpath:authorization.yaml";
    /** Auth Service issuer + JWKS (user JWTs). */
    private String userIssuer;
    private String userJwksUri;
    /** SSO/OIDC issuer + JWKS (service tokens). */
    private String serviceIssuer;
    private String serviceJwksUri;
    /**
     * Expected audience for user JWTs. REQUIRED — must be a non-blank string matching
     * the {@code aud} claim in user JWTs. Audience validation is mandatory and cannot
     * be disabled; a blank value causes a {@link com.example.authz.config.ConfigException}
     * at startup (fail-fast). Matches NestJS behavior where {@code audience} is required.
     */
    private String audience = "";
    /** Claim + value that marks a service token (§2.3). */
    private String serviceTokenUseClaim = "token_use";
    private String serviceTokenUseValue = "service";
    /** Clock-skew tolerance (seconds) for JWT exp/nbf checks (§2.2). */
    private long clockSkewSeconds = 5;
    /**
     * JWKS fetch HTTP timeout in ms (connect + read) for user/service token
     * validation (default 5000). A slow/hung JWKS endpoint must not block token
     * validation on the request path indefinitely. Matches the NestJS default.
     */
    private long jwksTimeoutMs = 5000;
    /** Authoritative Role Service base URL. */
    private String roleServiceUrl;
    /** Role Service HTTP connect timeout in ms (default 5000). */
    private int roleServiceConnectTimeout = 5000;
    /** Role Service HTTP read timeout in ms (default 5000). */
    private int roleServiceReadTimeout = 5000;
    /** Fallback/seed cache file. */
    private String diskCachePath = "authorization-cache.json";
    /** Kafka brokers for incremental role events (empty -> Kafka disabled). */
    private List<String> kafkaBrokers = List.of();
    /** Topics carrying role UPSERT and DELETE events, plus the forced-refresh trigger topic. */
    private String roleUpdatesTopic = "role-updates";
    private String roleDeleteTopic = "role-delete";
    private String publishRolesTopic = "publish-roles";
    /** Kafka consumer group prefix (default "authz-cache-sync"). A UUID is appended per instance. */
    private String kafkaGroupId = "authz-cache-sync";
    /** Kafka consumer client ID prefix (default "authz-cache-sync"). */
    private String kafkaClientId = "authz-cache-sync";
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
    public String getUserIssuer() { return userIssuer; }
    public void setUserIssuer(String v) { this.userIssuer = v; }
    public String getUserJwksUri() { return userJwksUri; }
    public void setUserJwksUri(String v) { this.userJwksUri = v; }
    public String getServiceIssuer() { return serviceIssuer; }
    public void setServiceIssuer(String v) { this.serviceIssuer = v; }
    public String getServiceJwksUri() { return serviceJwksUri; }
    public void setServiceJwksUri(String v) { this.serviceJwksUri = v; }
    public String getAudience() { return audience; }
    public void setAudience(String v) { this.audience = v; }
    public String getServiceTokenUseClaim() { return serviceTokenUseClaim; }
    public void setServiceTokenUseClaim(String v) { this.serviceTokenUseClaim = v; }
    public String getServiceTokenUseValue() { return serviceTokenUseValue; }
    public void setServiceTokenUseValue(String v) { this.serviceTokenUseValue = v; }
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
    public List<String> getKafkaBrokers() { return kafkaBrokers; }
    public void setKafkaBrokers(List<String> v) { this.kafkaBrokers = v; }
    public String getRoleUpdatesTopic() { return roleUpdatesTopic; }
    public void setRoleUpdatesTopic(String v) { this.roleUpdatesTopic = v; }
    public String getRoleDeleteTopic() { return roleDeleteTopic; }
    public void setRoleDeleteTopic(String v) { this.roleDeleteTopic = v; }
    public String getPublishRolesTopic() { return publishRolesTopic; }
    public void setPublishRolesTopic(String v) { this.publishRolesTopic = v; }
    public String getKafkaGroupId() { return kafkaGroupId; }
    public void setKafkaGroupId(String v) { this.kafkaGroupId = v; }
    public String getKafkaClientId() { return kafkaClientId; }
    public void setKafkaClientId(String v) { this.kafkaClientId = v; }
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
