package com.example.authz.outbound;

import com.example.authz.spi.Spi;
import io.github.resilience4j.core.IntervalFunction;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.DefaultClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.Arrays;
import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Acquires this service's outbound token via OAuth2 client-credentials, delegating
 * the grant, token caching, and reactive (clock-skew) refresh to Spring Security's
 * {@link OAuth2AuthorizedClientManager}, and retries/backoff to Resilience4j. The
 * manager caches the authorized client and only re-fetches when the token is within
 * the clock-skew window of expiry, so outbound calls reuse a cached token.
 *
 * <p>In addition to the reactive safety-net, a background scheduler proactively
 * refreshes the token at ~70% of its lifetime (architecture §9.1) so that outbound
 * calls never block on token issuance near expiry. The scheduler is a daemon thread
 * and can be stopped explicitly via {@link #stop()}.
 *
 * <p>Base retry backoff is 200ms with factor 2.0 (canonical value; NestJS is aligned
 * to match — see architecture-gaps.md B6/G9).
 *
 * <p>An explicit connect+read timeout ({@code tokenEndpointTimeoutMs}, default
 * 5000ms) is applied to <em>all</em> token-endpoint calls — both the startup
 * reachability probe and actual token acquisition — via the client-credentials
 * token-response client's timeout-bounded {@code RestTemplate} (G10). A hung SSO
 * token endpoint therefore cannot block outbound calls indefinitely. The timeout
 * is configured via {@code authz.token-endpoint-timeout-ms} in AuthzProperties.
 *
 * <p>Mirrors the NestJS ClientCredentialsProvider (simple-oauth2 + p-retry).
 */
public class ClientCredentialsServiceIdentityProvider implements Spi.ServiceIdentityProvider {

    private static final Logger log =
            LoggerFactory.getLogger(ClientCredentialsServiceIdentityProvider.class);

    private static final String REGISTRATION_ID = "authz-outbound";
    private static final String PRINCIPAL = "authz-service";

    /**
     * Timeout for the startup reachability probe and token-endpoint HTTP calls (G10).
     * Configured via {@code authz.token-endpoint-timeout-ms}.
     */
    private final int tokenEndpointTimeoutMs;

    /** Fraction of token lifetime at which the proactive scheduler refreshes (A1). */
    private static final double PROACTIVE_REFRESH_FRACTION = 0.70;

    private final OAuth2AuthorizedClientManager manager;
    private final OAuth2AuthorizeRequest authorizeRequest;
    private final String tokenUrl;
    private Retry retry;
    private Consumer<Throwable> onError = e -> {};

    /**
     * Tracks when the currently cached token was issued and when it expires, so the
     * proactive scheduler can compute the 70%-of-lifetime threshold without an extra
     * HTTP call. Both default to EPOCH (no token yet).
     */
    private final AtomicReference<Instant> cachedIssuedAt = new AtomicReference<>(Instant.EPOCH);
    private final AtomicReference<Instant> cachedExpiry    = new AtomicReference<>(Instant.EPOCH);

    /** Single-thread daemon executor for proactive refresh (A1). Null when disabled. */
    private ScheduledExecutorService proactiveScheduler;

    /** Production constructor: defaults (clock-skew 60s, 3 attempts, 200ms base backoff, 5000ms timeout). */
    public ClientCredentialsServiceIdentityProvider(String tokenUrl, String clientId, String clientSecret) {
        this(tokenUrl, clientId, clientSecret, Duration.ofSeconds(60), 3, 200, 5000);
    }

    /** Production constructor with configurable token endpoint timeout (G10). */
    public ClientCredentialsServiceIdentityProvider(String tokenUrl, String clientId, String clientSecret,
                                                    int tokenEndpointTimeoutMs) {
        this(tokenUrl, clientId, clientSecret, Duration.ofSeconds(60), 3, 200, tokenEndpointTimeoutMs);
    }

    /** Constructor for tests: tune clock-skew window and retry policy with default 5000ms timeout. */
    public ClientCredentialsServiceIdentityProvider(String tokenUrl, String clientId, String clientSecret,
                                                    Duration clockSkew, int maxAttempts, long baseBackoffMs) {
        this(tokenUrl, clientId, clientSecret, clockSkew, maxAttempts, baseBackoffMs, 5000);
    }

    /** Full constructor (tests/advanced): tune the clock-skew window, retry policy, and timeout. */
    public ClientCredentialsServiceIdentityProvider(String tokenUrl, String clientId, String clientSecret,
                                                    Duration clockSkew, int maxAttempts, long baseBackoffMs,
                                                    int tokenEndpointTimeoutMs) {
        this.tokenUrl = tokenUrl;
        this.tokenEndpointTimeoutMs = tokenEndpointTimeoutMs;
        ClientRegistration registration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
                .tokenUri(tokenUrl)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST) // credentials in body
                .build();
        ClientRegistrationRepository registrations = new InMemoryClientRegistrationRepository(registration);
        InMemoryOAuth2AuthorizedClientService clientService =
                new InMemoryOAuth2AuthorizedClientService(registrations);
        AuthorizedClientServiceOAuth2AuthorizedClientManager mgr =
                new AuthorizedClientServiceOAuth2AuthorizedClientManager(registrations, clientService);
        // G10: apply the configured connect+read timeout to the actual token
        // acquisition (not just the startup probe) by giving the client-credentials
        // token-response client a timeout-bounded RestTemplate. A hung SSO token
        // endpoint must not block outbound calls indefinitely.
        DefaultClientCredentialsTokenResponseClient tokenResponseClient =
                new DefaultClientCredentialsTokenResponseClient();
        tokenResponseClient.setRestOperations(tokenEndpointRestTemplate(tokenEndpointTimeoutMs));
        mgr.setAuthorizedClientProvider(OAuth2AuthorizedClientProviderBuilder.builder()
                .clientCredentials(c -> {
                    c.clockSkew(clockSkew);
                    c.accessTokenResponseClient(tokenResponseClient);
                })
                .build());
        this.manager = mgr;
        this.authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(REGISTRATION_ID)
                .principal(PRINCIPAL)
                .build();
        this.retry = buildRetry(maxAttempts, baseBackoffMs);
        attachListeners();
    }

    public ClientCredentialsServiceIdentityProvider withRetry(int maxAttempts, long baseBackoffMs) {
        this.retry = buildRetry(maxAttempts, baseBackoffMs);
        attachListeners();
        return this;
    }

    /** Called once per failed acquisition attempt (e.g. metrics). */
    public ClientCredentialsServiceIdentityProvider onError(Consumer<Throwable> cb) {
        this.onError = cb; // listeners read this field at event time, so no re-registration needed
        return this;
    }

    /**
     * Starts the proactive refresh scheduler (architecture §9.1 / gap A1).
     *
     * <p>The scheduler fires at a fixed period of {@code checkIntervalMs} milliseconds.
     * On each tick it checks whether the cached token is past its 70%-of-lifetime mark;
     * if so it eagerly re-fetches so that outbound calls never block near expiry. The
     * reactive clock-skew path remains as a safety net.
     *
     * <p>The executor is a single daemon thread so it does not prevent JVM shutdown.
     * Call {@link #stop()} for a clean shutdown when the Spring context is closing.
     *
     * @param checkIntervalMs how often (ms) the scheduler checks the token age
     */
    public synchronized void startProactiveRefresh(long checkIntervalMs) {
        if (proactiveScheduler != null && !proactiveScheduler.isShutdown()) {
            return; // already running
        }
        ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "authz-token-refresh");
            t.setDaemon(true);
            return t;
        });
        exec.scheduleAtFixedRate(this::proactiveRefreshTick, checkIntervalMs, checkIntervalMs,
                TimeUnit.MILLISECONDS);
        this.proactiveScheduler = exec;
    }

    /**
     * Proactively refreshes the cached token if it has exceeded 70% of its lifetime
     * (gap A1). Runs on the scheduler thread; errors are logged and swallowed so the
     * scheduler loop is never broken.
     */
    private void proactiveRefreshTick() {
        try {
            Instant issuedAt = cachedIssuedAt.get();
            Instant expiry   = cachedExpiry.get();
            if (issuedAt.equals(Instant.EPOCH) || expiry.equals(Instant.EPOCH)) {
                // No token acquired yet — fetch eagerly on first tick so it's warm.
                fetchAndUpdateExpiry();
                return;
            }
            // Proactive refresh threshold: issuedAt + 70% of (expiry - issuedAt).
            long lifetimeMs = expiry.toEpochMilli() - issuedAt.toEpochMilli();
            Instant proactiveAt = issuedAt.plusMillis((long) (lifetimeMs * PROACTIVE_REFRESH_FRACTION));
            if (Instant.now().isAfter(proactiveAt)) {
                fetchAndUpdateExpiry();
            }
        } catch (Exception e) {
            log.warn("authz: proactive token refresh tick failed (will retry next interval): {}", e.getMessage());
        }
    }

    /**
     * Refreshes the token by calling the manager and updates the cached issuedAt/expiry.
     * Uses the retry policy.
     */
    private void fetchAndUpdateExpiry() {
        String token = retry.executeSupplier(() -> {
            OAuth2AuthorizedClient client = manager.authorize(authorizeRequest);
            if (client == null || client.getAccessToken() == null) {
                throw new IllegalStateException("service token authorization returned no client");
            }
            Instant issuedAt = client.getAccessToken().getIssuedAt();
            Instant expiry   = client.getAccessToken().getExpiresAt();
            if (issuedAt != null) cachedIssuedAt.set(issuedAt);
            if (expiry   != null) cachedExpiry.set(expiry);
            return client.getAccessToken().getTokenValue();
        });
        log.debug("authz: proactive token refresh succeeded, token={}...",
                token != null && token.length() > 8 ? token.substring(0, 8) : "?");
    }

    /** Stops the proactive refresh scheduler cleanly (A1). */
    public synchronized void stop() {
        if (proactiveScheduler != null) {
            proactiveScheduler.shutdownNow();
            proactiveScheduler = null;
        }
    }

    /**
     * Performs a best-effort startup warm-acquire of a service token (M3).
     *
     * <p>Instead of a lightweight HEAD probe, performs a real OAuth2
     * client-credentials acquisition via the same internal path that
     * {@link #getServiceToken()} uses, so the Spring Security token cache is
     * pre-populated and the first outbound call is instant (matching NestJS
     * behaviour where the startup step warms the cache).
     *
     * <p>Strictly fail-open: on any error, logs a warning and returns without
     * throwing. The explicit token-endpoint timeout ({@code tokenEndpointTimeoutMs})
     * is honoured by the underlying HTTP client via the retry/backoff policy.
     */
    public void probeTokenEndpoint() {
        try {
            // Perform a real acquisition to warm the cache (M3).
            // fetchAndUpdateExpiry() uses the retry policy and stores issuedAt/expiry
            // in the AtomicReferences so proactiveRefreshTick() can compute the threshold.
            fetchAndUpdateExpiry();
            log.debug("authz: startup token warm-acquire succeeded, cache is hot");
        } catch (Exception e) {
            log.warn("authz: startup token warm-acquire failed (fail-open): {}", e.getMessage());
        }
    }

    @Override
    public String getServiceToken() {
        return retry.executeSupplier(() -> {
            OAuth2AuthorizedClient client = manager.authorize(authorizeRequest);
            if (client == null || client.getAccessToken() == null) {
                throw new IllegalStateException("service token authorization returned no client");
            }
            // Keep issuedAt/expiry in sync for the proactive scheduler (A1).
            Instant issuedAt = client.getAccessToken().getIssuedAt();
            Instant expiry   = client.getAccessToken().getExpiresAt();
            if (issuedAt != null) cachedIssuedAt.set(issuedAt);
            if (expiry   != null) cachedExpiry.set(expiry);
            return client.getAccessToken().getTokenValue();
        });
    }

    /**
     * RestTemplate for the OAuth2 token endpoint with an explicit connect+read
     * timeout (G10) and the converters the client-credentials flow requires
     * (form request body + token-response JSON), plus the OAuth2 error handler.
     */
    private static RestTemplate tokenEndpointRestTemplate(int timeoutMs) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        int t = Math.max(1, timeoutMs);
        factory.setConnectTimeout(t);
        factory.setReadTimeout(t);
        RestTemplate restTemplate = new RestTemplate(Arrays.asList(
                new FormHttpMessageConverter(),
                new OAuth2AccessTokenResponseHttpMessageConverter()));
        restTemplate.setRequestFactory(factory);
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        return restTemplate;
    }

    private Retry buildRetry(int maxAttempts, long baseBackoffMs) {
        // Base backoff is 200ms, factor 2.0 — canonical value (B6/G9).
        // NestJS is being aligned to match this value.
        return Retry.of("service-token", RetryConfig.custom()
                .maxAttempts(maxAttempts)
                .intervalFunction(IntervalFunction.ofExponentialBackoff(Math.max(1, baseBackoffMs), 2.0))
                .build());
    }

    /** Count every failed attempt (intermediate retries + final give-up) via the metric callback. */
    private void attachListeners() {
        retry.getEventPublisher().onRetry(e -> onError.accept(e.getLastThrowable()));
        retry.getEventPublisher().onError(e -> onError.accept(e.getLastThrowable()));
    }
}
