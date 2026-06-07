import { AccessToken, ClientCredentials } from "simple-oauth2";
import pRetry from "p-retry";
import { ServiceIdentityProvider } from "../spi";

/** Mirrors Java's PROACTIVE_REFRESH_FRACTION = 0.70 (§A1). */
const DEFAULT_PROACTIVE_REFRESH_FRACTION = 0.7;

export interface ClientCredentialsConfig {
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  /** Optional OAuth2 scope. */
  scope?: string;
  /**
   * Refresh when the cached token is within this many seconds of expiry
   * (clock-skew buffer). Reactive, library-native refresh. Default 60.
   */
  refreshBufferSeconds?: number;
  /** Total acquisition attempts before giving up (default 3). */
  maxRetries?: number;
  /**
   * Smallest backoff between retries in ms (default 200, matching Java).
   * B6: Java uses 200ms base backoff; NestJS must match for cross-language parity.
   */
  retryMinTimeoutMs?: number;
  /**
   * HTTP connection/request timeout for token-endpoint calls in ms (default 5000).
   * G10: Explicit timeout prevents hanging on unreachable SSO.
   */
  tokenEndpointTimeoutMs?: number;
  /**
   * Fraction of the token lifetime at which to proactively refresh (default 0.7).
   * A1: Background refresh at ~70% so the first outbound call near expiry never blocks.
   */
  proactiveRefreshFraction?: number;
  /** Called once per failed acquisition attempt (e.g. metrics). */
  onError?: (err: unknown) => void;
  /** Logger used for warnings (defaults to console.warn). */
  logger?: { warn: (msg: string) => void };
}

/**
 * Acquires + caches this service's outbound token via OAuth2 client-credentials,
 * delegating the grant to `simple-oauth2` and retries to `p-retry`.
 *
 * Refresh strategy (§9.1 / A1):
 *   - PROACTIVE: a background timer fires at ~70% of the token lifetime and
 *     refreshes the token silently. Outbound calls near expiry never block.
 *   - REACTIVE (safety net): if a call arrives and the cached token is within
 *     `refreshBufferSeconds` of expiry, it is refreshed on-demand.
 *
 * Fail-open design (G4):
 *   - `getServiceToken()` throws after retry exhaustion.
 *   - Callers (the outbound interceptor) catch that error, log a warning, and
 *     omit X-Service-Token rather than killing the whole request.
 *
 * Lifecycle:
 *   - Call `close()` (e.g. on shutdown) to cancel the proactive refresh timer.
 *   - Call `checkTokenEndpoint()` at startup for a best-effort reachability probe.
 */
export class ClientCredentialsProvider implements ServiceIdentityProvider {
  private readonly client: ClientCredentials;
  private readonly scope?: string;
  private readonly refreshBufferSeconds: number;
  private readonly maxRetries: number;
  readonly retryMinTimeoutMs: number;          // readable for tests (B6)
  readonly tokenEndpointTimeoutMs: number;     // readable for tests (G10)
  private readonly proactiveRefreshFraction: number;
  private readonly onError?: (err: unknown) => void;
  private readonly logger: { warn: (msg: string) => void };
  private cached?: AccessToken;
  private inflight?: Promise<string>;
  /** Handle returned by setTimeout for the proactive refresh, or null when idle. */
  _proactiveTimer: ReturnType<typeof setTimeout> | null = null; // accessible for tests (A1)

  constructor(cfg: ClientCredentialsConfig) {
    const url = new URL(cfg.tokenUrl);
    // G10: explicit timeout on the token endpoint HTTP call.
    // simple-oauth2 uses @hapi/wreck which accepts `timeout` as plain milliseconds.
    const timeoutMs = cfg.tokenEndpointTimeoutMs ?? 5000;
    this.client = new ClientCredentials({
      client: { id: cfg.clientId, secret: cfg.clientSecret },
      auth: { tokenHost: url.origin, tokenPath: url.pathname },
      options: { authorizationMethod: "body" }, // send credentials in the form body
      http: { timeout: timeoutMs } as any, // wreck option; simple-oauth2 passes http opts through
    });
    this.scope = cfg.scope;
    this.refreshBufferSeconds = cfg.refreshBufferSeconds ?? 60;
    this.maxRetries = cfg.maxRetries ?? 3;
    // B6: default 200ms matches Java's 200ms base backoff (not p-retry's 1000ms default)
    this.retryMinTimeoutMs = cfg.retryMinTimeoutMs ?? 200;
    // G10: explicit HTTP timeout (default 5s)
    this.tokenEndpointTimeoutMs = cfg.tokenEndpointTimeoutMs ?? 5000;
    // A1: proactive refresh at 70% of token lifetime by default
    this.proactiveRefreshFraction = cfg.proactiveRefreshFraction ?? DEFAULT_PROACTIVE_REFRESH_FRACTION;
    this.onError = cfg.onError;
    this.logger = cfg.logger ?? { warn: (m) => console.warn(m) };
  }

  async getServiceToken(): Promise<string> {
    if (this.cached && !this.cached.expired(this.refreshBufferSeconds)) {
      return String(this.cached.token.access_token);
    }
    if (this.inflight) return this.inflight;
    this.inflight = this.acquire().finally(() => (this.inflight = undefined));
    return this.inflight;
  }

  /**
   * Cancel the proactive refresh timer. Call this during shutdown to allow the
   * process to exit cleanly (A1 — provides a way to stop the timer).
   */
  close(): void {
    if (this._proactiveTimer !== null) {
      clearTimeout(this._proactiveTimer);
      this._proactiveTimer = null;
    }
  }

  /**
   * Best-effort startup reachability check for the token endpoint (G11).
   * Attempts one token acquisition; if it succeeds, the token is cached.
   * On any error, logs a warning and resolves — NEVER throws (fail-open).
   */
  async checkTokenEndpoint(): Promise<void> {
    try {
      await this.getServiceToken();
    } catch (err) {
      this.logger.warn(
        `[authz] Token endpoint reachability check failed (fail-open): ${String(err)}`,
      );
    }
  }

  private async acquire(): Promise<string> {
    const token = await pRetry(
      () => this.client.getToken(this.scope ? { scope: this.scope } : {}),
      {
        retries: Math.max(0, this.maxRetries - 1),
        minTimeout: this.retryMinTimeoutMs,
        onFailedAttempt: (err) => this.onError?.(err),
      },
    );
    this.cached = token;
    this.armProactiveRefresh(token);
    return String(token.token.access_token);
  }

  /**
   * Schedule a background refresh at ~70% of the token's lifetime (A1).
   * This ensures the cache is warm before the reactive refreshBufferSeconds window.
   */
  private armProactiveRefresh(token: AccessToken): void {
    // Cancel any existing timer before arming a new one.
    this.close();

    const expiresIn = Number(token.token.expires_in); // seconds
    if (!isFinite(expiresIn) || expiresIn <= 0) return; // no sensible lifetime

    const delayMs = Math.floor(expiresIn * this.proactiveRefreshFraction * 1000);
    if (delayMs <= 0) return;

    this._proactiveTimer = setTimeout(() => {
      this._proactiveTimer = null;
      // Trigger a background refresh; failures are logged, not propagated.
      this.acquire().catch((err) => {
        this.logger.warn(
          `[authz] Proactive token refresh failed (reactive path will retry): ${String(err)}`,
        );
      });
    }, delayMs);

    // unref() so the timer does not prevent process exit when the service
    // is shutting down and close() hasn't been explicitly called.
    if (typeof this._proactiveTimer === "object" && this._proactiveTimer !== null &&
        "unref" in this._proactiveTimer) {
      (this._proactiveTimer as any).unref();
    }
  }
}
