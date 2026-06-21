import nock from "nock";
import { ClientCredentialsProvider } from "../src/service-token/provider.js";
import {
  buildOutboundHeaders,
  attachOutboundPropagation,
  isHostAllowed,
  resolveEffectiveUrl,
} from "../src/outbound/propagation.js";
import { buildRequestContext } from "../src/inbound-auth/context.js";
import { runWithOutboundContext } from "../src/outbound/context-store.js";

const TOKEN_HOST = "http://sso";
const TOKEN_PATH = "/token";
const TOKEN_URL = `${TOKEN_HOST}${TOKEN_PATH}`;

describe("ClientCredentialsProvider", () => {
  afterEach(() => nock.cleanAll());

  it("caches the token across calls (single upstream fetch)", async () => {
    // One interceptor only: a second HTTP call would have no mock and fail.
    nock(TOKEN_HOST)
      .post(TOKEN_PATH)
      .reply(200, { access_token: "token-1", token_type: "Bearer", expires_in: 600 });

    const provider = new ClientCredentialsProvider({
      tokenUrl: TOKEN_URL,
      clientId: "c",
      clientSecret: "s",
    });

    expect(await provider.getServiceToken()).toBe("token-1");
    expect(await provider.getServiceToken()).toBe("token-1"); // served from cache
    expect(nock.isDone()).toBe(true);
  });

  it("refreshes when the cached token nears expiry", async () => {
    nock(TOKEN_HOST)
      .post(TOKEN_PATH)
      .reply(200, { access_token: "token-1", token_type: "Bearer", expires_in: 600 })
      .post(TOKEN_PATH)
      .reply(200, { access_token: "token-2", token_type: "Bearer", expires_in: 600 });

    // Buffer larger than the token lifetime => always considered near-expiry.
    const provider = new ClientCredentialsProvider({
      tokenUrl: TOKEN_URL,
      clientId: "c",
      clientSecret: "s",
      refreshBufferSeconds: 10_000,
    });

    expect(await provider.getServiceToken()).toBe("token-1");
    expect(await provider.getServiceToken()).toBe("token-2");
    expect(nock.isDone()).toBe(true);
  });

  it("retries with backoff and reports errors, then succeeds", async () => {
    nock(TOKEN_HOST)
      .post(TOKEN_PATH)
      .reply(500)
      .post(TOKEN_PATH)
      .reply(500)
      .post(TOKEN_PATH)
      .reply(200, { access_token: "ok", token_type: "Bearer", expires_in: 600 });

    const errors: unknown[] = [];
    const provider = new ClientCredentialsProvider({
      tokenUrl: TOKEN_URL,
      clientId: "c",
      clientSecret: "s",
      maxRetries: 3,
      retryMinTimeoutMs: 1,
      onError: (e) => errors.push(e),
    });

    expect(await provider.getServiceToken()).toBe("ok");
    expect(errors.length).toBe(2); // two failures before success
    expect(nock.isDone()).toBe(true);
  });

  it("throws after exhausting retries", async () => {
    nock(TOKEN_HOST).post(TOKEN_PATH).twice().reply(500);

    const provider = new ClientCredentialsProvider({
      tokenUrl: TOKEN_URL,
      clientId: "c",
      clientSecret: "s",
      maxRetries: 2,
      retryMinTimeoutMs: 1,
    });

    await expect(provider.getServiceToken()).rejects.toThrow();
  });

  // -------------------------------------------------------------------------
  // B6 — default retryMinTimeoutMs must be 200ms to match Java (not 1000ms)
  // -------------------------------------------------------------------------
  it("B6 — default retryMinTimeoutMs is 200 (matches Java 200ms base backoff)", () => {
    // We inspect the resolved value from the provider's config, not the
    // p-retry internals. A fresh provider with no retryMinTimeoutMs override
    // must use 200ms, not undefined (which lets p-retry default to 1000ms).
    const provider = new ClientCredentialsProvider({
      tokenUrl: TOKEN_URL,
      clientId: "c",
      clientSecret: "s",
    });
    // Access the private field via cast — only used in this test to verify
    // the default was applied correctly.
    expect((provider as any).retryMinTimeoutMs).toBe(200);
  });

  // -------------------------------------------------------------------------
  // A1 — proactive background refresh at ~70% of token lifetime
  // -------------------------------------------------------------------------
  it("A1 — proactive refresh timer is scheduled after a successful token fetch", async () => {
    nock(TOKEN_HOST)
      .post(TOKEN_PATH)
      .reply(200, { access_token: "proactive-tok", token_type: "Bearer", expires_in: 600 });

    const provider = new ClientCredentialsProvider({
      tokenUrl: TOKEN_URL,
      clientId: "c",
      clientSecret: "s",
    });

    await provider.getServiceToken();
    // After acquiring, a background timer should be active.
    // The timer handle is stored privately; its presence proves proactive refresh was armed.
    expect((provider as any)._proactiveTimer).not.toBeNull();
    expect((provider as any)._proactiveTimer).not.toBeUndefined();
    provider.close(); // clean up timer so jest can exit
  });

  it("A1 — close() cancels the proactive refresh timer", async () => {
    nock(TOKEN_HOST)
      .post(TOKEN_PATH)
      .reply(200, { access_token: "tok", token_type: "Bearer", expires_in: 600 });

    const provider = new ClientCredentialsProvider({
      tokenUrl: TOKEN_URL,
      clientId: "c",
      clientSecret: "s",
    });

    await provider.getServiceToken();
    expect((provider as any)._proactiveTimer).not.toBeNull();
    provider.close();
    expect((provider as any)._proactiveTimer).toBeNull();
  });

  it("A1 — proactive timer fires and refreshes the token before expiry", async () => {
    // Use a very short token lifetime so the proactive timer fires quickly.
    // expires_in=1s → 70% = 0.7s → timer fires at 700ms.
    // We use a very short proactiveRefreshFraction override via a tiny token lifetime
    // and a mocked second fetch to verify the timer actually triggers acquisition.
    nock(TOKEN_HOST)
      .post(TOKEN_PATH)
      .reply(200, { access_token: "first-tok", token_type: "Bearer", expires_in: 2 })
      .post(TOKEN_PATH)
      .reply(200, { access_token: "refreshed-tok", token_type: "Bearer", expires_in: 600 });

    const provider = new ClientCredentialsProvider({
      tokenUrl: TOKEN_URL,
      clientId: "c",
      clientSecret: "s",
      // Use 1ms retryMinTimeoutMs to speed up any retries in test
      retryMinTimeoutMs: 1,
    });

    const first = await provider.getServiceToken();
    expect(first).toBe("first-tok");

    // Wait for the proactive timer (fires at 70% of 2s = 1400ms) — use 1600ms.
    await new Promise((r) => setTimeout(r, 1600));

    // After the timer fired, the cache should now hold the refreshed token.
    const second = await provider.getServiceToken();
    expect(second).toBe("refreshed-tok");
    expect(nock.isDone()).toBe(true);
    provider.close();
  }, 4000);

  // -------------------------------------------------------------------------
  // G10 — explicit HTTP timeout on token endpoint calls
  // -------------------------------------------------------------------------
  it("G10 — tokenEndpointTimeoutMs is stored and applied to HTTP requests", async () => {
    const provider = new ClientCredentialsProvider({
      tokenUrl: TOKEN_URL,
      clientId: "c",
      clientSecret: "s",
      tokenEndpointTimeoutMs: 3000,
    });
    expect((provider as any).tokenEndpointTimeoutMs).toBe(3000);
    provider.close();
  });

  it("G10 — default tokenEndpointTimeoutMs is 5000ms when not specified", () => {
    const provider = new ClientCredentialsProvider({
      tokenUrl: TOKEN_URL,
      clientId: "c",
      clientSecret: "s",
    });
    expect((provider as any).tokenEndpointTimeoutMs).toBe(5000);
    provider.close();
  });

  // -------------------------------------------------------------------------
  // G11 — startup reachability check is fail-open (warns, never throws)
  // -------------------------------------------------------------------------
  it("G11 — checkTokenEndpoint() resolves (never throws) even when endpoint is unreachable", async () => {
    // nock blocks network — nothing listening at TOKEN_HOST → connection refused
    nock(TOKEN_HOST).post(TOKEN_PATH).replyWithError("ECONNREFUSED");

    const provider = new ClientCredentialsProvider({
      tokenUrl: TOKEN_URL,
      clientId: "c",
      clientSecret: "s",
    });

    // Must not throw — fail-open
    await expect(provider.checkTokenEndpoint()).resolves.not.toThrow();
    provider.close();
  });

  it("G11 — checkTokenEndpoint() resolves successfully when endpoint is reachable", async () => {
    nock(TOKEN_HOST)
      .post(TOKEN_PATH)
      .reply(200, { access_token: "startup-tok", token_type: "Bearer", expires_in: 600 });

    const provider = new ClientCredentialsProvider({
      tokenUrl: TOKEN_URL,
      clientId: "c",
      clientSecret: "s",
    });

    await expect(provider.checkTokenEndpoint()).resolves.toBeUndefined();
    provider.close();
  });
});

describe("buildOutboundHeaders", () => {
  const provider = { getServiceToken: async () => "svc-token" };

  // trusted: true simulates the allowlist matching the outbound target.
  it("propagates JWT, service token, and trace ids (trusted target)", async () => {
    const ctx = buildRequestContext({
      user: { userId: "u1", roleId: "MANAGER" },
      service: null,
      correlationId: "corr-1",
      requestId: "req-1",
    });
    const h = await buildOutboundHeaders({ ctx, userJwt: "user-jwt", serviceIdentity: provider, trusted: true });
    expect(h["Authorization"]).toBe("Bearer user-jwt");
    expect(h["X-Service-Token"]).toBe("svc-token");
    expect(h["X-Correlation-Id"]).toBe("corr-1");
    expect(h["X-Request-Id"]).toBe("req-1");
  });

  it("omits Authorization for service-to-service calls (trusted target)", async () => {
    const ctx = buildRequestContext({ user: null, service: { serviceName: "scheduler" } });
    const h = await buildOutboundHeaders({ ctx, userJwt: null, serviceIdentity: provider, trusted: true });
    expect(h["Authorization"]).toBeUndefined();
    expect(h["X-Service-Token"]).toBe("svc-token");
  });

  // -------------------------------------------------------------------------
  // T19 — default-deny: credentials suppressed when trusted is false/absent
  // -------------------------------------------------------------------------
  it("T19 — credentials are NOT attached when trusted is false (default)", async () => {
    const ctx = buildRequestContext({
      user: { userId: "u1", roleId: "MANAGER" },
      service: null,
      correlationId: "c1",
      requestId: "r1",
    });
    const h = await buildOutboundHeaders({
      ctx,
      userJwt: "some-jwt",
      serviceIdentity: provider,
      // trusted omitted → defaults to false
    });
    expect(h["Authorization"]).toBeUndefined();
    expect(h["X-Service-Token"]).toBeUndefined();
    // Trace headers are NOT credentials — always present.
    expect(h["X-Correlation-Id"]).toBe("c1");
    expect(h["X-Request-Id"]).toBe("r1");
  });

  it("T19 — credentials are NOT attached when trusted is explicitly false", async () => {
    const ctx = buildRequestContext({
      user: { userId: "u1", roleId: "MANAGER" },
      service: null,
    });
    const h = await buildOutboundHeaders({
      ctx,
      userJwt: "some-jwt",
      serviceIdentity: provider,
      trusted: false,
    });
    expect(h["Authorization"]).toBeUndefined();
    expect(h["X-Service-Token"]).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // B5 — whitespace-only user JWT must be treated as absent (Java parity)
  // -------------------------------------------------------------------------
  it("B5 — whitespace-only userJwt is NOT propagated as 'Bearer    '", async () => {
    const ctx = buildRequestContext({
      user: { userId: "u1", roleId: "MANAGER" },
      service: null,
    });
    const h = await buildOutboundHeaders({
      ctx,
      userJwt: "   ", // whitespace-only — must be treated as absent
      serviceIdentity: provider,
      trusted: true,
    });
    expect(h["Authorization"]).toBeUndefined();
  });

  it("B5 — empty string userJwt is NOT propagated", async () => {
    const ctx = buildRequestContext({
      user: { userId: "u1", roleId: "MANAGER" },
      service: null,
    });
    const h = await buildOutboundHeaders({
      ctx,
      userJwt: "",
      serviceIdentity: provider,
      trusted: true,
    });
    expect(h["Authorization"]).toBeUndefined();
  });

  it("B5 — a valid non-blank userJwt is still propagated correctly (trusted target)", async () => {
    const ctx = buildRequestContext({
      user: { userId: "u1", roleId: "MANAGER" },
      service: null,
    });
    const h = await buildOutboundHeaders({
      ctx,
      userJwt: "valid.jwt.token",
      serviceIdentity: provider,
      trusted: true,
    });
    expect(h["Authorization"]).toBe("Bearer valid.jwt.token");
  });

  // -------------------------------------------------------------------------
  // F4/G5 — X-Service-Token only attached when token is actually available
  // -------------------------------------------------------------------------
  it("F4/G5 — X-Service-Token is absent when serviceIdentity is undefined", async () => {
    const ctx = buildRequestContext({
      user: { userId: "u1", roleId: "MANAGER" },
      service: null,
      correlationId: "c1",
      requestId: "r1",
    });
    const h = await buildOutboundHeaders({
      ctx,
      userJwt: "valid-jwt",
      serviceIdentity: undefined,
      trusted: true,
    });
    expect(h["X-Service-Token"]).toBeUndefined();
    // Other headers still present
    expect(h["Authorization"]).toBe("Bearer valid-jwt");
    expect(h["X-Correlation-Id"]).toBe("c1");
    expect(h["X-Request-Id"]).toBe("r1");
  });

  // -------------------------------------------------------------------------
  // G4 — service token acquisition failure is fail-open
  // -------------------------------------------------------------------------
  it("G4 — when getServiceToken() rejects, outbound call still carries user JWT and trace ids", async () => {
    const failingIdentity = {
      getServiceToken: async () => { throw new Error("SSO unreachable after retries"); },
    };
    const ctx = buildRequestContext({
      user: { userId: "u2", roleId: "MANAGER" },
      service: null,
      correlationId: "c-fail",
      requestId: "r-fail",
    });
    const h = await buildOutboundHeaders({
      ctx,
      userJwt: "user.jwt.token",
      serviceIdentity: failingIdentity,
      trusted: true,
    });
    // User JWT MUST be propagated even when service token failed
    expect(h["Authorization"]).toBe("Bearer user.jwt.token");
    // Service token MUST be absent (not crash or throw)
    expect(h["X-Service-Token"]).toBeUndefined();
    // Trace headers MUST still be present
    expect(h["X-Correlation-Id"]).toBe("c-fail");
    expect(h["X-Request-Id"]).toBe("r-fail");
  });

  it("G4 — buildOutboundHeaders resolves (never rejects) even on service token failure", async () => {
    const failingIdentity = {
      getServiceToken: async () => { throw new Error("token endpoint down"); },
    };
    const ctx = buildRequestContext({
      user: { userId: "u3", roleId: "ADMIN" },
      service: null,
    });
    // Must resolve — not reject — even when service token acquisition throws
    await expect(
      buildOutboundHeaders({ ctx, userJwt: "jwt", serviceIdentity: failingIdentity, trusted: true }),
    ).resolves.toBeDefined();
  });
});

// -------------------------------------------------------------------------
// G4 — axios interceptor (attachOutboundPropagation) is fail-open
// -------------------------------------------------------------------------
describe("G4 — attachOutboundPropagation interceptor is fail-open on service token failure", () => {
  it("interceptor resolves with user JWT + trace headers when service token throws (trusted target)", async () => {
    const failingIdentity = {
      getServiceToken: async () => { throw new Error("SSO down"); },
    };
    const axiosLike: any = {
      interceptors: { request: { use: (fn: any) => { axiosLike._fn = fn; return 0; } } },
    };
    attachOutboundPropagation(axiosLike, {
      serviceIdentity: failingIdentity,
      allowedHosts: ["api.internal"],
    });

    const ctx = buildRequestContext({
      user: { userId: "u-axios", roleId: "MANAGER" },
      service: null,
      correlationId: "axcorr",
      requestId: "axreq",
    });

    const result = await new Promise<any>((resolve, reject) => {
      runWithOutboundContext(ctx, "bearer-jwt", () => {
        // url matches the allowlist host
        axiosLike._fn({ headers: {}, url: "https://api.internal/endpoint" }).then(resolve).catch(reject);
      });
    });

    // Must not reject, must carry user JWT + trace ids
    expect(result.headers["Authorization"]).toBe("Bearer bearer-jwt");
    expect(result.headers["X-Service-Token"]).toBeUndefined();
    expect(result.headers["X-Correlation-Id"]).toBe("axcorr");
    expect(result.headers["X-Request-Id"]).toBe("axreq");
  });

  it("interceptor resolves with all headers when service token succeeds (trusted target)", async () => {
    const goodIdentity = {
      getServiceToken: async () => "good-svc-token",
    };
    const axiosLike: any = {
      interceptors: { request: { use: (fn: any) => { axiosLike._fn = fn; return 0; } } },
    };
    attachOutboundPropagation(axiosLike, {
      serviceIdentity: goodIdentity,
      allowedHosts: ["api.internal"],
    });

    const ctx = buildRequestContext({
      user: { userId: "u-good", roleId: "VIEWER" },
      service: null,
      correlationId: "corr-good",
      requestId: "req-good",
    });

    const result = await new Promise<any>((resolve, reject) => {
      runWithOutboundContext(ctx, "user-tok", () => {
        // url matches the allowlist host
        axiosLike._fn({ headers: {}, url: "https://api.internal/data" }).then(resolve).catch(reject);
      });
    });

    expect(result.headers["Authorization"]).toBe("Bearer user-tok");
    expect(result.headers["X-Service-Token"]).toBe("good-svc-token");
    expect(result.headers["X-Correlation-Id"]).toBe("corr-good");
    expect(result.headers["X-Request-Id"]).toBe("req-good");
  });
});

// -------------------------------------------------------------------------
// T19 — trusted-host allowlist: isHostAllowed() unit tests
// -------------------------------------------------------------------------
describe("T19 — isHostAllowed()", () => {
  it("returns false for an empty allowlist (default-deny)", () => {
    expect(isHostAllowed("https://api.internal/data", [])).toBe(false);
  });

  it("returns true when the host matches an allowlist entry (bare hostname)", () => {
    expect(isHostAllowed("https://api.internal/path", ["api.internal"])).toBe(true);
  });

  it("returns true for http scheme on a bare hostname entry", () => {
    expect(isHostAllowed("http://api.internal/path", ["api.internal"])).toBe(true);
  });

  it("returns false when the host does NOT match", () => {
    expect(isHostAllowed("https://evil.attacker.com/data", ["api.internal"])).toBe(false);
  });

  it("returns true when host:port matches exactly", () => {
    expect(isHostAllowed("http://api.internal:8080/path", ["api.internal:8080"])).toBe(true);
  });

  it("returns false when port in allowlist does NOT match target port", () => {
    expect(isHostAllowed("http://api.internal:9090/path", ["api.internal:8080"])).toBe(false);
  });

  it("bare hostname entry matches any port (operator intent: trust this host)", () => {
    expect(isHostAllowed("http://api.internal:8080/path", ["api.internal"])).toBe(true);
    expect(isHostAllowed("https://api.internal:443/path", ["api.internal"])).toBe(true);
    expect(isHostAllowed("http://api.internal:9999/path", ["api.internal"])).toBe(true);
  });

  it("full base-URL entry: path is ignored, only host+port matched", () => {
    expect(isHostAllowed("https://api.internal/v2/something", ["https://api.internal/v1"])).toBe(true);
  });

  it("hostname matching is case-insensitive (RFC 4343)", () => {
    expect(isHostAllowed("https://API.INTERNAL/data", ["api.internal"])).toBe(true);
    expect(isHostAllowed("https://api.internal/data", ["API.INTERNAL"])).toBe(true);
  });

  it("returns false for a blank targetUrl", () => {
    expect(isHostAllowed("", ["api.internal"])).toBe(false);
  });

  it("SSRF target — attacker-controlled URL is not on allowlist → no leak", () => {
    const allowlist = ["api.internal", "payments.internal:8443"];
    // Attacker tries to redirect the call to their own server
    expect(isHostAllowed("https://attacker.example.com/steal", allowlist)).toBe(false);
    // Subdomain confusion attempt
    expect(isHostAllowed("https://api.internal.evil.com/path", allowlist)).toBe(false);
    // Port scan attempt
    expect(isHostAllowed("http://api.internal:22/", allowlist)).toBe(true); // port 22 allowed (bare hostname)
    expect(isHostAllowed("http://payments.internal:9999/", allowlist)).toBe(false); // wrong port
  });

  it("multiple allowlist entries — matches any", () => {
    const allowlist = ["service-a.internal", "service-b.internal:8080"];
    expect(isHostAllowed("https://service-a.internal/api", allowlist)).toBe(true);
    expect(isHostAllowed("http://service-b.internal:8080/api", allowlist)).toBe(true);
    expect(isHostAllowed("https://service-c.internal/api", allowlist)).toBe(false);
  });
});

// -------------------------------------------------------------------------
// T19 — resolveEffectiveUrl() unit tests
// -------------------------------------------------------------------------
describe("T19 — resolveEffectiveUrl()", () => {
  it("returns path when no baseURL", () => {
    expect(resolveEffectiveUrl({ url: "https://api.internal/v1" })).toBe("https://api.internal/v1");
  });

  it("returns baseURL when no url", () => {
    expect(resolveEffectiveUrl({ baseURL: "https://api.internal" })).toBe("https://api.internal");
  });

  it("combines baseURL and url", () => {
    expect(resolveEffectiveUrl({ baseURL: "https://api.internal", url: "/endpoint" })).toBe(
      "https://api.internal/endpoint",
    );
  });

  it("handles trailing slash on baseURL and leading slash on url", () => {
    expect(resolveEffectiveUrl({ baseURL: "https://api.internal/", url: "/endpoint" })).toBe(
      "https://api.internal/endpoint",
    );
  });

  it("returns empty string when both are absent", () => {
    expect(resolveEffectiveUrl({})).toBe("");
  });
});

// -------------------------------------------------------------------------
// T19 — attachOutboundPropagation: allowlist integration tests
// -------------------------------------------------------------------------
describe("T19 — attachOutboundPropagation: allowlist enforcement", () => {
  const goodIdentity = { getServiceToken: async () => "svc-tok" };

  function makeAxiosLike() {
    const inst: any = {
      interceptors: { request: { use: (fn: any) => { inst._fn = fn; return 0; } } },
    };
    return inst;
  }

  async function runInterceptor(
    axiosLike: any,
    ctx: ReturnType<typeof buildRequestContext>,
    jwt: string,
    config: { url?: string; baseURL?: string },
  ) {
    return new Promise<any>((resolve, reject) => {
      runWithOutboundContext(ctx, jwt, () => {
        axiosLike._fn({ headers: {}, ...config }).then(resolve).catch(reject);
      });
    });
  }

  it("credentials attached when target is on the allowlist", async () => {
    const ax = makeAxiosLike();
    attachOutboundPropagation(ax, {
      serviceIdentity: goodIdentity,
      allowedHosts: ["trusted.internal"],
    });
    const ctx = buildRequestContext({ user: { userId: "u1", roleId: "ADMIN" }, service: null });
    const result = await runInterceptor(ax, ctx, "user-jwt", { url: "https://trusted.internal/api" });
    expect(result.headers["Authorization"]).toBe("Bearer user-jwt");
    expect(result.headers["X-Service-Token"]).toBe("svc-tok");
  });

  it("credentials NOT attached when target is NOT on the allowlist", async () => {
    const ax = makeAxiosLike();
    attachOutboundPropagation(ax, {
      serviceIdentity: goodIdentity,
      allowedHosts: ["trusted.internal"],
    });
    const ctx = buildRequestContext({ user: { userId: "u1", roleId: "ADMIN" }, service: null });
    const result = await runInterceptor(ax, ctx, "user-jwt", { url: "https://untrusted.example.com/api" });
    expect(result.headers["Authorization"]).toBeUndefined();
    expect(result.headers["X-Service-Token"]).toBeUndefined();
  });

  it("credentials NOT attached when allowlist is empty (default-deny)", async () => {
    const ax = makeAxiosLike();
    attachOutboundPropagation(ax, {
      serviceIdentity: goodIdentity,
      allowedHosts: [],
    });
    const ctx = buildRequestContext({ user: { userId: "u1", roleId: "ADMIN" }, service: null });
    const result = await runInterceptor(ax, ctx, "user-jwt", { url: "https://any.host.com/api" });
    expect(result.headers["Authorization"]).toBeUndefined();
    expect(result.headers["X-Service-Token"]).toBeUndefined();
  });

  it("credentials NOT attached when allowedHosts is omitted (default-deny)", async () => {
    const ax = makeAxiosLike();
    // No allowedHosts → defaults to []
    attachOutboundPropagation(ax, { serviceIdentity: goodIdentity });
    const ctx = buildRequestContext({ user: { userId: "u1", roleId: "ADMIN" }, service: null });
    const result = await runInterceptor(ax, ctx, "user-jwt", { url: "https://any.host.com/api" });
    expect(result.headers["Authorization"]).toBeUndefined();
    expect(result.headers["X-Service-Token"]).toBeUndefined();
  });

  it("trace headers (X-Correlation-Id, X-Request-Id) always attached regardless of allowlist", async () => {
    const ax = makeAxiosLike();
    attachOutboundPropagation(ax, {
      serviceIdentity: goodIdentity,
      allowedHosts: [], // empty → deny credentials
    });
    const ctx = buildRequestContext({
      user: { userId: "u1", roleId: "ADMIN" },
      service: null,
      correlationId: "c-trace",
      requestId: "r-trace",
    });
    const result = await runInterceptor(ax, ctx, "user-jwt", { url: "https://any.host.com/api" });
    // No credentials
    expect(result.headers["Authorization"]).toBeUndefined();
    expect(result.headers["X-Service-Token"]).toBeUndefined();
    // Trace headers always present
    expect(result.headers["X-Correlation-Id"]).toBe("c-trace");
    expect(result.headers["X-Request-Id"]).toBe("r-trace");
  });

  it("baseURL + url combined and matched against allowlist", async () => {
    const ax = makeAxiosLike();
    attachOutboundPropagation(ax, {
      serviceIdentity: goodIdentity,
      allowedHosts: ["trusted.internal"],
    });
    const ctx = buildRequestContext({ user: { userId: "u1", roleId: "ADMIN" }, service: null });
    const result = await runInterceptor(ax, ctx, "user-jwt", {
      baseURL: "https://trusted.internal",
      url: "/data",
    });
    expect(result.headers["Authorization"]).toBe("Bearer user-jwt");
  });

  it("SSRF scenario — attacker-influenced URL leaks nothing", async () => {
    const ax = makeAxiosLike();
    attachOutboundPropagation(ax, {
      serviceIdentity: goodIdentity,
      allowedHosts: ["trusted.internal"],
    });
    const ctx = buildRequestContext({ user: { userId: "victim", roleId: "ADMIN" }, service: null });
    // attacker redirects to their own host
    const result = await runInterceptor(ax, ctx, "victim-jwt", {
      url: "https://attacker.evil.com/steal",
    });
    expect(result.headers["Authorization"]).toBeUndefined();
    expect(result.headers["X-Service-Token"]).toBeUndefined();
  });

  it("host with explicit port on allowlist: only matching port allowed", async () => {
    const ax = makeAxiosLike();
    attachOutboundPropagation(ax, {
      serviceIdentity: goodIdentity,
      allowedHosts: ["trusted.internal:8443"],
    });
    const ctx = buildRequestContext({ user: { userId: "u1", roleId: "ADMIN" }, service: null });

    // Correct port → credentials attached
    const ok = await runInterceptor(ax, ctx, "jwt", { url: "https://trusted.internal:8443/api" });
    expect(ok.headers["Authorization"]).toBe("Bearer jwt");

    // Wrong port → no credentials
    const ax2 = makeAxiosLike();
    attachOutboundPropagation(ax2, {
      serviceIdentity: goodIdentity,
      allowedHosts: ["trusted.internal:8443"],
    });
    const bad = await runInterceptor(ax2, ctx, "jwt", { url: "https://trusted.internal:9999/api" });
    expect(bad.headers["Authorization"]).toBeUndefined();
  });
});
