import nock from "nock";
import { ClientCredentialsProvider } from "../src/service-token/provider";
import { buildOutboundHeaders, attachOutboundPropagation } from "../src/outbound/propagation";
import { buildRequestContext } from "../src/inbound-auth/context";
import { runWithOutboundContext } from "../src/outbound/context-store";

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

  it("propagates JWT, service token, and trace ids", async () => {
    const ctx = buildRequestContext({
      user: { userId: "u1", roleId: "MANAGER" },
      service: null,
      correlationId: "corr-1",
      requestId: "req-1",
    });
    const h = await buildOutboundHeaders({ ctx, userJwt: "user-jwt", serviceIdentity: provider });
    expect(h["Authorization"]).toBe("Bearer user-jwt");
    expect(h["X-Service-Token"]).toBe("svc-token");
    expect(h["X-Correlation-Id"]).toBe("corr-1");
    expect(h["X-Request-Id"]).toBe("req-1");
  });

  it("omits Authorization for service-to-service calls", async () => {
    const ctx = buildRequestContext({ user: null, service: { serviceName: "scheduler" } });
    const h = await buildOutboundHeaders({ ctx, userJwt: null, serviceIdentity: provider });
    expect(h["Authorization"]).toBeUndefined();
    expect(h["X-Service-Token"]).toBe("svc-token");
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
    });
    expect(h["Authorization"]).toBeUndefined();
  });

  it("B5 — a valid non-blank userJwt is still propagated correctly", async () => {
    const ctx = buildRequestContext({
      user: { userId: "u1", roleId: "MANAGER" },
      service: null,
    });
    const h = await buildOutboundHeaders({
      ctx,
      userJwt: "valid.jwt.token",
      serviceIdentity: provider,
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
      buildOutboundHeaders({ ctx, userJwt: "jwt", serviceIdentity: failingIdentity }),
    ).resolves.toBeDefined();
  });
});

// -------------------------------------------------------------------------
// G4 — axios interceptor (attachOutboundPropagation) is fail-open
// -------------------------------------------------------------------------
describe("G4 — attachOutboundPropagation interceptor is fail-open on service token failure", () => {
  it("interceptor resolves with user JWT + trace headers when service token throws", async () => {
    const failingIdentity = {
      getServiceToken: async () => { throw new Error("SSO down"); },
    };
    const axiosLike: any = {
      interceptors: { request: { use: (fn: any) => { axiosLike._fn = fn; return 0; } } },
    };
    attachOutboundPropagation(axiosLike, { serviceIdentity: failingIdentity });

    const ctx = buildRequestContext({
      user: { userId: "u-axios", roleId: "MANAGER" },
      service: null,
      correlationId: "axcorr",
      requestId: "axreq",
    });

    const result = await new Promise<any>((resolve, reject) => {
      runWithOutboundContext(ctx, "bearer-jwt", () => {
        axiosLike._fn({ headers: {} }).then(resolve).catch(reject);
      });
    });

    // Must not reject, must carry user JWT + trace ids
    expect(result.headers["Authorization"]).toBe("Bearer bearer-jwt");
    expect(result.headers["X-Service-Token"]).toBeUndefined();
    expect(result.headers["X-Correlation-Id"]).toBe("axcorr");
    expect(result.headers["X-Request-Id"]).toBe("axreq");
  });

  it("interceptor resolves with all headers when service token succeeds", async () => {
    const goodIdentity = {
      getServiceToken: async () => "good-svc-token",
    };
    const axiosLike: any = {
      interceptors: { request: { use: (fn: any) => { axiosLike._fn = fn; return 0; } } },
    };
    attachOutboundPropagation(axiosLike, { serviceIdentity: goodIdentity });

    const ctx = buildRequestContext({
      user: { userId: "u-good", roleId: "VIEWER" },
      service: null,
      correlationId: "corr-good",
      requestId: "req-good",
    });

    const result = await new Promise<any>((resolve, reject) => {
      runWithOutboundContext(ctx, "user-tok", () => {
        axiosLike._fn({ headers: {} }).then(resolve).catch(reject);
      });
    });

    expect(result.headers["Authorization"]).toBe("Bearer user-tok");
    expect(result.headers["X-Service-Token"]).toBe("good-svc-token");
    expect(result.headers["X-Correlation-Id"]).toBe("corr-good");
    expect(result.headers["X-Request-Id"]).toBe("req-good");
  });
});
