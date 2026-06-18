/**
 * Tests for gaps N4, N7, and M4:
 *
 *   N4  — sanitizeHeadersInPlace: in-place removal of untrusted identity headers
 *   N7  — YAML bare-* auto-quoting: bare `*` in arrays must parse as the string "*"
 *   M4  — nbf boundary parity: jose accept/reject at exactly the skew boundary
 */

// ---------------------------------------------------------------------------
// N4 — sanitizeHeadersInPlace
// ---------------------------------------------------------------------------

import {
  sanitizeHeadersInPlace,
  stripUntrustedHeaders,
} from "../src/inbound-auth/context.js";
import { loadAuthorizationConfig } from "../src/rule-config/loader.js";
import { PermissionCache } from "../src/permission-cache/cache.js";
import * as http from "http";
import { AddressInfo } from "net";
import {
  generateKeyPair,
  exportJWK,
  SignJWT,
  GenerateKeyPairResult,
  KeyLike,
} from "jose";
import {
  JwksTokenValidator,
  JwksValidatorConfig,
} from "../src/inbound-auth/token-validator.js";

describe("N4 — sanitizeHeadersInPlace", () => {
  it("mutates the SAME object reference (in-place)", () => {
    const headers: Record<string, unknown> = {
      "x-user-id": "spoof",
      "content-type": "application/json",
    };
    const original = headers;
    sanitizeHeadersInPlace(headers);
    expect(headers).toBe(original); // same reference
  });

  it("removes default identity headers from the object", () => {
    const headers: Record<string, unknown> = {
      "x-user-id": "spoof-uid",
      "x-user-role": "spoof-role",
      "x-role": "admin",
      "x-tenant": "evil-tenant",
      "content-type": "application/json",
      authorization: "Bearer real-token",
      "x-correlation-id": "trace-123",
    };
    sanitizeHeadersInPlace(headers);

    // Identity headers must be gone
    expect(headers["x-user-id"]).toBeUndefined();
    expect(headers["x-user-role"]).toBeUndefined();
    expect(headers["x-role"]).toBeUndefined();
    expect(headers["x-tenant"]).toBeUndefined();

    // Non-identity headers must survive
    expect(headers["content-type"]).toBe("application/json");
    expect(headers["authorization"]).toBe("Bearer real-token");
    expect(headers["x-correlation-id"]).toBe("trace-123");
  });

  it("x-service-token is preserved (consumed by inbound validator, not a spoofed header)", () => {
    // x-service-token is the bearer credential consumed by the inbound auth pipeline
    // (same reason authorization is preserved). Both helpers keep it intact.
    const headers: Record<string, unknown> = {
      "x-service-token": "Bearer svc-token",
      "x-user-id": "spoof",
    };
    sanitizeHeadersInPlace(headers);
    expect(headers["x-service-token"]).toBe("Bearer svc-token"); // kept
    expect(headers["x-user-id"]).toBeUndefined();                // removed
  });

  it("respects additionalPrefixes option", () => {
    const headers: Record<string, unknown> = {
      "x-custom-secret": "stolen",
      "x-user-id": "spoof",
      "content-type": "text/plain",
    };
    sanitizeHeadersInPlace(headers, { additionalPrefixes: ["x-custom-"] });
    expect(headers["x-custom-secret"]).toBeUndefined();
    expect(headers["x-user-id"]).toBeUndefined();
    expect(headers["content-type"]).toBe("text/plain");
  });

  it("respects additionalExactNames option", () => {
    const headers: Record<string, unknown> = {
      "x-internal-user": "spoof",
      "accept": "application/json",
    };
    sanitizeHeadersInPlace(headers, { additionalExactNames: ["x-internal-user"] });
    expect(headers["x-internal-user"]).toBeUndefined();
    expect(headers["accept"]).toBe("application/json");
  });

  it("is consistent with stripUntrustedHeaders — same headers removed", () => {
    const source: Record<string, unknown> = {
      "x-user-id": "spoof",
      "x-role": "admin",
      "x-tenant": "t1",
      "content-type": "application/json",
      authorization: "Bearer tok",
    };

    // stripUntrustedHeaders returns a new object (existing behavior, unchanged)
    const stripped = stripUntrustedHeaders({ ...source });

    // sanitizeHeadersInPlace modifies in-place
    const inPlace = { ...source };
    sanitizeHeadersInPlace(inPlace);

    // Both must yield the same set of keys
    expect(Object.keys(inPlace).sort()).toEqual(Object.keys(stripped).sort());
  });

  it("handles empty headers object without throwing", () => {
    const headers: Record<string, unknown> = {};
    expect(() => sanitizeHeadersInPlace(headers)).not.toThrow();
    expect(Object.keys(headers)).toHaveLength(0);
  });

  it("x-userid exact-name match is removed", () => {
    const headers: Record<string, unknown> = { "x-userid": "spoof", "host": "example.com" };
    sanitizeHeadersInPlace(headers);
    expect(headers["x-userid"]).toBeUndefined();
    expect(headers["host"]).toBe("example.com");
  });
});

// ---------------------------------------------------------------------------
// N7 — YAML bare-* auto-quoting in loader
// ---------------------------------------------------------------------------

describe("N7 — YAML bare-* auto-quoting (parity with Java YamlLoader)", () => {
  it("bare * in allowedServices list parses as the string '*'", () => {
    // Without preprocessing, js-yaml treats bare * as an alias → throws or parses as null.
    // After N7 fix, it must parse to the string "*" and compile without error.
    expect(() =>
      loadAuthorizationConfig(`
rules:
  - path: /public
    methods: [GET]
    allowedServices: [*]
`),
    ).not.toThrow();
  });

  it("engine compiled from bare * allows any service (wildcard behaviour)", () => {
    const engine = loadAuthorizationConfig(`
rules:
  - path: /public
    methods: [GET]
    allowedServices: [*]
`);
    // Any service name must be allowed (the '*' wildcard)
    const cache = PermissionCache;
    const result = engine.authorize(
      { method: "GET", path: "/public", authType: "SERVICE", serviceName: "any-svc" },
      new cache({}),
    );
    expect(result).toBe("ALLOW");
  });

  it("bare * mixed with quoted name in array [*, \"foo\"] parses correctly", () => {
    expect(() =>
      loadAuthorizationConfig(`
rules:
  - path: /mixed
    methods: [POST]
    allowedServices: [*, "named-svc"]
`),
    ).not.toThrow();
  });

  it("[*, \"foo\"] compiled engine allows wildcard and named service", () => {
    const engine = loadAuthorizationConfig(`
rules:
  - path: /mixed
    methods: [POST]
    allowedServices: [*, "named-svc"]
`);
    const c = new PermissionCache({});
    // Wildcard → any service allowed
    expect(engine.authorize({ method: "POST", path: "/mixed", authType: "SERVICE", serviceName: "anything" }, c)).toBe("ALLOW");
    // Named service also allowed
    expect(engine.authorize({ method: "POST", path: "/mixed", authType: "SERVICE", serviceName: "named-svc" }, c)).toBe("ALLOW");
  });

  it("bare * also works in permissions list (permissions: [*]) as string", () => {
    // This is unusual but the preprocessing must not break non-allowedServices arrays.
    // The main goal: it parses as the string "*" rather than crashing.
    expect(() =>
      loadAuthorizationConfig(`
rules:
  - path: /star-perm
    methods: [GET]
    permissions: [*]
`),
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// M4 — nbf boundary parity: jose accept/reject matches Java's nbf-skew > now
//
// Java: Nimbus rejects when nbf - skewSeconds > now
//       i.e. token not-yet-valid AND outside tolerance → reject
// jose: rejects when now < nbf - clockTolerance
//       Both are equivalent: accept when now >= nbf - tolerance
//
// We test:
//   1. nbf = now + skew     → accepted (exactly at boundary)
//   2. nbf = now + skew + 1 → rejected (one second past boundary)
// ---------------------------------------------------------------------------

describe("M4 — nbf boundary parity (jose ≡ Java Nimbus)", () => {
  interface KeySet {
    privateKey: KeyLike;
    publicKey: KeyLike;
    kid: string;
  }

  let userKeys: KeySet;
  let server: { url: string; close: () => Promise<void> };
  let validator5s: JwksTokenValidator;  // clockSkewSeconds = 5

  const USER_ISSUER = "https://auth.example.com";
  const AUDIENCE = "api://m4-test";

  async function makeKeySet(kid: string): Promise<KeySet> {
    const pair: GenerateKeyPairResult<KeyLike> = await generateKeyPair("RS256", { extractable: true });
    return { privateKey: pair.privateKey, publicKey: pair.publicKey, kid };
  }

  async function startJwksServer(ks: KeySet): Promise<{ url: string; close: () => Promise<void> }> {
    const jwk = await exportJWK(ks.publicKey);
    const body = JSON.stringify({ keys: [{ ...jwk, kid: ks.kid, use: "sig" }] });
    const srv = http.createServer((_req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(body);
    });
    await new Promise<void>((resolve) => srv.listen(0, "127.0.0.1", resolve));
    const { port } = srv.address() as AddressInfo;
    return {
      url: `http://127.0.0.1:${port}/.well-known/jwks.json`,
      close: () => new Promise<void>((resolve) => srv.close(() => resolve())),
    };
  }

  async function mintToken(overrides: Record<string, unknown>): Promise<string> {
    return new SignJWT(overrides)
      .setProtectedHeader({ alg: "RS256", kid: userKeys.kid })
      .setIssuedAt()
      .sign(userKeys.privateKey as KeyLike);
  }

  beforeAll(async () => {
    userKeys = await makeKeySet("m4-key");
    server = await startJwksServer(userKeys);

    const cfg: JwksValidatorConfig = {
      userIssuer: USER_ISSUER,
      userJwksUri: server.url,
      serviceIssuer: "https://sso.example.com",
      serviceJwksUri: server.url, // unused in these tests
      audience: AUDIENCE,
      clockSkewSeconds: 5,
    };
    validator5s = new JwksTokenValidator(cfg);
  }, 15_000);

  afterAll(async () => {
    await server.close();
  });

  function basePayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      sub: "u1",
      role: "VIEWER",
      iss: USER_ISSUER,
      aud: AUDIENCE,
      exp: Math.floor(Date.now() / 1000) + 3600,
      ...overrides,
    };
  }

  /**
   * M4-parity: jose accepts nbf = now + skew (exactly at boundary).
   *
   * Java:  accept when (nbf - skew) <= now  →  nbf <= now + skew
   * jose:  accept when now >= nbf - tolerance  (equivalent)
   *
   * At nbf = now + skew → now >= (now + skew) - skew  →  now >= now  ✓ ACCEPT
   */
  it("M4 — nbf exactly at boundary (nbf = now + skew) is ACCEPTED", async () => {
    const skew = 5;
    const now = Math.floor(Date.now() / 1000);
    // nbf is exactly `skew` seconds in the future — right at the tolerance boundary
    const jwt = await mintToken(basePayload({ nbf: now + skew }));
    await expect(validator5s.validateUserToken(jwt)).resolves.toBeDefined();
  });

  /**
   * M4-parity: jose rejects nbf = now + skew + 1 (one second past boundary).
   *
   * At nbf = now + skew + 1 → now < (now + skew + 1) - skew = now + 1  →  REJECT
   */
  it("M4 — nbf one second past boundary (nbf = now + skew + 1) is REJECTED", async () => {
    const skew = 5;
    const now = Math.floor(Date.now() / 1000);
    const jwt = await mintToken(basePayload({ nbf: now + skew + 1 }));
    await expect(validator5s.validateUserToken(jwt)).rejects.toMatchObject({
      message: expect.stringContaining("user token validation failed"),
      cause: expect.any(Error),
    });
  });

  /**
   * M4-parity: nbf well within tolerance is accepted.
   * nbf = now + 2 with skew = 5 → 2 < 5 → ACCEPT
   */
  it("M4 — nbf within tolerance (nbf = now + 2, skew = 5) is ACCEPTED", async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await mintToken(basePayload({ nbf: now + 2 }));
    await expect(validator5s.validateUserToken(jwt)).resolves.toBeDefined();
  });

  /**
   * M4-parity: zero-tolerance validator rejects nbf even 1 second in the future.
   * This mirrors the strict clockSkewSeconds=0 used in the token-validator suite.
   */
  it("M4 — zero-tolerance validator rejects nbf 1 second in future", async () => {
    const strictCfg: JwksValidatorConfig = {
      userIssuer: USER_ISSUER,
      userJwksUri: server.url,
      serviceIssuer: "https://sso.example.com",
      serviceJwksUri: server.url,
      audience: AUDIENCE,
      clockSkewSeconds: 0,
    };
    const strict = new JwksTokenValidator(strictCfg);
    const now = Math.floor(Date.now() / 1000);
    const jwt = await mintToken(basePayload({ nbf: now + 1 }));
    await expect(strict.validateUserToken(jwt)).rejects.toMatchObject({
      message: expect.stringContaining("user token validation failed"),
    });
  });

  /**
   * M4-parity: past nbf (nbf in the past) is always accepted regardless of skew.
   */
  it("M4 — past nbf (already valid) is always accepted", async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await mintToken(basePayload({ nbf: now - 3600 }));
    await expect(validator5s.validateUserToken(jwt)).resolves.toBeDefined();
  });
});
