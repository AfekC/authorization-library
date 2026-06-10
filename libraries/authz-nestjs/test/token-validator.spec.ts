/**
 * Direct unit tests for JwksTokenValidator (D1/G8).
 *
 * Uses `jose` to generate ephemeral RSA keys and mint JWTs in-process.
 * The JWKS endpoint is served by a lightweight HTTP server so that
 * `createRemoteJWKSet` can fetch it.
 */
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
  userPrincipalFromClaims,
  servicePrincipalFromClaims,
} from "../src/inbound-auth/token-validator";

// ---------------------------------------------------------------------------
// Key + JWKS server helpers
// ---------------------------------------------------------------------------

interface KeySet {
  privateKey: KeyLike;
  publicKey: KeyLike;
  kid: string;
}

async function makeKeySet(alg: string, kid: string): Promise<KeySet> {
  const pair: GenerateKeyPairResult<KeyLike> = await generateKeyPair(alg, {
    extractable: true,
  });
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, kid };
}

/** Start a minimal JWKS HTTP server serving the supplied public keys. */
async function startJwksServer(keySets: KeySet[]): Promise<{
  url: string;
  close: () => Promise<void>;
}> {
  const keys = await Promise.all(
    keySets.map(async (ks) => {
      const jwk = await exportJWK(ks.publicKey);
      return { ...jwk, kid: ks.kid, use: "sig" };
    }),
  );
  const body = JSON.stringify({ keys });

  const server = http.createServer((_req, res) => {
    res.setHeader("content-type", "application/json");
    res.end(body);
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/.well-known/jwks.json`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

/** Mint a signed JWT with arbitrary payload overrides. */
async function mintJwt(
  ks: KeySet,
  claims: Record<string, unknown>,
  alg = "RS256",
): Promise<string> {
  let builder = new SignJWT(claims)
    .setProtectedHeader({ alg, kid: ks.kid });
  if (!("iat" in claims)) builder = builder.setIssuedAt();
  return builder.sign(ks.privateKey as KeyLike);
}

// ---------------------------------------------------------------------------
// Test scaffolding — shared key sets and JWKS servers per suite
// ---------------------------------------------------------------------------

const USER_ISSUER = "https://auth.example.com";
const SERVICE_ISSUER = "https://sso.example.com";
const AUDIENCE = "api://my-service";

let userKeys: KeySet;
let serviceKeys: KeySet;
let wrongKeys: KeySet; // a third keypair to sign with the wrong key
let userJwksServer: { url: string; close: () => Promise<void> };
let serviceJwksServer: { url: string; close: () => Promise<void> };
let validator: JwksTokenValidator;
let cfg: JwksValidatorConfig;

beforeAll(async () => {
  [userKeys, serviceKeys, wrongKeys] = await Promise.all([
    makeKeySet("RS256", "user-key-1"),
    makeKeySet("RS256", "svc-key-1"),
    makeKeySet("RS256", "wrong-key"),
  ]);

  [userJwksServer, serviceJwksServer] = await Promise.all([
    startJwksServer([userKeys]),
    startJwksServer([serviceKeys]),
  ]);

  cfg = {
    userIssuer: USER_ISSUER,
    userJwksUri: userJwksServer.url,
    serviceIssuer: SERVICE_ISSUER,
    serviceJwksUri: serviceJwksServer.url,
    audience: AUDIENCE,
    clockSkewSeconds: 0, // strict — no tolerance by default in these tests
  };

  validator = new JwksTokenValidator(cfg);
}, 15_000);

afterAll(async () => {
  await Promise.all([userJwksServer.close(), serviceJwksServer.close()]);
});

// ---------------------------------------------------------------------------
// Helper: mint valid user / service JWTs
// ---------------------------------------------------------------------------

function validUserJwt(overrides: Record<string, unknown> = {}): Promise<string> {
  return mintJwt(userKeys, {
    sub: "user-123",
    role: "MANAGER",
    tenant: "tenant-1",
    iss: USER_ISSUER,
    aud: AUDIENCE,
    exp: Math.floor(Date.now() / 1000) + 3600,
    jti: "jti-abc",
    ...overrides,
  });
}

function validServiceJwt(
  overrides: Record<string, unknown> = {},
): Promise<string> {
  return mintJwt(serviceKeys, {
    sub: "svc-scheduler",
    service_name: "scheduler",
    client_id: "sched-client",
    token_use: "service",
    iss: SERVICE_ISSUER,
    exp: Math.floor(Date.now() / 1000) + 3600,
    ...overrides,
  });
}

// ===========================================================================
// validateUserToken
// ===========================================================================

describe("JwksTokenValidator.validateUserToken", () => {
  it("D1 — valid token → returns correct claims", async () => {
    const jwt = await validUserJwt();
    const claims = await validator.validateUserToken(jwt);
    expect(claims.sub).toBe("user-123");
    expect(claims["role"]).toBe("MANAGER");
    expect(claims["tenant"]).toBe("tenant-1");
    expect(claims.jti).toBe("jti-abc");
  });

  it("D1 — bad signature → throws (preserves cause, G12)", async () => {
    // Sign with the wrong private key — JWKS has the correct public key
    const jwt = await mintJwt(wrongKeys, {
      sub: "user-x",
      iss: USER_ISSUER,
      aud: AUDIENCE,
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    await expect(validator.validateUserToken(jwt)).rejects.toMatchObject({
      message: expect.stringContaining("user token validation failed"),
      cause: expect.any(Error),
    });
  });

  it("B2/D1 — unexpected algorithm (e.g. HS256) → throws", async () => {
    // Mint a token using HS256 (symmetric) — our validator pins RS256/ES256
    const secret = new TextEncoder().encode("super-secret");
    const jwt = await new SignJWT({
      sub: "user-x",
      iss: USER_ISSUER,
      aud: AUDIENCE,
      exp: Math.floor(Date.now() / 1000) + 3600,
    })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .sign(secret);
    await expect(validator.validateUserToken(jwt)).rejects.toMatchObject({
      message: expect.stringContaining("user token validation failed"),
      cause: expect.any(Error),
    });
  });

  it("D1 — wrong issuer → throws", async () => {
    const jwt = await validUserJwt({ iss: "https://evil.example.com" });
    await expect(validator.validateUserToken(jwt)).rejects.toMatchObject({
      message: expect.stringContaining("user token validation failed"),
      cause: expect.any(Error),
    });
  });

  it("A4/D1 — missing audience → throws", async () => {
    const jwt = await mintJwt(userKeys, {
      sub: "user-x",
      iss: USER_ISSUER,
      // aud deliberately omitted
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    await expect(validator.validateUserToken(jwt)).rejects.toMatchObject({
      message: expect.stringContaining("user token validation failed"),
      cause: expect.any(Error),
    });
  });

  it("A4/D1 — wrong audience → throws", async () => {
    const jwt = await validUserJwt({ aud: "api://wrong-service" });
    await expect(validator.validateUserToken(jwt)).rejects.toMatchObject({
      message: expect.stringContaining("user token validation failed"),
      cause: expect.any(Error),
    });
  });

  it("D1 — expired token → throws", async () => {
    const jwt = await validUserJwt({
      exp: Math.floor(Date.now() / 1000) - 3600, // expired 1 hour ago
    });
    await expect(validator.validateUserToken(jwt)).rejects.toMatchObject({
      message: expect.stringContaining("user token validation failed"),
      cause: expect.any(Error),
    });
  });

  it("A6/D1 — future nbf → throws (clockSkewSeconds=0)", async () => {
    const jwt = await validUserJwt({
      nbf: Math.floor(Date.now() / 1000) + 3600, // not valid for another hour
    });
    await expect(validator.validateUserToken(jwt)).rejects.toMatchObject({
      message: expect.stringContaining("user token validation failed"),
      cause: expect.any(Error),
    });
  });

  it("A6 — nbf within clock skew tolerance is accepted", async () => {
    // Allow 60 s skew; nbf is 30 s in the future → should pass
    const lenientValidator = new JwksTokenValidator({
      ...cfg,
      clockSkewSeconds: 60,
    });
    const jwt = await validUserJwt({
      nbf: Math.floor(Date.now() / 1000) + 30,
    });
    await expect(lenientValidator.validateUserToken(jwt)).resolves.toBeDefined();
  });
});

// ===========================================================================
// validateServiceToken
// ===========================================================================

describe("JwksTokenValidator.validateServiceToken", () => {
  it("D1/G8 — valid service token → returns correct claims", async () => {
    const jwt = await validServiceJwt();
    const claims = await validator.validateServiceToken(jwt);
    expect(claims["token_use"]).toBe("service");
    expect(claims["service_name"]).toBe("scheduler");
  });

  it("D1/G8 — bad signature → throws (preserves cause, G12)", async () => {
    const jwt = await mintJwt(wrongKeys, {
      sub: "svc",
      token_use: "service",
      iss: SERVICE_ISSUER,
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    await expect(validator.validateServiceToken(jwt)).rejects.toMatchObject({
      message: expect.stringContaining("service token validation failed"),
      cause: expect.any(Error),
    });
  });

  it("B2/D1/G8 — alg:none / unexpected alg → throws", async () => {
    const secret = new TextEncoder().encode("super-secret");
    const jwt = await new SignJWT({
      sub: "svc",
      token_use: "service",
      iss: SERVICE_ISSUER,
      exp: Math.floor(Date.now() / 1000) + 3600,
    })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .sign(secret);
    await expect(validator.validateServiceToken(jwt)).rejects.toMatchObject({
      message: expect.stringContaining("service token validation failed"),
      cause: expect.any(Error),
    });
  });

  it("D1/G8 — wrong issuer → throws", async () => {
    const jwt = await validServiceJwt({ iss: "https://evil-sso.example.com" });
    await expect(validator.validateServiceToken(jwt)).rejects.toMatchObject({
      message: expect.stringContaining("service token validation failed"),
      cause: expect.any(Error),
    });
  });

  it("D1/G8 — expired token → throws", async () => {
    const jwt = await validServiceJwt({
      exp: Math.floor(Date.now() / 1000) - 3600,
    });
    await expect(validator.validateServiceToken(jwt)).rejects.toMatchObject({
      message: expect.stringContaining("service token validation failed"),
      cause: expect.any(Error),
    });
  });

  it("A6/D1/G8 — future nbf → throws (clockSkewSeconds=0)", async () => {
    const jwt = await validServiceJwt({
      nbf: Math.floor(Date.now() / 1000) + 3600,
    });
    await expect(validator.validateServiceToken(jwt)).rejects.toMatchObject({
      message: expect.stringContaining("service token validation failed"),
      cause: expect.any(Error),
    });
  });

  it("D1/G8 — wrong token_use → throws", async () => {
    const jwt = await validServiceJwt({ token_use: "access" });
    await expect(validator.validateServiceToken(jwt)).rejects.toThrow(
      /service token rejected/,
    );
  });

  it("D1/G8 — missing token_use → throws", async () => {
    const jwt = await mintJwt(serviceKeys, {
      sub: "svc",
      service_name: "scheduler",
      iss: SERVICE_ISSUER,
      exp: Math.floor(Date.now() / 1000) + 3600,
      // token_use deliberately omitted
    });
    await expect(validator.validateServiceToken(jwt)).rejects.toThrow(
      /service token rejected/,
    );
  });

  it("B3/G3 — empty serviceTokenUseClaim falls back to token_use check", async () => {
    // blank claim name must NOT cause "always fail" — it must enforce token_use
    const strictValidator = new JwksTokenValidator({
      ...cfg,
      serviceTokenUseClaim: "", // empty → should default to "token_use"
    });
    const goodJwt = await validServiceJwt({ token_use: "service" });
    await expect(
      strictValidator.validateServiceToken(goodJwt),
    ).resolves.toBeDefined();

    const badJwt = await validServiceJwt({ token_use: "access" });
    await expect(strictValidator.validateServiceToken(badJwt)).rejects.toThrow(
      /service token rejected/,
    );
  });

  it("B3/G3 — whitespace-only serviceTokenUseClaim falls back to token_use check", async () => {
    const strictValidator = new JwksTokenValidator({
      ...cfg,
      serviceTokenUseClaim: "   ", // whitespace-only → should default to "token_use"
    });
    const goodJwt = await validServiceJwt({ token_use: "service" });
    await expect(
      strictValidator.validateServiceToken(goodJwt),
    ).resolves.toBeDefined();
  });
});

// ===========================================================================
// servicePrincipalFromClaims — service name extraction fallback priority (G8)
// ===========================================================================

describe("servicePrincipalFromClaims — name fallback priority (G8)", () => {
  it("prefers service_name over azp over client_id", () => {
    const p = servicePrincipalFromClaims({
      service_name: "alpha",
      azp: "beta",
      client_id: "gamma",
    });
    expect(p.serviceName).toBe("alpha");
  });

  it("falls back to azp when service_name absent", () => {
    const p = servicePrincipalFromClaims({ azp: "beta", client_id: "gamma" });
    expect(p.serviceName).toBe("beta");
  });

  it("falls back to client_id when service_name and azp absent", () => {
    const p = servicePrincipalFromClaims({ client_id: "gamma" });
    expect(p.serviceName).toBe("gamma");
  });

  it("returns null serviceName when none of the three claims exist", () => {
    const p = servicePrincipalFromClaims({ sub: "something-else" });
    expect(p.serviceName).toBeNull();
  });

  it("derives serviceName from service_name/azp/client_id precedence", () => {
    const p = servicePrincipalFromClaims({
      service_name: "s",
      azp: "az",
      client_id: "c",
    });
    expect(p.serviceName).toBe("s");
  });
});

// ===========================================================================
// userPrincipalFromClaims
// ===========================================================================

describe("userPrincipalFromClaims", () => {
  it("maps userId and roleId claims", () => {
    const p = userPrincipalFromClaims({
      userId: "u-1",
      roleId: "ADMIN",
    });
    expect(p).toEqual({ userId: "u-1", roleId: "ADMIN" });
  });

  it("returns null for absent/invalid claims", () => {
    const p = userPrincipalFromClaims({ userId: "u-1" });
    expect(p.roleId).toBeNull();
  });
});
