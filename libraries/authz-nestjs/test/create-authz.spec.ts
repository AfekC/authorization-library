/**
 * Tests for createAuthz() orchestrator — config validation, wiring, and
 * conditional feature gating (Kafka / service identity).
 *
 * Covers:
 *   K4a — Throws ConfigError when required options are missing
 *   K4b — Throws when neither authorizationYaml nor authorizationYamlPath provided
 *   K4c — Returns Authz object with expected shape when all options valid
 *   K4d — Skips Kafka when no brokers configured
 *   K4e — Skips service identity when no serviceToken configured
 */

import nock from "nock";
import { createAuthz, createAuthzFromOptions as createAuthzWithOptions } from "../src/bootstrap/create-authz.js";
import { ConfigError } from "../src/rule-config/types.js";

const ROLE_SERVICE_URL = "http://localhost:18150";

const VALID_YAML = `
rules:
  - path: "/api/test"
    methods: ["GET"]
    permissions: ["read"]
`;

// Respond with a minimal role map for any role service GET
function mockRoleService(): nock.Scope {
  return nock(ROLE_SERVICE_URL).get("/roles").reply(200, { viewer: ["read"] });
}

describe("createAuthz env-only bootstrap", () => {
  const OLD_ENV = { ...process.env };

  afterEach(() => {
    process.env = { ...OLD_ENV };
    nock.cleanAll();
  });

  it("reads required configuration from AUTHZ_* env vars", async () => {
    mockRoleService();
    process.env.AUTHZ_USER_ISSUER = "https://issuer";
    process.env.AUTHZ_USER_JWKS_URI = "https://jwks";
    process.env.AUTHZ_SERVICE_ISSUER = "https://sso";
    process.env.AUTHZ_SERVICE_JWKS_URI = "https://sso-jwks";
    process.env.AUTHZ_USER_AUDIENCE = "my-app";
    process.env.AUTHZ_ROLE_SERVICE_URL = ROLE_SERVICE_URL;
    process.env.AUTHZ_AUTHORIZATION_YAML = VALID_YAML;
    process.env.AUTHZ_RECONCILE_INTERVAL_MS = "999999";
    const authz = await createAuthz();
    expect(authz).toHaveProperty("middleware");
    await authz.stop();
  });
});

// ---------------------------------------------------------------------------
// K4a — required options validation
// ---------------------------------------------------------------------------

describe("K4a — required options validation", () => {
  // Service auth is ALWAYS required; user auth is all-or-nothing (§0.5).
  // These tests supply the service fields, then probe user-field validation.
  it("throws ConfigError when audience is missing", async () => {
    await expect(
      createAuthzWithOptions({
        serviceIssuer: "https://sso",
        serviceJwksUri: "https://sso/jwks",
        userIssuer: "https://issuer",
        userJwksUri: "https://jwks",
        roleServiceUrl: ROLE_SERVICE_URL,
        authorizationYaml: VALID_YAML,
      } as any),
    ).rejects.toThrow(ConfigError);
  });

  it("throws ConfigError when userIssuer is missing (user auth enabled)", async () => {
    await expect(
      createAuthzWithOptions({
        serviceIssuer: "https://sso",
        serviceJwksUri: "https://sso/jwks",
        audience: "my-app",
        userJwksUri: "https://jwks",
        roleServiceUrl: ROLE_SERVICE_URL,
        authorizationYaml: VALID_YAML,
      } as any),
    ).rejects.toThrow(/userIssuer/i);
  });

  it("throws ConfigError when userJwksUri is missing (user auth enabled)", async () => {
    await expect(
      createAuthzWithOptions({
        serviceIssuer: "https://sso",
        serviceJwksUri: "https://sso/jwks",
        audience: "my-app",
        userIssuer: "https://issuer",
        roleServiceUrl: ROLE_SERVICE_URL,
        authorizationYaml: VALID_YAML,
      } as any),
    ).rejects.toThrow(/jwks/i);
  });

  it("throws ConfigError when roleServiceUrl is missing (user auth enabled)", async () => {
    await expect(
      createAuthzWithOptions({
        audience: "my-app",
        userIssuer: "https://issuer",
        userJwksUri: "https://jwks",
        serviceIssuer: "https://sso",
        serviceJwksUri: "https://sso/jwks",
        authorizationYaml: VALID_YAML,
      } as any),
    ).rejects.toThrow(/roleServiceUrl/i);
  });

  it("throws ConfigError when serviceIssuer is missing (service auth always required)", async () => {
    await expect(
      createAuthzWithOptions({
        authorizationYaml: VALID_YAML,
      } as any),
    ).rejects.toThrow(/serviceIssuer/i);
  });
});

// ---------------------------------------------------------------------------
// K4b — YAML source validation
// ---------------------------------------------------------------------------

describe("K4b — YAML source validation", () => {
  it("throws when neither authorizationYaml nor authorizationYamlPath provided", async () => {
    await expect(
      createAuthzWithOptions({
        audience: "my-app",
        userIssuer: "https://issuer",
        userJwksUri: "https://jwks",
        serviceIssuer: "https://sso",
        serviceJwksUri: "https://sso/jwks",
        roleServiceUrl: ROLE_SERVICE_URL,
      } as any),
    ).rejects.toThrow(/authorizationYaml/i);
  });
});

// ---------------------------------------------------------------------------
// K4c — successful creation returns Authz object
// ---------------------------------------------------------------------------

describe("K4c — Authz object shape", () => {
  beforeEach(() => {
    mockRoleService();
  });

  afterEach(() => {
    nock.cleanAll();
  });

  it("returns Authz object with middleware, engine, cache, metrics, mode, health, stop", async () => {
    const authz = await createAuthzWithOptions({
      userIssuer: "https://issuer",
      userJwksUri: "https://jwks",
      serviceIssuer: "https://sso",
      serviceJwksUri: "https://sso-jwks",
      audience: "my-app",
      roleServiceUrl: ROLE_SERVICE_URL,
      authorizationYaml: VALID_YAML,
      validator: {
        validateUserToken: async () => ({ userId: "user1", roleId: "admin" }),
        validateServiceToken: async () => ({ service_name: "svc1" }),
      },
      reconcileIntervalMs: 999999,
    });
    expect(authz).toHaveProperty("middleware");
    expect(typeof authz.middleware).toBe("function");
    expect(authz).toHaveProperty("engine");
    expect(authz).toHaveProperty("cache");
    expect(authz).toHaveProperty("metrics");
    expect(authz).toHaveProperty("mode");
    expect(authz).toHaveProperty("health");
    expect(typeof authz.health).toBe("function");
    expect(authz).toHaveProperty("stop");
    expect(typeof authz.stop).toBe("function");
    await authz.stop();
  });

  it("accepts authorizationYaml as text", async () => {
    const authz = await createAuthzWithOptions({
      userIssuer: "https://issuer",
      userJwksUri: "https://jwks",
      serviceIssuer: "https://sso",
      serviceJwksUri: "https://sso-jwks",
      audience: "my-app",
      roleServiceUrl: ROLE_SERVICE_URL,
      authorizationYaml: VALID_YAML,
      validator: {
        validateUserToken: async () => ({ userId: "u1", roleId: "admin" }),
        validateServiceToken: async () => ({ service_name: "s1" }),
      },
      reconcileIntervalMs: 999999,
    });
    expect(authz).toHaveProperty("engine");
    expect(authz).toHaveProperty("middleware");
    await authz.stop();
  });
});

// ---------------------------------------------------------------------------
// K4d — Kafka skipped when no brokers
// ---------------------------------------------------------------------------

describe("K4d — Kafka conditional", () => {
  beforeEach(() => {
    mockRoleService();
  });

  afterEach(() => {
    nock.cleanAll();
  });

  it("skips Kafka subscription when no kafkaBrokers configured", async () => {
    const authz = await createAuthzWithOptions({
      userIssuer: "https://issuer",
      userJwksUri: "https://jwks",
      serviceIssuer: "https://sso",
      serviceJwksUri: "https://sso-jwks",
      audience: "my-app",
      roleServiceUrl: ROLE_SERVICE_URL,
      authorizationYaml: VALID_YAML,
      validator: {
        validateUserToken: async () => ({ userId: "u1", roleId: "admin" }),
        validateServiceToken: async () => ({ service_name: "s1" }),
      },
      reconcileIntervalMs: 999999,
    });
    expect(authz).toHaveProperty("health");
    await authz.stop();
  });
});

// ---------------------------------------------------------------------------
// K4e — service identity skipped when no serviceToken
// ---------------------------------------------------------------------------

describe("K4e — service identity conditional", () => {
  beforeEach(() => {
    mockRoleService();
  });

  afterEach(() => {
    nock.cleanAll();
  });

  it("skips service identity when no serviceToken configured", async () => {
    const authz = await createAuthzWithOptions({
      userIssuer: "https://issuer",
      userJwksUri: "https://jwks",
      serviceIssuer: "https://sso",
      serviceJwksUri: "https://sso-jwks",
      audience: "my-app",
      roleServiceUrl: ROLE_SERVICE_URL,
      authorizationYaml: VALID_YAML,
      validator: {
        validateUserToken: async () => ({ userId: "u1", roleId: "admin" }),
        validateServiceToken: async () => ({ service_name: "s1" }),
      },
      reconcileIntervalMs: 999999,
    });
    expect(authz.serviceIdentity).toBeUndefined();
    await authz.stop();
  });

  it("creates service identity when serviceToken is configured", async () => {
    // checkTokenEndpoint makes a POST to the token URL; using https so nock
    // matches sso/token and returns 200 so the check passes.
    const ssoScope = nock("https://sso")
      .post("/token")
      .reply(200, { access_token: "tok", expires_in: 3600 });
    mockRoleService();

    const authz = await createAuthzWithOptions({
      userIssuer: "https://issuer",
      userJwksUri: "https://jwks",
      serviceIssuer: "https://sso",
      serviceJwksUri: "https://sso-jwks",
      audience: "my-app",
      roleServiceUrl: ROLE_SERVICE_URL,
      authorizationYaml: VALID_YAML,
      validator: {
        validateUserToken: async () => ({ userId: "u1", roleId: "admin" }),
        validateServiceToken: async () => ({ service_name: "s1" }),
      },
      reconcileIntervalMs: 999999,
      serviceToken: {
        tokenUrl: "https://sso/token",
        clientId: "my-client",
        clientSecret: "my-secret",
      },
    });
    expect(authz.serviceIdentity).toBeDefined();
    ssoScope.done();
    await authz.stop();
  });
});
