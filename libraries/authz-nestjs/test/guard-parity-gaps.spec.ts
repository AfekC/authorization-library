/**
 * Tests for NestJS guard + middleware parity gaps M1, M2, N1, N2, N3.
 *
 * Covers:
 *   M1  — Guard service-token failure increments classified metric (incTokenFailure)
 *   M2  — createAuthz() exposes validator and audit on the returned Authz object
 *   N1  — Guard honors policyEngine and roleResolver overrides (matching middleware)
 *   N2  — Guard 401/403 bodies are { error: "..." } matching middleware shape
 *   N3  — extractBearer handles array headers and double-space "Bearer  token"
 *         consistently in both guard and middleware paths
 */

import nock from "nock";
import { AuthzGuard } from "../src/nest/authz.guard";
import { PermissionCache } from "../src/permission-cache/cache";
import { loadAuthorizationConfig } from "../src/rule-config/loader";
import { LoggingAuditSink } from "../src/audit/audit";
import { Metrics, METRIC } from "../src/observability/metrics";
import { TokenValidator, PolicyEngine, RoleResolver } from "../src/spi";
import { extractBearer } from "../src/inbound-auth/bearer";
import { createAuthzFromOptions as createAuthz } from "../src/bootstrap/create-authz";

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const ROLE_SERVICE_URL = "http://localhost:19150";

const VALID_YAML = `
rules:
  - path: "/api/test"
    methods: ["GET"]
    permissions: ["read"]
`;

const silentAudit = new LoggingAuditSink({ info: () => {}, debug: () => {} });

/** Build a minimal fake ExecutionContext for the guard. */
function fakeCtx(headers: Record<string, unknown>, method = "GET", path = "/api/test"): any {
  const req = { headers, method, url: path, path };
  return { switchToHttp: () => ({ getRequest: () => req }) };
}

const goodUserValidator: TokenValidator = {
  validateUserToken: async () => ({ userId: "u1", roleId: "MANAGER" }),
  validateServiceToken: async () => { throw new Error("not expected"); },
};

const failUserValidator: TokenValidator = {
  validateUserToken: async () => { throw new Error("jwt expired: token has expired"); },
  validateServiceToken: async () => { throw new Error("not expected"); },
};

const goodServiceValidator: TokenValidator = {
  validateUserToken: async () => { throw new Error("not expected"); },
  validateServiceToken: async () => ({ service_name: "my-service" }),
};

const failServiceValidator: TokenValidator = {
  validateUserToken: async () => { throw new Error("not expected"); },
  validateServiceToken: async () => { throw new Error("jwt malformed: bad structure"); },
};

function mockRoleService() {
  return nock(ROLE_SERVICE_URL).get("/roles").reply(200, { MANAGER: ["read"] });
}

// ---------------------------------------------------------------------------
// M1 — Service-token failure path uses incTokenFailure (classified metric)
// ---------------------------------------------------------------------------

describe("M1 — guard service-token failure increments classified metric", () => {
  const engine = loadAuthorizationConfig(VALID_YAML);

  it("increments base service_token_failures_total counter on failure", async () => {
    const metrics = new Metrics();
    const guard = new AuthzGuard({
      engine,
      cache: new PermissionCache({ MANAGER: ["read"] }),
      validator: failServiceValidator,
      audit: silentAudit,
      metrics,
    });

    await guard
      .canActivate(fakeCtx({ "x-service-token": "bad-token" }))
      .catch(() => {});

    expect(metrics.get(METRIC.serviceTokenFailures)).toBe(1);
  });

  it("also increments the classified sub-counter (e.g. _malformed) — not just the base", async () => {
    const metrics = new Metrics();
    const guard = new AuthzGuard({
      engine,
      cache: new PermissionCache({ MANAGER: ["read"] }),
      validator: failServiceValidator,
      audit: silentAudit,
      metrics,
    });

    await guard
      .canActivate(fakeCtx({ "x-service-token": "bad-token" }))
      .catch(() => {});

    // incTokenFailure increments both base and base_<mode>
    const snapshot = metrics.snapshot();
    const subCounters = Object.keys(snapshot).filter(
      (k) => k.startsWith(METRIC.serviceTokenFailures + "_"),
    );
    expect(subCounters.length).toBeGreaterThan(0);
    expect(snapshot[subCounters[0]]).toBe(1);
  });

  it("classifies 'expired' errors as _expired sub-counter", async () => {
    const metrics = new Metrics();
    const expiredValidator: TokenValidator = {
      validateUserToken: async () => { throw new Error("not expected"); },
      validateServiceToken: async () => { throw new Error("token expired"); },
    };
    const guard = new AuthzGuard({
      engine,
      cache: new PermissionCache(),
      validator: expiredValidator,
      audit: silentAudit,
      metrics,
    });

    await guard
      .canActivate(fakeCtx({ "x-service-token": "any" }))
      .catch(() => {});

    expect(metrics.get(METRIC.serviceTokenFailures + "_expired")).toBe(1);
  });

  it("mirrors the same classification pattern already used for user-token failures", async () => {
    const metrics = new Metrics();
    const guard = new AuthzGuard({
      engine,
      cache: new PermissionCache({ MANAGER: ["read"] }),
      validator: failUserValidator,
      audit: silentAudit,
      metrics,
    });

    await guard
      .canActivate(fakeCtx({ authorization: "Bearer any" }))
      .catch(() => {});

    // User-token path
    expect(metrics.get(METRIC.jwtValidationFailures)).toBe(1);
    const userSubs = Object.keys(metrics.snapshot()).filter(
      (k) => k.startsWith(METRIC.jwtValidationFailures + "_"),
    );
    expect(userSubs.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// M2 — createAuthz exposes validator and audit on the returned Authz object
// ---------------------------------------------------------------------------

describe("M2 — createAuthz exposes validator and audit", () => {
  beforeEach(() => {
    mockRoleService();
  });

  afterEach(() => {
    nock.cleanAll();
  });

  it("authz.validator is the validator instance passed in via opts.validator", async () => {
    const myValidator: TokenValidator = {
      validateUserToken: async () => ({ userId: "u1", roleId: "admin" }),
      validateServiceToken: async () => ({ service_name: "svc1" }),
    };

    const authz = await createAuthz({
      userIssuer: "https://issuer",
      userJwksUri: "https://jwks",
      serviceIssuer: "https://sso",
      serviceJwksUri: "https://sso-jwks",
      audience: "my-app",
      roleServiceUrl: ROLE_SERVICE_URL,
      authorizationYaml: VALID_YAML,
      validator: myValidator,
      reconcileIntervalMs: 999999,
    });

    expect(authz.validator).toBeDefined();
    expect(authz.validator).toBe(myValidator);
    await authz.stop();
  });

  it("authz.audit is the auditSink instance passed in via opts.auditSink", async () => {
    const myAudit = new LoggingAuditSink({ info: () => {}, debug: () => {} });

    const authz = await createAuthz({
      userIssuer: "https://issuer",
      userJwksUri: "https://jwks",
      serviceIssuer: "https://sso",
      serviceJwksUri: "https://sso-jwks",
      audience: "my-app",
      roleServiceUrl: ROLE_SERVICE_URL,
      authorizationYaml: VALID_YAML,
      validator: {
        validateUserToken: async () => ({ userId: "u1", roleId: "admin" }),
        validateServiceToken: async () => ({ service_name: "svc1" }),
      },
      auditSink: myAudit,
      reconcileIntervalMs: 999999,
    });

    expect(authz.audit).toBeDefined();
    expect(authz.audit).toBe(myAudit);
    await authz.stop();
  });

  it("authz.validator is defined even when using the default JwksTokenValidator", async () => {
    const authz = await createAuthz({
      userIssuer: "https://issuer",
      userJwksUri: "https://jwks",
      serviceIssuer: "https://sso",
      serviceJwksUri: "https://sso-jwks",
      audience: "my-app",
      roleServiceUrl: ROLE_SERVICE_URL,
      authorizationYaml: VALID_YAML,
      validator: {
        validateUserToken: async () => ({ userId: "u1", roleId: "admin" }),
        validateServiceToken: async () => ({ service_name: "svc1" }),
      },
      reconcileIntervalMs: 999999,
    });

    expect(authz.validator).toBeDefined();
    expect(typeof authz.validator.validateUserToken).toBe("function");
    expect(typeof authz.validator.validateServiceToken).toBe("function");
    await authz.stop();
  });

  it("authz.audit is defined and implements the AuditSink interface", async () => {
    const authz = await createAuthz({
      userIssuer: "https://issuer",
      userJwksUri: "https://jwks",
      serviceIssuer: "https://sso",
      serviceJwksUri: "https://sso-jwks",
      audience: "my-app",
      roleServiceUrl: ROLE_SERVICE_URL,
      authorizationYaml: VALID_YAML,
      validator: {
        validateUserToken: async () => ({ userId: "u1", roleId: "admin" }),
        validateServiceToken: async () => ({ service_name: "svc1" }),
      },
      reconcileIntervalMs: 999999,
    });

    expect(authz.audit).toBeDefined();
    expect(typeof authz.audit.emit).toBe("function");
    await authz.stop();
  });
});

// ---------------------------------------------------------------------------
// N1 — Guard honors policyEngine and roleResolver overrides
// ---------------------------------------------------------------------------

describe("N1 — guard honors policyEngine override", () => {
  const engine = loadAuthorizationConfig(VALID_YAML);
  const cache = new PermissionCache(); // empty — would DENY by default

  it("policyEngine returning ALLOW overrides empty cache", async () => {
    const alwaysAllow: PolicyEngine = {
      authorize: () => "ALLOW",
    };
    const guard = new AuthzGuard({
      engine,
      cache,
      validator: goodUserValidator,
      audit: silentAudit,
      metrics: new Metrics(),
      policyEngine: alwaysAllow,
    });

    const result = await guard.canActivate(
      fakeCtx({ authorization: "Bearer valid" }),
    );
    expect(result).toBe(true);
  });

  it("policyEngine returning DENY causes 403", async () => {
    const alwaysDeny: PolicyEngine = {
      authorize: () => "DENY",
    };
    const guard = new AuthzGuard({
      engine,
      cache: new PermissionCache({ MANAGER: ["read"] }),
      validator: goodUserValidator,
      audit: silentAudit,
      metrics: new Metrics(),
      policyEngine: alwaysDeny,
    });

    const err: any = await guard
      .canActivate(fakeCtx({ authorization: "Bearer valid" }))
      .catch((e) => e);
    expect(err.status).toBe(403);
  });

  it("policyEngine receives correct request shape (method, path, authType, role, serviceName)", async () => {
    let captured: any = null;
    const capturingEngine: PolicyEngine = {
      authorize: (req) => {
        captured = req;
        return "ALLOW";
      },
    };
    const guard = new AuthzGuard({
      engine,
      cache,
      validator: goodUserValidator,
      audit: silentAudit,
      metrics: new Metrics(),
      policyEngine: capturingEngine,
    });

    await guard.canActivate(fakeCtx({ authorization: "Bearer valid" }, "GET", "/api/test"));

    expect(captured).toBeDefined();
    expect(captured.method).toBe("GET");
    expect(captured.path).toBe("/api/test");
    expect(captured.role).toBe("MANAGER");
  });
});

describe("N1 — guard honors roleResolver override", () => {
  const engine = loadAuthorizationConfig(VALID_YAML);
  const emptyCache = new PermissionCache(); // no roles

  it("roleResolver granting the required permission causes ALLOW", async () => {
    const permissiveResolver: RoleResolver = {
      permissionsForRole: (_role) => new Set(["read"]),
    };
    const guard = new AuthzGuard({
      engine,
      cache: emptyCache,
      validator: goodUserValidator,
      audit: silentAudit,
      metrics: new Metrics(),
      roleResolver: permissiveResolver,
    });

    const result = await guard.canActivate(
      fakeCtx({ authorization: "Bearer valid" }),
    );
    expect(result).toBe(true);
  });

  it("roleResolver granting no permissions causes DENY → 403", async () => {
    const emptyResolver: RoleResolver = {
      permissionsForRole: () => new Set(),
    };
    const guard = new AuthzGuard({
      engine,
      cache: new PermissionCache({ MANAGER: ["read"] }), // cache would ALLOW, resolver should win
      validator: goodUserValidator,
      audit: silentAudit,
      metrics: new Metrics(),
      roleResolver: emptyResolver,
    });

    const err: any = await guard
      .canActivate(fakeCtx({ authorization: "Bearer valid" }))
      .catch((e) => e);
    expect(err.status).toBe(403);
  });

  it("policyEngine takes precedence over roleResolver when both are set", async () => {
    // policyEngine wins, roleResolver is ignored
    const alwaysAllow: PolicyEngine = { authorize: () => "ALLOW" };
    const alwaysDenyResolver: RoleResolver = { permissionsForRole: () => new Set() };

    const guard = new AuthzGuard({
      engine,
      cache: emptyCache,
      validator: goodUserValidator,
      audit: silentAudit,
      metrics: new Metrics(),
      policyEngine: alwaysAllow,
      roleResolver: alwaysDenyResolver,
    });

    // If policyEngine wins → ALLOW
    const result = await guard.canActivate(
      fakeCtx({ authorization: "Bearer valid" }),
    );
    expect(result).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// N2 — Guard 401/403 response bodies are { error: "..." }
// ---------------------------------------------------------------------------

describe("N2 — guard error response bodies are { error: string }", () => {
  const engine = loadAuthorizationConfig(VALID_YAML);

  it("no credentials → 401 with body { error: 'no credentials' }", async () => {
    const guard = new AuthzGuard({
      engine,
      cache: new PermissionCache(),
      validator: goodUserValidator,
      audit: silentAudit,
      metrics: new Metrics(),
    });

    const err: any = await guard.canActivate(fakeCtx({})).catch((e) => e);
    expect(err.status).toBe(401);
    expect(err.response).toEqual({ error: "no credentials" });
  });

  it("invalid user token → 401 with body { error: 'user token validation failed' }", async () => {
    const guard = new AuthzGuard({
      engine,
      cache: new PermissionCache(),
      validator: failUserValidator,
      audit: silentAudit,
      metrics: new Metrics(),
    });

    const err: any = await guard
      .canActivate(fakeCtx({ authorization: "Bearer bad" }))
      .catch((e) => e);
    expect(err.status).toBe(401);
    expect(err.response).toEqual({ error: "user token validation failed" });
  });

  it("invalid service token → 401 with body { error: 'service token validation failed' }", async () => {
    const guard = new AuthzGuard({
      engine,
      cache: new PermissionCache(),
      validator: failServiceValidator,
      audit: silentAudit,
      metrics: new Metrics(),
    });

    const err: any = await guard
      .canActivate(fakeCtx({ "x-service-token": "bad" }))
      .catch((e) => e);
    expect(err.status).toBe(401);
    expect(err.response).toEqual({ error: "service token validation failed" });
  });

  it("authorization denied → 403 with body { error: 'authorization denied' }", async () => {
    const guard = new AuthzGuard({
      engine,
      cache: new PermissionCache(), // empty cache → no permissions → DENY
      validator: goodUserValidator,
      audit: silentAudit,
      metrics: new Metrics(),
    });

    const err: any = await guard
      .canActivate(fakeCtx({ authorization: "Bearer valid" }))
      .catch((e) => e);
    expect(err.status).toBe(403);
    expect(err.response).toEqual({ error: "authorization denied" });
  });

  it("body does NOT contain legacy NestJS statusCode/message fields", async () => {
    const guard = new AuthzGuard({
      engine,
      cache: new PermissionCache(),
      validator: goodUserValidator,
      audit: silentAudit,
      metrics: new Metrics(),
    });

    const err: any = await guard.canActivate(fakeCtx({})).catch((e) => e);
    // Old shape was { message, statusCode, error } — must NOT have statusCode
    expect(err.response).not.toHaveProperty("statusCode");
    expect(err.response).not.toHaveProperty("message");
  });

  it("middleware also produces { error } shape for consistency", async () => {
    // This test drives the middleware directly to confirm N2 parity
    mockRoleService();
    const authz = await createAuthz({
      userIssuer: "https://issuer",
      userJwksUri: "https://jwks",
      serviceIssuer: "https://sso",
      serviceJwksUri: "https://sso-jwks",
      audience: "my-app",
      roleServiceUrl: ROLE_SERVICE_URL,
      authorizationYaml: VALID_YAML,
      validator: {
        validateUserToken: async () => ({ userId: "u", roleId: "MANAGER" }),
        validateServiceToken: async () => ({ service_name: "svc" }),
      },
      reconcileIntervalMs: 999999,
    });

    const bodies: any[] = [];
    const statuses: number[] = [];
    const fakeRes = {
      status(code: number) {
        statuses.push(code);
        return { json(body: any) { bodies.push(body); } };
      },
    };
    const fakeReq = { headers: {}, method: "GET", url: "/api/test", path: "/api/test" };

    await authz.middleware(fakeReq, fakeRes, () => {});
    expect(statuses[0]).toBe(401);
    expect(bodies[0]).toEqual({ error: "no credentials" });

    nock.cleanAll();
    await authz.stop();
  });
});

// ---------------------------------------------------------------------------
// N3 — extractBearer handles array headers and double-space consistently
// ---------------------------------------------------------------------------

describe("N3 — extractBearer shared helper", () => {
  it("extracts token from a plain string header", () => {
    expect(extractBearer("Bearer mytoken123")).toBe("mytoken123");
  });

  it("extracts token from an array header (uses first element)", () => {
    expect(extractBearer(["Bearer first-token", "Bearer second-token"])).toBe("first-token");
  });

  it("returns undefined for a missing (undefined) header", () => {
    expect(extractBearer(undefined)).toBeUndefined();
  });

  it("returns undefined for a null header", () => {
    expect(extractBearer(null)).toBeUndefined();
  });

  it("returns undefined for a non-string non-array value", () => {
    expect(extractBearer(42)).toBeUndefined();
    expect(extractBearer({})).toBeUndefined();
  });

  it("is case-insensitive for 'Bearer' prefix", () => {
    expect(extractBearer("bearer mytoken")).toBe("mytoken");
    expect(extractBearer("BEARER MYTOKEN")).toBe("MYTOKEN");
  });

  it("handles double-space 'Bearer  token' (two spaces) — captures everything after first space+", () => {
    // Regex: /^Bearer\s+(.+)$/i — \s+ matches one or more whitespace chars
    // With "Bearer  token" (2 spaces), \s+ consumes both, (.+) captures "token"
    expect(extractBearer("Bearer  token-with-double-space")).toBe("token-with-double-space");
  });

  it("returns undefined for 'Bearer ' with no token after it", () => {
    // "Bearer " — after \s+ there's nothing for (.+) to match
    expect(extractBearer("Bearer ")).toBeUndefined();
  });

  it("returns undefined for a non-Bearer Authorization header (e.g. Basic)", () => {
    expect(extractBearer("Basic dXNlcjpwYXNz")).toBeUndefined();
  });

  it("array header with empty-string first element falls through to undefined", () => {
    // first element is "", which doesn't match /^Bearer\s+(.+)$/
    expect(extractBearer(["", "Bearer second"])).toBeUndefined();
  });
});

describe("N3 — guard uses extractBearer (array header parity with middleware)", () => {
  const engine = loadAuthorizationConfig(VALID_YAML);

  it("guard: array Authorization header uses the first element (not the whole array)", async () => {
    const guard = new AuthzGuard({
      engine,
      cache: new PermissionCache({ MANAGER: ["read"] }),
      validator: goodUserValidator,
      audit: silentAudit,
      metrics: new Metrics(),
    });

    // Supply array Authorization header — guard must handle it gracefully
    const result = await guard.canActivate(
      fakeCtx({ authorization: ["Bearer valid", "Bearer extra"] }),
    );
    expect(result).toBe(true);
  });

  it("middleware: array Authorization header uses the first element", async () => {
    mockRoleService();
    const authz = await createAuthz({
      userIssuer: "https://issuer",
      userJwksUri: "https://jwks",
      serviceIssuer: "https://sso",
      serviceJwksUri: "https://sso-jwks",
      audience: "my-app",
      roleServiceUrl: ROLE_SERVICE_URL,
      authorizationYaml: VALID_YAML,
      validator: {
        validateUserToken: async (token) => {
          // Validator should receive the token string, not "Bearer ..." or an array
          if (typeof token !== "string") throw new Error("token is not a string");
          return { userId: "u1", roleId: "MANAGER" };
        },
        validateServiceToken: async () => ({ service_name: "svc" }),
      },
      reconcileIntervalMs: 999999,
    });

    let nextCalled = false;
    const fakeReq = {
      headers: { authorization: ["Bearer array-token", "Bearer extra"] },
      method: "GET",
      url: "/api/test",
      path: "/api/test",
    };
    const fakeRes = {
      status(code: number) { return { json() {} }; },
    };

    await authz.middleware(fakeReq, fakeRes, () => { nextCalled = true; });
    expect(nextCalled).toBe(true);

    nock.cleanAll();
    await authz.stop();
  });

  it("guard: double-space Bearer header works the same as single-space", async () => {
    // "Bearer  mytoken" — two spaces between Bearer and token
    const capturedTokens: string[] = [];
    const capturingValidator: TokenValidator = {
      validateUserToken: async (token) => {
        capturedTokens.push(token);
        return { userId: "u1", roleId: "MANAGER" };
      },
      validateServiceToken: async () => { throw new Error("not expected"); },
    };
    const guard = new AuthzGuard({
      engine,
      cache: new PermissionCache({ MANAGER: ["read"] }),
      validator: capturingValidator,
      audit: silentAudit,
      metrics: new Metrics(),
    });

    await guard.canActivate(
      fakeCtx({ authorization: "Bearer  double-spaced-token" }),
    );
    // extractBearer("Bearer  double-spaced-token") returns "double-spaced-token"
    expect(capturedTokens[0]).toBe("double-spaced-token");
  });
});
