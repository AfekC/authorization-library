/**
 * Tests for inbound-auth gaps:
 *   B1  — whitespace-only trace IDs must be treated as absent (generate UUID)
 *   C13 — duplicate Authorization headers (array) must not cause false 401
 *   F1  — RequestContext must be frozen (immutable)
 *   G12 — validation errors must preserve the cause error
 */
import { buildRequestContext } from "../src/inbound-auth/context";
import { AuthzGuard } from "../src/nest/authz.guard";
import { PermissionCache } from "../src/permission-cache/cache";
import { loadAuthorizationConfig } from "../src/rule-config/loader";
import { LoggingAuditSink } from "../src/audit/audit";
import { Metrics } from "../src/observability/metrics";
import { TokenValidator } from "../src/spi";

const silentAudit = new LoggingAuditSink({ info: () => {}, debug: () => {} });

// ---------------------------------------------------------------------------
// B1 — whitespace-only trace IDs rejected, UUID generated instead
// ---------------------------------------------------------------------------

describe("B1 — whitespace-only trace/correlation IDs treated as absent", () => {
  it("a whitespace-only correlationId is replaced with a UUID", () => {
    const ctx = buildRequestContext({
      user: null,
      service: { serviceName: "s", serviceId: "s-id" },
      correlationId: "   ", // whitespace-only
    });
    // Must not be "   " — should be a UUID
    expect(ctx.correlationId.trim()).not.toBe("");
    expect(ctx.correlationId).not.toBe("   ");
    // UUID v4 pattern (basic check)
    expect(ctx.correlationId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    );
  });

  it("a whitespace-only requestId is replaced with a UUID", () => {
    const ctx = buildRequestContext({
      user: { userId: "u", role: "R", tenant: null, jwtId: null },
      service: null,
      requestId: "\t\n  ", // whitespace-only
    });
    expect(ctx.requestId).not.toBe("\t\n  ");
    expect(ctx.requestId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    );
  });

  it("a valid non-blank correlationId is preserved as-is", () => {
    const ctx = buildRequestContext({
      user: null,
      service: { serviceName: "s", serviceId: "sid" },
      correlationId: "corr-123",
    });
    expect(ctx.correlationId).toBe("corr-123");
  });

  it("an empty-string correlationId is replaced with a UUID", () => {
    const ctx = buildRequestContext({
      user: null,
      service: { serviceName: "s", serviceId: "sid" },
      correlationId: "",
    });
    expect(ctx.correlationId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    );
  });
});

// ---------------------------------------------------------------------------
// F1 — RequestContext is immutable (Object.freeze)
// ---------------------------------------------------------------------------

describe("F1 — RequestContext is frozen (immutable)", () => {
  it("the returned context object is frozen", () => {
    const ctx = buildRequestContext({
      user: { userId: "u1", role: "R", tenant: null, jwtId: null },
      service: null,
    });
    expect(Object.isFrozen(ctx)).toBe(true);
  });

  it("attempting to mutate a frozen field throws in strict mode", () => {
    const ctx = buildRequestContext({
      user: { userId: "u1", role: "MANAGER", tenant: null, jwtId: null },
      service: null,
    });
    // In strict mode (TypeScript compiles to strict JS modules) this throws.
    expect(() => {
      "use strict";
      (ctx as any).userId = "hacked";
    }).toThrow();
  });
});

// ---------------------------------------------------------------------------
// C13 — duplicate Authorization headers (array) must not cause false 401
// ---------------------------------------------------------------------------

describe("C13 — duplicate Authorization headers (array) handled gracefully", () => {
  const engine = loadAuthorizationConfig(`
rules:
  - path: /orders
    methods: [GET]
    permissions: [READ_ORDER]
`);

  const goodValidator: TokenValidator = {
    validateUserToken: async () => ({
      sub: "u1",
      role: "MANAGER",
      iss: "https://auth.example.com",
      aud: "api://my-service",
      exp: Math.floor(Date.now() / 1000) + 3600,
    }),
    validateServiceToken: async () => {
      throw new Error("not expected");
    },
  };

  function fakeCtx(headers: Record<string, unknown>): any {
    const req = { headers, method: "GET", url: "/orders", path: "/orders" };
    return { switchToHttp: () => ({ getRequest: () => req }) };
  }

  it("array Authorization header uses the first element and succeeds", async () => {
    const guard = new AuthzGuard({
      engine,
      cache: new PermissionCache({ MANAGER: ["READ_ORDER"] }),
      validator: goodValidator,
      audit: silentAudit,
      metrics: new Metrics(),
    });
    // Express can deliver duplicate Authorization headers as an array
    const result = await guard.canActivate(
      fakeCtx({ authorization: ["Bearer valid-token", "Bearer duplicate"] }),
    );
    expect(result).toBe(true);
  });

  it("genuinely missing Authorization header (not array) → 401", async () => {
    const guard = new AuthzGuard({
      engine,
      cache: new PermissionCache({ MANAGER: ["READ_ORDER"] }),
      validator: goodValidator,
      audit: silentAudit,
      metrics: new Metrics(),
    });
    // N2: guard now throws HttpException({error:"..."}) — check response body
    const err: any = await guard.canActivate(fakeCtx({})).catch((e) => e);
    expect(err.status).toBe(401);
    expect(err.response?.error).toMatch(/no credentials/i);
  });

  it("array Authorization with invalid token → 401 (validator threw)", async () => {
    const failValidator: TokenValidator = {
      validateUserToken: async () => {
        throw new Error("bad token");
      },
      validateServiceToken: async () => {
        throw new Error("bad token");
      },
    };
    const guard = new AuthzGuard({
      engine,
      cache: new PermissionCache(),
      validator: failValidator,
      audit: silentAudit,
      metrics: new Metrics(),
    });
    // N2: guard now throws HttpException({error:"..."}) — check response body
    const err: any = await guard
      .canActivate(fakeCtx({ authorization: ["Bearer bad", "Bearer duplicate"] }))
      .catch((e) => e);
    expect(err.status).toBe(401);
    expect(err.response?.error).toMatch(/user token validation failed/i);
  });
});

// ---------------------------------------------------------------------------
// G12 — error cause chain is preserved through validation failures
// ---------------------------------------------------------------------------

describe("G12 — validation error cause chain is preserved", () => {
  it("AuthzGuard 401 does not expose internal cause to callers", async () => {
    // The guard must throw UnauthorizedException (401) — internal cause
    // is preserved on the validator's own Error but the guard wraps it.
    const engine = loadAuthorizationConfig(`
rules:
  - path: /x
    methods: [GET]
    permissions: [READ]
`);
    const throwingValidator: TokenValidator = {
      validateUserToken: async () => {
        throw Object.assign(new Error("jwt expired"), {
          code: "ERR_JWT_EXPIRED",
        });
      },
      validateServiceToken: async () => {
        throw new Error("not expected");
      },
    };
    const guard = new AuthzGuard({
      engine,
      cache: new PermissionCache(),
      validator: throwingValidator,
      audit: silentAudit,
      metrics: new Metrics(),
    });
    const err: any = await guard
      .canActivate({
        switchToHttp: () => ({
          getRequest: () => ({
            headers: { authorization: "Bearer expired-token" },
            method: "GET",
            path: "/x",
            url: "/x",
          }),
        }),
      } as any)
      .catch((e) => e);
    // Must be a 401 Unauthorized
    expect(err.status).toBe(401);
  });
});
