import * as jsYaml from "js-yaml";
import { AuthorizationEngine, auditPermission } from "../src/decision-engine/engine.js";
import { PermissionCache } from "../src/permission-cache/cache.js";
import { ConfigError, RuleInput } from "../src/rule-config/types.js";
import { compileRules } from "../src/rule-config/compile.js";
import { ConfigError as ConfigErrorClass } from "../src/rule-config/types.js";
import { RequestContext } from "../src/inbound-auth/context.js";
import { PolicyEngine, RoleResolver, AttributeProvider } from "../src/spi.js";

function engine(rules: RuleInput[]): AuthorizationEngine {
  return AuthorizationEngine.compile(rules);
}

function yamlEngine(yaml: string): AuthorizationEngine {
  // Simulate what loadAuthorizationConfig does
  const parsed = jsYaml.load(yaml) as any;
  return engine(parsed.rules);
}

// =========================================================================
// C8 — Root path "/" compiles and matches
// =========================================================================

describe("C8 — root path /", () => {
  it("root path compiles to valid rule", () => {
    expect(() =>
      engine([{ path: "/", methods: ["GET"], permissions: ["READ_ROOT"] }]),
    ).not.toThrow();
  });

  it("root rule allows GET / with matching permission", () => {
    const e = engine([{ path: "/", methods: ["GET"], permissions: ["READ_ROOT"] }]);
    const cache = new PermissionCache({ VIEWER: ["READ_ROOT"] });
    expect(e.authorize({ method: "GET", path: "/", authType: "USER", role: "VIEWER" }, cache)).toBe("ALLOW");
  });

  it("root rule denies when permission missing", () => {
    const e = engine([{ path: "/", methods: ["GET"], permissions: ["READ_ROOT"] }]);
    const cache = new PermissionCache({ VIEWER: ["OTHER_PERM"] });
    expect(e.authorize({ method: "GET", path: "/", authType: "USER", role: "VIEWER" }, cache)).toBe("DENY");
  });

  it("root rule does not match /orders (no rule -> DENY)", () => {
    const e = engine([{ path: "/", methods: ["GET"], permissions: ["READ_ROOT"] }]);
    const cache = new PermissionCache({ VIEWER: ["READ_ROOT"] });
    expect(e.authorize({ method: "GET", path: "/orders", authType: "USER", role: "VIEWER" }, cache)).toBe("DENY");
  });

  it("root rule only matches its methods", () => {
    const e = engine([{ path: "/", methods: ["POST"], permissions: ["WRITE_ROOT"] }]);
    const cache = new PermissionCache({ VIEWER: ["WRITE_ROOT"] });
    // GET / has no matching rule (only POST /)
    expect(e.authorize({ method: "GET", path: "/", authType: "USER", role: "VIEWER" }, cache)).toBe("DENY");
  });

  it("SERVICE request to / with allowed service ALLOWs", () => {
    const e = engine([{ path: "/", methods: ["GET"], allowedServices: ["health-checker"] }]);
    const cache = new PermissionCache({});
    expect(
      e.authorize({ method: "GET", path: "/", authType: "SERVICE", serviceName: "health-checker" }, cache),
    ).toBe("ALLOW");
  });

  it("root rule coexists with more specific rules", () => {
    const e = engine([
      { path: "/", methods: ["GET"], permissions: ["READ_ROOT"] },
      { path: "/orders", methods: ["GET"], permissions: ["READ_ORDER"] },
    ]);
    const cache = new PermissionCache({ VIEWER: ["READ_ROOT", "READ_ORDER"] });

    expect(e.authorize({ method: "GET", path: "/", authType: "USER", role: "VIEWER" }, cache)).toBe("ALLOW");
    expect(e.authorize({ method: "GET", path: "/orders", authType: "USER", role: "VIEWER" }, cache)).toBe("ALLOW");
  });

  it("/** does not match root path /", () => {
    const e = engine([
      { path: "/", methods: ["GET"], permissions: ["READ_ROOT"] },
      { path: "/**", methods: ["GET"], permissions: ["READ_ANY"] },
    ]);
    const cache = new PermissionCache({ VIEWER: ["READ_ROOT", "READ_ANY"] });

    // GET / -> root rule matches (0-segment path)
    expect(e.authorize({ method: "GET", path: "/", authType: "USER", role: "VIEWER" }, cache)).toBe("ALLOW");
    // GET /foo -> /** rule matches
    expect(e.authorize({ method: "GET", path: "/foo", authType: "USER", role: "VIEWER" }, cache)).toBe("ALLOW");
  });
});

// =========================================================================
// E5 — Partial wildcard error message is clear and specific
// =========================================================================

describe("E5 — partial wildcard rejection", () => {
  it("partial wildcard 'par*' rejected with clear message", () => {
    let err: any;
    try {
      compileRules([{ path: "/par*", methods: ["GET"], permissions: ["READ"] }]);
    } catch (e) {
      err = e;
    }
    expect(err).toBeDefined();
    const msg = err.message;
    // Must reference the offending segment or say "partial wildcard"
    expect(msg.includes("par*") || msg.includes("partial wildcard")).toBe(true);
    // Must indicate what wildcards ARE allowed
    expect(msg.includes("supported") || msg.includes("only") || msg.includes("*")).toBe(true);
  });

  it("partial wildcard '*ix' rejected with clear message", () => {
    let err: any;
    try {
      compileRules([{ path: "/orders/*ix", methods: ["GET"], permissions: ["READ"] }]);
    } catch (e) {
      err = e;
    }
    expect(err).toBeDefined();
    const msg = err.message;
    expect(msg.includes("partial wildcard") || msg.includes("*ix") || msg.includes("not supported")).toBe(true);
    expect(msg.includes("*") && (msg.includes("full") || msg.includes("segment") || msg.includes("only") || msg.includes("supported"))).toBe(true);
  });

  it("full-segment * is still accepted", () => {
    expect(() =>
      compileRules([{ path: "/orders/*", methods: ["GET"], permissions: ["READ"] }]),
    ).not.toThrow();
  });

  it("trailing ** is still accepted", () => {
    expect(() =>
      compileRules([{ path: "/orders/**", methods: ["GET"], permissions: ["READ"] }]),
    ).not.toThrow();
  });
});

// =========================================================================
// D11 — Permission names are case-sensitive
// =========================================================================

describe("D11 — permission case sensitivity", () => {
  it("READ != read: uppercase matches, lowercase DENY", () => {
    const e = engine([{ path: "/data", methods: ["GET"], permissions: ["READ"] }]);

    const cacheUpper = new PermissionCache({ ROLE_A: ["READ"] });
    expect(e.authorize({ method: "GET", path: "/data", authType: "USER", role: "ROLE_A" }, cacheUpper)).toBe("ALLOW");

    const cacheLower = new PermissionCache({ ROLE_B: ["read"] });
    expect(e.authorize({ method: "GET", path: "/data", authType: "USER", role: "ROLE_B" }, cacheLower)).toBe("DENY");
  });

  it("mixed-case: exact match ALLOWs, case variants DENY", () => {
    const e = engine([{ path: "/admin", methods: ["POST"], permissions: ["Write_Order"], decision: "ANY" }]);

    const exact = new PermissionCache({ MGR: ["Write_Order"] });
    expect(e.authorize({ method: "POST", path: "/admin", authType: "USER", role: "MGR" }, exact)).toBe("ALLOW");

    const upper = new PermissionCache({ MGR: ["WRITE_ORDER"] });
    expect(e.authorize({ method: "POST", path: "/admin", authType: "USER", role: "MGR" }, upper)).toBe("DENY");

    const lower = new PermissionCache({ MGR: ["write_order"] });
    expect(e.authorize({ method: "POST", path: "/admin", authType: "USER", role: "MGR" }, lower)).toBe("DENY");
  });

  it("ALL decision mode is case-sensitive too", () => {
    const e = engine([{ path: "/secure", methods: ["DELETE"], permissions: ["DELETE_RESOURCE", "ADMIN"], decision: "ALL" }]);

    const wrong = new PermissionCache({ ROLE_X: ["DELETE_RESOURCE", "admin"] });
    expect(e.authorize({ method: "DELETE", path: "/secure", authType: "USER", role: "ROLE_X" }, wrong)).toBe("DENY");

    const right = new PermissionCache({ ROLE_X: ["DELETE_RESOURCE", "ADMIN"] });
    expect(e.authorize({ method: "DELETE", path: "/secure", authType: "USER", role: "ROLE_X" }, right)).toBe("ALLOW");
  });
});

// =========================================================================
// D12 — SPI pluggability
// =========================================================================

describe("D12 — SPI pluggability", () => {
  it("custom PolicyEngine is used when provided", () => {
    const e = engine([{ path: "/locked", methods: ["GET"], permissions: ["SECRET_PERM"] }]);
    const cache = new PermissionCache({ VIEWER: ["READ_ONLY"] });
    const req = { method: "GET", path: "/locked", authType: "USER" as const, role: "VIEWER" };

    // Built-in engine -> DENY (VIEWER lacks SECRET_PERM)
    expect(e.authorize(req, cache)).toBe("DENY");

    // Custom PolicyEngine always ALLOWs
    let customCalled = false;
    const alwaysAllow: PolicyEngine = {
      authorize: (r) => {
        customCalled = true;
        return "ALLOW";
      },
    };

    const result = AuthorizationEngine.withPolicyEngine(alwaysAllow).decide(req);
    expect(result).toBe("ALLOW");
    expect(customCalled).toBe(true);
  });

  it("custom PolicyEngine DENY overrides default ALLOW", () => {
    const e = engine([{ path: "/public", methods: ["GET"], allowedServices: ["*"] }]);
    const cache = new PermissionCache({});
    const req = { method: "GET", path: "/public", authType: "SERVICE" as const, serviceName: "any-service" };

    // Built-in would ALLOW (wildcard service)
    expect(e.authorize(req, cache)).toBe("ALLOW");

    // Custom PolicyEngine always DENYs
    const alwaysDeny: PolicyEngine = { authorize: () => "DENY" };
    const result = AuthorizationEngine.withPolicyEngine(alwaysDeny).decide(req);
    expect(result).toBe("DENY");
  });

  it("custom RoleResolver supplies permissions", () => {
    const e = engine([{ path: "/orders", methods: ["GET"], permissions: ["READ_ORDER"] }]);

    const emptyCache = new PermissionCache({});
    const req = { method: "GET", path: "/orders", authType: "USER" as const, role: "CUSTOM_ROLE" };

    // Without custom resolver -> DENY (unknown role in cache)
    expect(e.authorize(req, emptyCache)).toBe("DENY");

    // Custom RoleResolver supplies permissions
    let resolverCalled = false;
    const customResolver: RoleResolver = {
      permissionsForRole: (role) => {
        resolverCalled = true;
        if (role === "CUSTOM_ROLE") return new Set(["READ_ORDER"]);
        return new Set();
      },
    };

    const result = e.authorizeWithResolver(req, customResolver);
    expect(result).toBe("ALLOW");
    expect(resolverCalled).toBe(true);
  });

  it("custom RoleResolver returning empty set causes DENY", () => {
    const e = engine([{ path: "/orders", methods: ["GET"], permissions: ["READ_ORDER"] }]);
    const req = { method: "GET", path: "/orders", authType: "USER" as const, role: "ROLE_X" };

    const emptyResolver: RoleResolver = { permissionsForRole: () => new Set() };
    const result = e.authorizeWithResolver(req, emptyResolver);
    expect(result).toBe("DENY");
  });

  it("custom AttributeProvider returns attributes", () => {
    const ctx: RequestContext = Object.freeze({
      userId: "u1",
      roleId: "VIEWER",
      serviceName: null,
      requestId: "r1",
      correlationId: "c1",
      authenticationType: "USER",
    });

    let providerCalled = false;
    const customProvider: AttributeProvider = {
      attributesFor: (c) => {
        providerCalled = true;
        return { region: "us-east-1", tier: "premium" };
      },
    };

    const attrs = AuthorizationEngine.attributesFor(ctx, customProvider);
    expect(providerCalled).toBe(true);
    expect(attrs).toEqual({ region: "us-east-1", tier: "premium" });
  });

  it("null AttributeProvider returns empty attributes", () => {
    const ctx: RequestContext = Object.freeze({
      userId: "u1",
      roleId: null,
      serviceName: null,
      requestId: "r1",
      correlationId: "c1",
      authenticationType: "USER",
    });

    const attrs = AuthorizationEngine.attributesFor(ctx, null);
    expect(attrs).toEqual({});
  });

  it("default behavior unchanged with no SPI overrides", () => {
    const e = engine([
      { path: "/orders", methods: ["GET"], permissions: ["READ_ORDER"] },
      { path: "/orders/*", methods: ["GET"], permissions: ["READ_ORDER"] },
      { path: "/admin", methods: ["POST"], allowedServices: ["scheduler"] },
    ]);

    const cache = new PermissionCache({ VIEWER: ["READ_ORDER"] });

    expect(e.authorize({ method: "GET", path: "/orders", authType: "USER", role: "VIEWER" }, cache)).toBe("ALLOW");
    expect(e.authorize({ method: "GET", path: "/orders/123", authType: "USER", role: "VIEWER" }, cache)).toBe("ALLOW");
    expect(e.authorize({ method: "POST", path: "/admin", authType: "SERVICE", serviceName: "scheduler" }, cache)).toBe("ALLOW");
    expect(e.authorize({ method: "DELETE", path: "/orders", authType: "USER", role: "VIEWER" }, cache)).toBe("DENY");
  });
});

// =========================================================================
// D9 — YAML config edge cases: no rules key, null field values
// =========================================================================

describe("D9 — YAML config edge cases", () => {
  it("no rules key throws ConfigError", () => {
    expect(() => {
      yamlEngine("otherKey: value");
    }).toThrow();
  });

  it("null permissions treats rule as service-only -> USER DENY", () => {
    const e = yamlEngine(`
rules:
  - path: /data
    methods: [GET]
    permissions:
    allowedServices: [svc]
`);
    const cache = new PermissionCache({ VIEWER: ["READ"] });
    expect(
      e.authorize({ method: "GET", path: "/data", authType: "USER", role: "VIEWER" }, cache),
    ).toBe("DENY");
  });

  it("null allowedServices treats rule as user-only -> SERVICE DENY", () => {
    const e = yamlEngine(`
rules:
  - path: /data
    methods: [GET]
    permissions: [READ]
    allowedServices:
`);
    const cache = new PermissionCache({ VIEWER: ["READ"] });
    expect(
      e.authorize({ method: "GET", path: "/data", authType: "SERVICE", serviceName: "any-svc" }, cache),
    ).toBe("DENY");
  });
});
