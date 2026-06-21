import { createAuthzFromOptions, CreateAuthzOptions, Authz } from "../src/bootstrap/create-authz.js";
import { ConfigError } from "../src/rule-config/types.js";
import { PolicyEngine, RoleResolver, TokenValidator } from "../src/spi/index.js";

/**
 * §0.5b — external permission source mode: the service supplies a RoleResolver
 * (or PolicyEngine) backed by its own store (Redis/Postgres/Infinispan), and the
 * built-in role-distribution machinery (Role Service fetch, reconciler,
 * seed-retry, disk cache, Kafka role events) is OFF. User-JWT validation stays
 * on; `roleServiceUrl` is not required.
 */
const YAML = `
rules:
  - path: /orders
    methods: [GET]
    permissions: [READ_ORDER]
    decision: ANY
  - path: /admin
    methods: [POST]
    permissions: [ADMIN]
    allowedServices: [scheduler]
    decision: ANY
`;

/** Fake validator: skips real JWKS; returns the roleId / serviceName the test wants. */
const fakeValidator = (roleId: string | null, serviceName = "scheduler"): TokenValidator => ({
  validateUserToken: async () => ({ userId: "u-1", roleId }),
  validateServiceToken: async () => ({ service_name: serviceName }),
});

const silentAudit = { emit: () => {} };

function baseOpts(role: string | null, serviceName = "scheduler"): CreateAuthzOptions {
  return {
    authorizationYaml: YAML,
    serviceIssuer: "https://sso.example",
    serviceJwksUri: "https://sso.example/jwks",
    userIssuer: "https://auth.example",
    userJwksUri: "https://auth.example/jwks",
    audience: "client-api",
    externalPermissionSource: true,
    auditSink: silentAudit,
    validator: fakeValidator(role, serviceName),
  };
}

/** Invoke the Express-style middleware; returns 200 (next called) or the deny status. */
async function run(
  authz: Authz,
  opts: { method?: string; url?: string; headers?: Record<string, string> } = {},
): Promise<number> {
  let status = 0;
  let nexted = false;
  const headers = opts.headers ?? { authorization: "Bearer x" };
  const req: any = { method: opts.method ?? "GET", url: opts.url ?? "/orders", path: opts.url ?? "/orders", headers };
  const res: any = { status: (s: number) => ({ json: () => { status = s; } }) };
  await authz.middleware(req, res, () => { nexted = true; });
  return nexted ? 200 : status;
}

describe("external permission source (§0.5b)", () => {
  it("boots without roleServiceUrl and decides via the injected resolver", async () => {
    const resolver: RoleResolver = {
      permissionsForRole: (r: string | null | undefined) => new Set(r === "M" ? ["READ_ORDER"] : []),
    };
    const authz = await createAuthzFromOptions({ ...baseOpts("M"), roleResolver: resolver });
    expect(await run(authz)).toBe(200); // resolver grants READ_ORDER to M
    await authz.stop();
  });

  it("denies when the resolver withholds the permission", async () => {
    const resolver: RoleResolver = { permissionsForRole: () => new Set() };
    const authz = await createAuthzFromOptions({ ...baseOpts("VIEWER"), roleResolver: resolver });
    expect(await run(authz)).toBe(403);
    await authz.stop();
  });

  it("supports a PolicyEngine instead of a resolver", async () => {
    const policyEngine: PolicyEngine = { authorize: (req) => (req.path === "/orders" ? "ALLOW" : "DENY") };
    const authz = await createAuthzFromOptions({ ...baseOpts("M"), policyEngine });
    expect(await run(authz)).toBe(200);
    expect(await run(authz, { method: "POST", url: "/admin", headers: { authorization: "Bearer x" } })).toBe(403);
    await authz.stop();
  });

  it("still enforces the service allow-list for USER_AND_SERVICE requests", async () => {
    const resolver: RoleResolver = { permissionsForRole: () => new Set(["ADMIN"]) };
    const both = { authorization: "Bearer x", "x-service-token": "svc" };

    // service "scheduler" is in the rule's allowedServices -> ALLOW
    const allowed = await createAuthzFromOptions({ ...baseOpts("A", "scheduler"), roleResolver: resolver });
    expect(await run(allowed, { method: "POST", url: "/admin", headers: both })).toBe(200);
    await allowed.stop();

    // user permission granted but service NOT in allowlist -> DENY (allowlist still enforced)
    const denied = await createAuthzFromOptions({ ...baseOpts("A", "intruder"), roleResolver: resolver });
    expect(await run(denied, { method: "POST", url: "/admin", headers: both })).toBe(403);
    await denied.stop();
  });

  it("reports no built-in sync in the health snapshot", async () => {
    const resolver: RoleResolver = { permissionsForRole: () => new Set() };
    const authz = await createAuthzFromOptions({ ...baseOpts("M"), roleResolver: resolver });
    const h = authz.health();
    expect(authz.mode).toBe("normal");
    expect(h.roleServiceLastSync).toBeNull();
    expect(h.kafkaConsumerConnected).toBe(false);
    await authz.stop();
  });

  it("ignores roleServiceUrl entirely (not validated, not used) in external mode", async () => {
    // A bogus roleServiceUrl would fail URL validation in full mode; external mode
    // skips that branch and never constructs the Role Service client.
    const resolver: RoleResolver = { permissionsForRole: () => new Set(["READ_ORDER"]) };
    const authz = await createAuthzFromOptions({
      ...baseOpts("M"),
      roleServiceUrl: "not-a-valid-url",
      roleResolver: resolver,
    });
    expect(authz.health().roleServiceLastSync).toBeNull();
    expect(await run(authz)).toBe(200);
    await authz.stop();
  });

  it("fails fast when external mode is set without a resolver or policy engine", async () => {
    await expect(createAuthzFromOptions(baseOpts("M"))).rejects.toThrow(ConfigError);
  });
});
