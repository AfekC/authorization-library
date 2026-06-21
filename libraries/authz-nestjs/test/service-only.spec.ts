import { createAuthzFromOptions, CreateAuthzOptions, Authz } from "../src/bootstrap/create-authz.js";
import { ConfigError } from "../src/rule-config/types.js";
import { TokenValidator } from "../src/spi/index.js";

/**
 * §0.5 — explicit SERVICE-ONLY mode via `serviceOnly: true`: user JWTs are
 * ignored (Authorization bearer never read), only X-Service-Token is accepted,
 * and the role-permission machinery is off. Mutually exclusive with user-auth
 * config.
 */
const YAML = `
rules:
  - path: /orders
    methods: [GET]
    permissions: [READ_ORDER]
  - path: /jobs
    methods: [POST]
    allowedServices: [scheduler]
`;

const fakeValidator: TokenValidator = {
  validateUserToken: async () => ({ userId: "u-1", roleId: "M" }),
  validateServiceToken: async () => ({ service_name: "scheduler" }),
};

const silentAudit = { emit: () => {} };

function serviceOnlyOpts(): CreateAuthzOptions {
  return {
    authorizationYaml: YAML,
    serviceIssuer: "https://sso.example",
    serviceJwksUri: "https://sso.example/jwks",
    serviceOnly: true,
    auditSink: silentAudit,
    validator: fakeValidator,
  };
}

async function run(
  authz: Authz,
  opts: { method?: string; url?: string; headers?: Record<string, string> },
): Promise<number> {
  let status = 0;
  let nexted = false;
  const req: any = {
    method: opts.method ?? "GET",
    url: opts.url ?? "/orders",
    path: opts.url ?? "/orders",
    headers: opts.headers ?? {},
  };
  const res: any = { status: (s: number) => ({ json: () => { status = s; } }) };
  await authz.middleware(req, res, () => { nexted = true; });
  return nexted ? 200 : status;
}

describe("explicit service-only mode (§0.5)", () => {
  it("ignores the user bearer and disables the role machinery", async () => {
    const authz = await createAuthzFromOptions(serviceOnlyOpts());
    expect(authz.userAuthEnabled).toBe(false);
    expect(authz.mode).toBe("normal");
    expect(authz.health().roleServiceLastSync).toBeNull();

    // A user bearer alone is ignored -> treated as no credentials (401).
    expect(await run(authz, { url: "/orders", headers: { authorization: "Bearer x" } })).toBe(401);
    // A service token against an allowedServices rule still works.
    expect(await run(authz, { method: "POST", url: "/jobs", headers: { "x-service-token": "svc" } })).toBe(200);
    await authz.stop();
  });

  it("strips the user identity even when a bearer rides alongside a service token", async () => {
    const authz = await createAuthzFromOptions(serviceOnlyOpts());
    // Both credentials present: the bearer is ignored, so the request is SERVICE,
    // not USER_AND_SERVICE. A service-only /jobs rule still allows it...
    expect(
      await run(authz, { method: "POST", url: "/jobs", headers: { authorization: "Bearer x", "x-service-token": "svc" } }),
    ).toBe(200);
    // ...but a user-permission rule (/orders) can never match a SERVICE request -> DENY.
    expect(
      await run(authz, { url: "/orders", headers: { authorization: "Bearer x", "x-service-token": "svc" } }),
    ).toBe(403);
    await authz.stop();
  });

  it.each([
    ["userIssuer", { userIssuer: "https://auth.example" }],
    ["roleServiceUrl", { roleServiceUrl: "http://role-service:8080" }],
  ])("rejects serviceOnly combined with %s", async (_label, extra) => {
    await expect(
      createAuthzFromOptions({ ...serviceOnlyOpts(), ...extra }),
    ).rejects.toThrow(ConfigError);
  });

  it("rejects serviceOnly combined with externalPermissionSource", async () => {
    await expect(
      createAuthzFromOptions({ ...serviceOnlyOpts(), externalPermissionSource: true }),
    ).rejects.toThrow(ConfigError);
  });
});
