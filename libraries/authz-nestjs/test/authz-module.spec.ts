/**
 * Tests for AuthzModule — NestJS DI auto-wiring module (Gap N8).
 *
 * Covers:
 *   N8a — AuthzModule.forRoot() compiles without error
 *   N8b — AuthzGuard is resolvable from the DI container
 *   N8c — APP_GUARD is registered (guard resolves under APP_GUARD token)
 *   N8d — AUTHZ token resolves and the Authz object exposes validator + audit
 *   N8e — onModuleDestroy calls authz.stop()
 */

import "reflect-metadata";
import { jest } from "@jest/globals";
import nock from "nock";
import { Test, TestingModule } from "@nestjs/testing";
import { APP_GUARD } from "@nestjs/core";
import { AuthzModule, AUTHZ } from "../src/nest/authz.module.js";
import { AuthzGuard } from "../src/nest/authz.guard.js";
import { Authz } from "../src/bootstrap/create-authz.js";

// ---------------------------------------------------------------------------
// Shared test fixtures
// ---------------------------------------------------------------------------

const ROLE_SERVICE_URL = "http://localhost:18250";

const VALID_YAML = `
rules:
  - path: "/api/test"
    methods: ["GET"]
    permissions: ["read"]
`;

/** Minimal CreateAuthzOptions that avoids real JWKS/Kafka IO. */
const MINIMAL_OPTIONS = {
  userIssuer: "https://issuer.test",
  userJwksUri: "https://jwks.test",
  serviceIssuer: "https://sso.test",
  serviceJwksUri: "https://sso-jwks.test",
  audience: "test-app",
  roleServiceUrl: ROLE_SERVICE_URL,
  authorizationYaml: VALID_YAML,
  // Stub out token validation so no real JWKS calls are made.
  validator: {
    validateUserToken: async () => ({ userId: "u1", roleId: "viewer" }),
    validateServiceToken: async () => ({ service_name: "svc" }),
  },
  // Prevent background reconciler from firing during tests.
  reconcileIntervalMs: 999_999,
};

/** Mock the Role Service so CacheBootstrap can complete its startup. */
function mockRoleService(): nock.Scope {
  return nock(ROLE_SERVICE_URL).get("/roles").reply(200, { viewer: ["read"] });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function buildModule(): Promise<TestingModule> {
  mockRoleService();
  return Test.createTestingModule({
    imports: [AuthzModule.forRoot(MINIMAL_OPTIONS)],
  }).compile();
}

// ---------------------------------------------------------------------------
// N8a — Module compiles
// ---------------------------------------------------------------------------

describe("N8a — AuthzModule.forRoot() compiles", () => {
  let module: TestingModule;

  beforeAll(async () => {
    module = await buildModule();
  });

  afterAll(async () => {
    await module.close();
    nock.cleanAll();
  });

  it("creates a TestingModule without error", () => {
    expect(module).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// N8b — AuthzGuard resolvable by class reference
// ---------------------------------------------------------------------------

describe("N8b — AuthzGuard is resolvable from the container", () => {
  let module: TestingModule;

  beforeAll(async () => {
    module = await buildModule();
  });

  afterAll(async () => {
    await module.close();
    nock.cleanAll();
  });

  it("resolves AuthzGuard by class token", () => {
    const guard = module.get<AuthzGuard>(AuthzGuard);
    expect(guard).toBeDefined();
    expect(guard).toBeInstanceOf(AuthzGuard);
  });
});

// ---------------------------------------------------------------------------
// N8c — APP_GUARD is registered
// ---------------------------------------------------------------------------

describe("N8c — APP_GUARD is registered as a global guard", () => {
  let module: TestingModule;

  beforeAll(async () => {
    module = await buildModule();
  });

  afterAll(async () => {
    await module.close();
    nock.cleanAll();
  });

  it("APP_GUARD is registered in applicationConfig.globalGuards", () => {
    // NestJS scanner renames APP_GUARD providers to "APP_GUARD (UUID: ...)"
    // and calls applicationConfig.addGlobalGuard() with the resolved instance.
    // We verify the result via applicationConfig.getGlobalGuards() which reflects
    // the post-compile state after applyApplicationProviders() runs.
    const appConfig: any = (module as any)["applicationConfig"];
    const globalGuards: unknown[] = appConfig.getGlobalGuards();
    expect(globalGuards.length).toBeGreaterThanOrEqual(1);
    const hasAuthzGuard = globalGuards.some((g) => g instanceof AuthzGuard);
    expect(hasAuthzGuard).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// N8d — AUTHZ token exposes validator + audit
// ---------------------------------------------------------------------------

describe("N8d — AUTHZ token resolves and exposes validator + audit", () => {
  let module: TestingModule;

  beforeAll(async () => {
    module = await buildModule();
  });

  afterAll(async () => {
    await module.close();
    nock.cleanAll();
  });

  it("resolves the AUTHZ token", () => {
    const authz = module.get<Authz>(AUTHZ);
    expect(authz).toBeDefined();
  });

  it("AUTHZ.validator is the TokenValidator used at startup", () => {
    const authz = module.get<Authz>(AUTHZ);
    // The stub validator was injected via options.validator — it must be present.
    expect(authz.validator).toBeDefined();
    expect(typeof authz.validator.validateUserToken).toBe("function");
  });

  it("AUTHZ.audit is an AuditSink instance", () => {
    const authz = module.get<Authz>(AUTHZ);
    expect(authz.audit).toBeDefined();
    expect(typeof authz.audit.emit).toBe("function");
  });

  it("AUTHZ.engine, cache, metrics, health, stop are all present", () => {
    const authz = module.get<Authz>(AUTHZ);
    expect(authz.engine).toBeDefined();
    expect(authz.cache).toBeDefined();
    expect(authz.metrics).toBeDefined();
    expect(typeof authz.health).toBe("function");
    expect(typeof authz.stop).toBe("function");
  });
});

// ---------------------------------------------------------------------------
// N8e — onModuleDestroy calls authz.stop()
// ---------------------------------------------------------------------------

describe("N8e — onModuleDestroy calls authz.stop()", () => {
  it("calls stop() on the Authz instance when the module is destroyed", async () => {
    mockRoleService();
    const module = await Test.createTestingModule({
      imports: [AuthzModule.forRoot(MINIMAL_OPTIONS)],
    }).compile();

    // Retrieve the Authz object and spy on stop().
    const authz = module.get<Authz>(AUTHZ);
    const stopSpy = jest.spyOn(authz, "stop").mockResolvedValue(undefined);

    // module.close() triggers OnModuleDestroy hooks.
    await module.close();

    expect(stopSpy).toHaveBeenCalledTimes(1);

    nock.cleanAll();
  });
});
