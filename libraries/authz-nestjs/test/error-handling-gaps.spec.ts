/**
 * Tests for error-handling / data-validation gaps:
 *   Q1 — DiskCache.write() unguarded: EACCES/ENOSPC errors must be caught and surfaced (log + metric)
 *   Q2 — Role Service snapshot value-validation: non-string[] values must be rejected
 *   Q3 — JWKS fetch timeout: createRemoteJWKSet must use timeoutDuration option (5000ms default)
 *   Q5 — role events: empty roleId or empty/non-string permission entries must be rejected
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { DiskCache } from "../src/cache-sync/disk.js";
import { CacheBootstrap } from "../src/cache-sync/bootstrap.js";
import { applyUpsert, applyDelete } from "../src/cache-sync/events.js";
import { PermissionCache } from "../src/permission-cache/cache.js";
import { Metrics, METRIC } from "../src/observability/metrics.js";
import { HttpRoleServiceClient } from "../src/role-service-client/client.js";
import { JwksTokenValidator, JwksValidatorConfig } from "../src/inbound-auth/token-validator.js";
import { RoleServiceClient } from "../src/spi.js";
import nock from "nock";

// ---------------------------------------------------------------------------
// Q1 — DiskCache.write() must catch write failures and return an error
// ---------------------------------------------------------------------------

describe("Q1 — DiskCache.write() wraps fs errors and returns them instead of throwing", () => {
  it("write() to a non-existent directory returns an error (not a thrown exception)", () => {
    const badPath = path.join(os.tmpdir(), "no-such-dir-authz-test", "cache.json");
    const disk = new DiskCache(badPath);
    const cache = new PermissionCache({ ADMIN: ["READ"] });

    let threw = false;
    let returnedError: Error | null = null;
    try {
      returnedError = disk.write(cache);
    } catch {
      threw = true;
    }
    expect(threw).toBe(false);
    expect(returnedError).toBeInstanceOf(Error);
  });

  it("write() to a valid path succeeds and returns null (no error)", () => {
    const validPath = path.join(os.tmpdir(), `authz-q1-ok-${Date.now()}.json`);
    const disk = new DiskCache(validPath);
    const cache = new PermissionCache({ ADMIN: ["READ"] });

    let threw = false;
    let returnedError: Error | null = null;
    try {
      returnedError = disk.write(cache);
    } catch {
      threw = true;
    }
    expect(threw).toBe(false);
    expect(returnedError).toBeNull();

    try { fs.unlinkSync(validPath); } catch { /* ignore */ }
  });
});

describe("Q1 — CacheBootstrap logs and increments metric on disk write failure", () => {
  it("fullSync disk write failure is logged and counted as disk_cache_write_failures_total; does not crash", async () => {
    const badPath = path.join(os.tmpdir(), "no-such-dir-authz-q1", "cache.json");
    const client: RoleServiceClient = {
      fetchSnapshot: async () => ({ ADMIN: ["READ"] }),
    };
    const cache = new PermissionCache();
    const metrics = new Metrics();
    const warnings: string[] = [];
    const logger = { warn: (msg: string) => warnings.push(msg) };

    const boot = new CacheBootstrap(cache, client, new DiskCache(badPath), {
      metrics,
      logger,
    });

    await boot.start();

    expect(warnings.some((w) => /disk|write|cache/i.test(w))).toBe(true);
    expect(metrics.get("disk_cache_write_failures_total")).toBeGreaterThan(0);
  });

  it("role event apply disk write failure is logged and counted; cache update still committed", async () => {
    const goodPath = path.join(os.tmpdir(), `authz-q1-kafka-${Date.now()}.json`);
    const client: RoleServiceClient = {
      fetchSnapshot: async () => ({ EXISTING: ["PERM_A"] }),
    };

    const cache = new PermissionCache();
    const metrics = new Metrics();
    const warnings: string[] = [];
    const logger = { warn: (msg: string) => warnings.push(msg) };

    const disk = new DiskCache(goodPath);
    const boot = new CacheBootstrap(cache, client, disk, { metrics, logger });
    await boot.start();

    // Redirect disk to a bad path to simulate failure only on subsequent writes
    const badDisk = new DiskCache(
      path.join(os.tmpdir(), "no-such-dir-kafka-q1", "cache.json"),
    );
    (boot as any).disk = badDisk;

    // Trigger a role event via the new public API (N6/L2 serial chain)
    boot.applyUpsert({ roleId: "NEW_ROLE", permissions: ["PERM_NEW"] });

    // Wait for chain to drain
    await new Promise((r) => setTimeout(r, 50));

    // The role event MUST still be applied to in-memory cache (fail-open on disk)
    expect(cache.permissionsForRole("NEW_ROLE").has("PERM_NEW")).toBe(true);

    expect(metrics.get("disk_cache_write_failures_total")).toBeGreaterThan(0);

    try { fs.unlinkSync(goodPath); } catch { /* ignore */ }
  });
});

// ---------------------------------------------------------------------------
// Q2 — Role Service snapshot must reject non-string[] values
// ---------------------------------------------------------------------------

describe("Q2 — HttpRoleServiceClient.fetchSnapshot() validates each role's permissions are string[]", () => {
  afterEach(() => nock.cleanAll());

  it("throws malformed error when a role value is null instead of string[]", async () => {
    nock("http://role-service.test")
      .get("/roles")
      .reply(200, { ADMIN: null });

    const client = new HttpRoleServiceClient({ baseUrl: "http://role-service.test" });
    await expect(client.fetchSnapshot()).rejects.toThrow(/malformed/i);
  });

  it("throws malformed error when a role value is an object instead of string[]", async () => {
    nock("http://role-service.test")
      .get("/roles")
      .reply(200, { ADMIN: { permissions: ["READ"] } });

    const client = new HttpRoleServiceClient({ baseUrl: "http://role-service.test" });
    await expect(client.fetchSnapshot()).rejects.toThrow(/malformed/i);
  });

  it("throws malformed error when a role value is a string instead of string[]", async () => {
    nock("http://role-service.test")
      .get("/roles")
      .reply(200, { ADMIN: "READ_ORDER" });

    const client = new HttpRoleServiceClient({ baseUrl: "http://role-service.test" });
    await expect(client.fetchSnapshot()).rejects.toThrow(/malformed/i);
  });

  it("throws malformed error when a role value is a number instead of string[]", async () => {
    nock("http://role-service.test")
      .get("/roles")
      .reply(200, { ADMIN: 42 });

    const client = new HttpRoleServiceClient({ baseUrl: "http://role-service.test" });
    await expect(client.fetchSnapshot()).rejects.toThrow(/malformed/i);
  });

  it("throws malformed error when permissions array contains non-string entries", async () => {
    nock("http://role-service.test")
      .get("/roles")
      .reply(200, { ADMIN: [null, 123] });

    const client = new HttpRoleServiceClient({ baseUrl: "http://role-service.test" });
    await expect(client.fetchSnapshot()).rejects.toThrow(/malformed/i);
  });

  it("accepts a valid role map with string[] values", async () => {
    nock("http://role-service.test")
      .get("/roles")
      .reply(200, { ADMIN: ["READ_ORDER", "WRITE_ORDER"], VIEWER: ["READ_ORDER"] });

    const client = new HttpRoleServiceClient({ baseUrl: "http://role-service.test" });
    const result = await client.fetchSnapshot();
    expect(result).toEqual({ ADMIN: ["READ_ORDER", "WRITE_ORDER"], VIEWER: ["READ_ORDER"] });
  });

  it("accepts an empty array [] as a valid permissions value", async () => {
    nock("http://role-service.test")
      .get("/roles")
      .reply(200, { ADMIN: [] });

    const client = new HttpRoleServiceClient({ baseUrl: "http://role-service.test" });
    const result = await client.fetchSnapshot();
    expect(result).toEqual({ ADMIN: [] });
  });

  it("accepts an empty role map {} without throwing", async () => {
    nock("http://role-service.test")
      .get("/roles")
      .reply(200, {});

    const client = new HttpRoleServiceClient({ baseUrl: "http://role-service.test" });
    await expect(client.fetchSnapshot()).resolves.toEqual({});
  });
});

// ---------------------------------------------------------------------------
// Q3 — JWKS fetch timeout via timeoutDuration option
// ---------------------------------------------------------------------------

describe("Q3 — JwksTokenValidator passes timeoutDuration to createRemoteJWKSet", () => {
  it("constructor accepts jwksTimeoutMs option (no error)", () => {
    const cfg: JwksValidatorConfig = {
      userIssuer: "https://auth.example.com",
      userJwksUri: "https://auth.example.com/.well-known/jwks.json",
      serviceIssuer: "https://sso.example.com",
      serviceJwksUri: "https://sso.example.com/.well-known/jwks.json",
      audience: "api://test",
      jwksTimeoutMs: 3000,
    };
    expect(() => new JwksTokenValidator(cfg)).not.toThrow();
  });

  it("constructor works without jwksTimeoutMs (defaults to 5000ms, no error)", () => {
    const cfg: JwksValidatorConfig = {
      userIssuer: "https://auth.example.com",
      userJwksUri: "https://auth.example.com/.well-known/jwks.json",
      serviceIssuer: "https://sso.example.com",
      serviceJwksUri: "https://sso.example.com/.well-known/jwks.json",
      audience: "api://test",
    };
    expect(() => new JwksTokenValidator(cfg)).not.toThrow();
  });

  it("DEFAULT_JWKS_TIMEOUT_MS is exported and equals 5000", async () => {
    const mod = await import("../src/inbound-auth/token-validator");
    expect((mod as any).DEFAULT_JWKS_TIMEOUT_MS).toBe(5000);
  });

  it("a slow JWKS endpoint times out within jwksTimeoutMs and throws", async () => {
    nock("http://slow-jwks.test")
      .get("/.well-known/jwks.json")
      .delayConnection(30_000)
      .reply(200, { keys: [] });

    const cfg: JwksValidatorConfig = {
      userIssuer: "https://auth.example.com",
      userJwksUri: "http://slow-jwks.test/.well-known/jwks.json",
      serviceIssuer: "https://sso.example.com",
      serviceJwksUri: "http://slow-jwks.test/.well-known/jwks.json",
      audience: "api://test",
      jwksTimeoutMs: 50,
    };
    const validator = new JwksTokenValidator(cfg);

    const fakeJwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QifQ.eyJzdWIiOiJ1c2VyIn0.fakesig";
    await expect(validator.validateUserToken(fakeJwt)).rejects.toThrow();

    nock.cleanAll();
  }, 10_000);
});

// ---------------------------------------------------------------------------
// Q5 — role events: empty roleId / empty permission strings must be rejected
// ---------------------------------------------------------------------------

describe("Q5 — applyUpsert rejects empty roleId", () => {
  it("upsert with empty-string roleId is not applied", async () => {
    const cache = new PermissionCache();
    const result = await applyUpsert(cache, {
      roleId: "",
      permissions: ["READ_ORDER"],
    });
    expect(result.applied).toBe(false);
    expect(result.reason).toMatch(/empty|invalid|malformed/i);
  });
});

describe("Q5 — applyDelete rejects empty roleId", () => {
  it("delete with empty-string roleId is not applied", async () => {
    const cache = new PermissionCache({ "": ["STALE_PERM"] });
    const result = await applyDelete(cache, { roleId: "" });
    expect(result.applied).toBe(false);
    expect(result.reason).toMatch(/empty|invalid|malformed/i);
  });
});

describe("Q5 — applyUpsert rejects empty/non-string permission entries", () => {
  it("upsert with an empty-string permission entry is not applied", async () => {
    const cache = new PermissionCache();
    const result = await applyUpsert(cache, {
      roleId: "ADMIN",
      permissions: ["READ_ORDER", ""],
    });
    expect(result.applied).toBe(false);
    expect(result.reason).toMatch(/empty|invalid|malformed/i);
  });

  it("upsert with all empty-string permissions is not applied", async () => {
    const cache = new PermissionCache();
    const result = await applyUpsert(cache, {
      roleId: "ADMIN",
      permissions: ["", ""],
    });
    expect(result.applied).toBe(false);
    expect(result.reason).toMatch(/empty|invalid|malformed/i);
  });

  it("upsert with a whitespace-only permission entry is not applied", async () => {
    const cache = new PermissionCache();
    const result = await applyUpsert(cache, {
      roleId: "ADMIN",
      permissions: ["  "],
    });
    expect(result.applied).toBe(false);
    expect(result.reason).toMatch(/empty|invalid|malformed/i);
  });

  it("upsert with valid non-empty permissions is still applied (regression guard)", async () => {
    const cache = new PermissionCache();
    const result = await applyUpsert(cache, {
      roleId: "ADMIN",
      permissions: ["READ_ORDER", "WRITE_ORDER"],
    });
    expect(result.applied).toBe(true);
    expect(cache.permissionsForRole("ADMIN").has("READ_ORDER")).toBe(true);
  });

  it("upsert with empty permissions array [] is applied (empty role is valid)", async () => {
    const cache = new PermissionCache();
    const result = await applyUpsert(cache, {
      roleId: "EMPTY_ROLE",
      permissions: [],
    });
    expect(result.applied).toBe(true);
  });
});
