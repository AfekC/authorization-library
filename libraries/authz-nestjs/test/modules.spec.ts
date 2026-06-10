import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  buildRequestContext,
  stripUntrustedHeaders,
} from "../src/inbound-auth/context";
import { PermissionCache } from "../src/permission-cache/cache";
import { applyRoleEvent, parseRoleEvent } from "../src/cache-sync/events";
import { DiskCache } from "../src/cache-sync/disk";
import { CacheBootstrap } from "../src/cache-sync/bootstrap";
import { loadAuthorizationConfig } from "../src/rule-config/loader";
import { buildAuditEvent, formatInfoLine } from "../src/audit/audit";
import { RoleServiceClient, RoleMap } from "../src/spi";
import { Metrics, METRIC } from "../src/observability/metrics";

describe("stripUntrustedHeaders", () => {
  it("drops identity headers but keeps tokens and trace ids", () => {
    const out = stripUntrustedHeaders({
      authorization: "Bearer x",
      "x-service-token": "svc",
      "x-user-id": "spoof",
      "X-Role": "ADMIN",
      "x-tenant": "evil",
      "x-correlation-id": "c-1",
      "content-type": "application/json",
    });
    expect(out["authorization"]).toBe("Bearer x");
    expect(out["x-service-token"]).toBe("svc");
    expect(out["x-correlation-id"]).toBe("c-1");
    expect(out["content-type"]).toBe("application/json");
    expect(out["x-user-id"]).toBeUndefined();
    expect(out["X-Role"]).toBeUndefined();
    expect(out["x-tenant"]).toBeUndefined();
  });
});

describe("buildRequestContext", () => {
  it("derives USER_AND_SERVICE and only uses claim-derived identity", () => {
    const ctx = buildRequestContext({
      user: { userId: "u1", roleId: "MANAGER" },
      service: { serviceName: "scheduler" },
      correlationId: "c-xyz",
    });
    expect(ctx.authenticationType).toBe("USER_AND_SERVICE");
    expect(ctx.userId).toBe("u1");
    expect(ctx.serviceName).toBe("scheduler");
    expect(ctx.correlationId).toBe("c-xyz");
    expect(ctx.requestId).toBeTruthy();
  });

  it("derives SERVICE when only a service principal is present", () => {
    const ctx = buildRequestContext({
      user: null,
      service: { serviceName: "batch" },
    });
    expect(ctx.authenticationType).toBe("SERVICE");
  });
});

describe("applyRoleEvent", () => {
  it("applies UPSERT and DELETE, skips unknown", async () => {
    const cache = new PermissionCache({ MANAGER: ["READ_ORDER"] });
    expect(
      (await applyRoleEvent(cache, {
        operation: "UPSERT_ROLE",
        roleId: "MANAGER",
        permissions: ["READ_ORDER", "DELETE_ORDER"],
      })).applied,
    ).toBe(true);
    expect(cache.permissionsForRole("MANAGER").has("DELETE_ORDER")).toBe(true);

    expect(
      (await applyRoleEvent(cache, { operation: "DELETE_ROLE", roleId: "MANAGER" }))
        .applied,
    ).toBe(true);
    expect(cache.permissionsForRole("MANAGER").size).toBe(0);

    const skipped = await applyRoleEvent(cache, { operation: "FROBNICATE" });
    expect(skipped.applied).toBe(false);
  });

  it("parseRoleEvent returns null on bad json", () => {
    expect(parseRoleEvent("{not json")).toBeNull();
    expect(parseRoleEvent(null)).toBeNull();
  });
});

describe("DiskCache", () => {
  it("round-trips a snapshot", () => {
    const file = path.join(os.tmpdir(), `authz-cache-${Date.now()}.json`);
    const disk = new DiskCache(file);
    const cache = new PermissionCache({ VIEWER: ["READ_ORDER"] });
    disk.write(cache);
    const snap = disk.read();
    expect(snap?.roles.VIEWER).toEqual(["READ_ORDER"]);
    fs.unlinkSync(file);
  });
});

describe("CacheBootstrap", () => {
  const failingClient: RoleServiceClient = {
    fetchSnapshot: async () => {
      throw new Error("unreachable");
    },
  };
  const okClient = (roles: RoleMap): RoleServiceClient => ({
    fetchSnapshot: async () => roles,
  });

  it("normal mode on Role Service success", async () => {
    const cache = new PermissionCache();
    const file = path.join(os.tmpdir(), `boot-${Date.now()}.json`);
    const boot = new CacheBootstrap(
      cache,
      okClient({ VIEWER: ["READ_ORDER"] }),
      new DiskCache(file),
    );
    const res = await boot.start();
    expect(res.mode).toBe("normal");
    expect(cache.permissionsForRole("VIEWER").has("READ_ORDER")).toBe(true);
    fs.unlinkSync(file);
  });

  it("seed mode when Role Service unreachable but disk exists", async () => {
    const file = path.join(os.tmpdir(), `seed-${Date.now()}.json`);
    const disk = new DiskCache(file);
    disk.write(new PermissionCache({ MANAGER: ["DELETE_ORDER"] }));
    const cache = new PermissionCache();
    const boot = new CacheBootstrap(cache, failingClient, disk);
    const res = await boot.start();
    expect(res.mode).toBe("seed");
    expect(cache.permissionsForRole("MANAGER").has("DELETE_ORDER")).toBe(true);
    fs.unlinkSync(file);
  });

  it("fails fast when Role Service unreachable and disk is missing", async () => {
    const file = path.join(os.tmpdir(), `nodisk-${Date.now()}.json`); // never written
    const cache = new PermissionCache();
    const boot = new CacheBootstrap(cache, failingClient, new DiskCache(file));
    await expect(boot.start()).rejects.toThrow(/disk cache/i);
  });

  it("fails fast when Role Service unreachable and disk cache is empty", async () => {
    const file = path.join(os.tmpdir(), `emptydisk-${Date.now()}.json`);
    const disk = new DiskCache(file);
    disk.write(new PermissionCache()); // empty roles map
    const cache = new PermissionCache();
    const boot = new CacheBootstrap(cache, failingClient, disk);
    await expect(boot.start()).rejects.toThrow(/empty|disk cache/i);
    fs.unlinkSync(file);
  });

  it("forcedRefresh re-fetches from the Role Service and replaces the cache", async () => {
    const file = path.join(os.tmpdir(), `refresh-${Date.now()}.json`);
    let roles: RoleMap = { VIEWER: ["READ_ORDER"] };
    const client: RoleServiceClient = { fetchSnapshot: async () => roles };
    const cache = new PermissionCache();
    const boot = new CacheBootstrap(cache, client, new DiskCache(file));
    await boot.start();
    expect(cache.permissionsForRole("VIEWER").has("WRITE_ORDER")).toBe(false);
    roles = { VIEWER: ["READ_ORDER", "WRITE_ORDER"] };
    await boot.forcedRefresh();
    expect(cache.permissionsForRole("VIEWER").has("WRITE_ORDER")).toBe(true);
    fs.unlinkSync(file);
  });

  it("forcedRefresh is fail-open: keeps cache and counts a failure on error", async () => {
    const file = path.join(os.tmpdir(), `refresh-fail-${Date.now()}.json`);
    let up = true;
    const client: RoleServiceClient = {
      fetchSnapshot: async () => {
        if (!up) throw new Error("down");
        return { VIEWER: ["READ_ORDER"] };
      },
    };
    const metrics = new Metrics();
    const cache = new PermissionCache();
    const boot = new CacheBootstrap(cache, client, new DiskCache(file), undefined, {
      metrics,
    });
    await boot.start();
    up = false;
    await boot.forcedRefresh();
    expect(cache.permissionsForRole("VIEWER").has("READ_ORDER")).toBe(true); // unchanged
    expect(metrics.get(METRIC.roleRefreshFailures)).toBe(1);
    fs.unlinkSync(file);
  });

  it("startSeedRetry is a no-op when already in normal mode", async () => {
    const file = path.join(os.tmpdir(), `ssr-noop-${Date.now()}.json`);
    const boot = new CacheBootstrap(
      new PermissionCache(),
      okClient({ MANAGER: ["READ_ORDER"] }),
      new DiskCache(file),
    );
    await boot.start();
    expect(boot.mode_()).toBe("normal");
    // Must not throw
    boot.startSeedRetry();
    boot.stop();
    fs.unlinkSync(file);
  });

  it("startSeedRetry promotes seed -> normal once the Role Service recovers", async () => {
    const file = path.join(os.tmpdir(), `ssr-promote-${Date.now()}.json`);
    const disk = new DiskCache(file);
    disk.write(new PermissionCache({ MANAGER: ["READ_ORDER"] }));
    let up = false;
    const flakyClient: RoleServiceClient = {
      fetchSnapshot: async () => {
        if (!up) throw new Error("down");
        return { MANAGER: ["READ_ORDER", "WRITE_ORDER"] };
      },
    };
    const cache = new PermissionCache();
    const boot = new CacheBootstrap(cache, flakyClient, disk);
    expect((await boot.start()).mode).toBe("seed");
    boot.startSeedRetry();
    up = true;
    // First wait is 2s; wait for promotion up to 5s
    for (let i = 0; i < 100 && boot.mode_() === "seed"; i++) {
      await new Promise((r) => setTimeout(r, 50));
    }
    boot.stop();
    expect(boot.mode_()).toBe("normal");
    expect(cache.permissionsForRole("MANAGER").has("WRITE_ORDER")).toBe(true);
    fs.unlinkSync(file);
  });

  it("reconciler promotes seed -> normal once the Role Service recovers", async () => {
    const file = path.join(os.tmpdir(), `recon-${Date.now()}.json`);
    const disk = new DiskCache(file);
    disk.write(new PermissionCache({ MANAGER: ["READ_ORDER"] }));
    let up = false;
    const flakyClient: RoleServiceClient = {
      fetchSnapshot: async () => {
        if (!up) throw new Error("down");
        return { MANAGER: ["READ_ORDER", "WRITE_ORDER"] };
      },
    };
    const cache = new PermissionCache();
    const boot = new CacheBootstrap(cache, flakyClient, disk);
    expect((await boot.start()).mode).toBe("seed");
    boot.startReconciler(20);
    up = true;
    // wait for the reconciler to promote to normal
    for (let i = 0; i < 50 && boot.mode_() === "seed"; i++) {
      await new Promise((r) => setTimeout(r, 20));
    }
    boot.stop();
    expect(boot.mode_()).toBe("normal");
    expect(cache.permissionsForRole("MANAGER").has("WRITE_ORDER")).toBe(true);
    fs.unlinkSync(file);
  });
});

describe("YAML loader", () => {
  it("compiles valid config and rejects ambiguous", () => {
    const engine = loadAuthorizationConfig(`
rules:
  - path: /orders/**
    methods: [GET]
    permissions: [READ_ORDER]
`);
    expect(
      engine.authorize(
        { method: "GET", path: "/orders/7", authType: "USER", role: "V" },
        new PermissionCache({ V: ["READ_ORDER"] }),
      ),
    ).toBe("ALLOW");

    expect(() =>
      loadAuthorizationConfig(`
rules:
  - path: /orders/*
    methods: [GET]
    permissions: [READ_ORDER]
  - path: /orders/*
    methods: [GET]
    permissions: [ADMIN]
`),
    ).toThrow();
  });
});

describe("audit formatting", () => {
  it("formats an info line for a user decision", () => {
    const ctx = buildRequestContext({
      user: { userId: "u-123", roleId: "MANAGER" },
      service: null,
      correlationId: "c-xyz",
      requestId: "r-1",
    });
    const evt = buildAuditEvent({
      ctx,
      method: "GET",
      path: "/orders/7",
      permission: "READ_ORDER",
      result: "ALLOW",
    });
    const line = formatInfoLine(evt);
    expect(line).toContain("AUTHZ ALLOW");
    expect(line).toContain("userId=u-123");
    expect(line).toContain("corr=c-xyz");
  });
});
