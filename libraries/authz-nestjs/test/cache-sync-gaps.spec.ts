/**
 * Tests for cache-sync correctness and crash gaps.
 *
 * Covers:
 *   C1  — DiskCache.read() must reject roles:null (typeof null === "object" trap)
 *   C5  — applyUpsert must validate each permission element is a string
 *   B4  — numeric/boolean permissions are stringified on ingest (Java parity)
 *   B11 — stop() clears the pending timer so the loop exits promptly
 *   D5  — atomic copy-on-replace: in-flight reader sees a consistent snapshot
 *   D7  — DiskCache edge cases: corrupt JSON, missing roles key, roles:null, empty roles
 *   N6  — applyUpsert/forceRefresh serialized on applyChain
 *   L2  — rejecting forceRefresh must not produce an unhandled promise rejection
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { DiskCache } from "../src/cache-sync/disk.js";
import { applyUpsert, applyDelete } from "../src/cache-sync/events.js";
import { CacheBootstrap } from "../src/cache-sync/bootstrap.js";
import { PermissionCache } from "../src/permission-cache/cache.js";
import { Metrics, METRIC } from "../src/observability/metrics.js";
import { RoleServiceClient } from "../src/spi.js";

// ---------------------------------------------------------------------------
// Helper: write raw JSON to a temp file
// ---------------------------------------------------------------------------
function writeTempFile(content: string): string {
  const file = path.join(os.tmpdir(), `authz-test-${Date.now()}-${Math.random()}.json`);
  fs.writeFileSync(file, content, "utf8");
  return file;
}

function cleanupFile(file: string): void {
  try { fs.unlinkSync(file); } catch { /* ignore */ }
}

// ---------------------------------------------------------------------------
// D7 — DiskCache edge cases
// ---------------------------------------------------------------------------

describe("D7 — DiskCache edge cases", () => {
  it("returns null for corrupt/malformed JSON (not valid JSON)", () => {
    const file = writeTempFile("{not valid json!!!");
    const disk = new DiskCache(file);
    expect(disk.read()).toBeNull();
    cleanupFile(file);
  });

  it("returns null for valid JSON that is missing the roles key entirely", () => {
    const file = writeTempFile(JSON.stringify({ timestamp: "2026-01-01T00:00:00Z" }));
    const disk = new DiskCache(file);
    expect(disk.read()).toBeNull();
    cleanupFile(file);
  });

  it("returns null for valid JSON where roles is an array (not a plain object)", () => {
    const file = writeTempFile(JSON.stringify({ timestamp: "2026-01-01T00:00:00Z", roles: ["bad"] }));
    const disk = new DiskCache(file);
    expect(disk.read()).toBeNull();
    cleanupFile(file);
  });

  it("C1 — returns null when roles is null (typeof null === 'object' guard)", () => {
    const file = writeTempFile(JSON.stringify({ timestamp: "2026-01-01T00:00:00Z", roles: null }));
    const disk = new DiskCache(file);
    expect(disk.read()).toBeNull();
    cleanupFile(file);
  });

  it("returns a valid snapshot for an empty roles map (zero roles is valid)", () => {
    const file = writeTempFile(JSON.stringify({ timestamp: "2026-01-01T00:00:00Z", roles: {} }));
    const disk = new DiskCache(file);
    const snap = disk.read();
    expect(snap).not.toBeNull();
    expect(snap!.roles).toEqual({});
    cleanupFile(file);
  });
});

// ---------------------------------------------------------------------------
// C1 — DiskCache.read() null-roles does NOT crash CacheBootstrap at startup
// ---------------------------------------------------------------------------

describe("C1 — roles:null cache treated as absent, not crash-at-startup", () => {
  it("bootstrap fails fast (CacheBootstrapError) rather than crashing with TypeError", async () => {
    const file = writeTempFile(
      JSON.stringify({ timestamp: "2026-01-01T00:00:00Z", roles: null }),
    );
    const failingClient: RoleServiceClient = {
      fetchSnapshot: async () => { throw new Error("unreachable"); },
    };
    const cache = new PermissionCache();
    const boot = new CacheBootstrap(cache, failingClient, new DiskCache(file));

    await expect(boot.start()).rejects.toThrow(/disk cache/i);
    const err: unknown = await boot.start().catch((e) => e);
    expect(err).not.toBeInstanceOf(TypeError);
    cleanupFile(file);
  });
});

// ---------------------------------------------------------------------------
// C5 & B4 — permission element type validation and stringification
// ---------------------------------------------------------------------------

describe("C5 — applyUpsert rejects non-array permissions", () => {
  it("returns not-applied when permissions is a string instead of array", async () => {
    const cache = new PermissionCache();
    const result = await applyUpsert(cache, {
      roleId: "ADMIN",
      permissions: "READ_ORDER" as any, // not an array
    });
    expect(result.applied).toBe(false);
    expect(result.reason).toMatch(/malformed|array/i);
  });

  it("returns not-applied when permissions is null", async () => {
    const cache = new PermissionCache();
    const result = await applyUpsert(cache, {
      roleId: "ADMIN",
      permissions: null as any,
    });
    expect(result.applied).toBe(false);
  });
});

describe("B4 — numeric/boolean permissions stringified on ingest (Java parity)", () => {
  it("stores numeric 123 as string '123' so Set.has('123') matches", async () => {
    const cache = new PermissionCache();
    const result = await applyUpsert(cache, {
      roleId: "ROLE_X",
      permissions: ["read", 123, true] as any,
    });
    expect(result.applied).toBe(true);
    const perms = cache.permissionsForRole("ROLE_X");
    expect(perms.has("read")).toBe(true);
    expect(perms.has("123")).toBe(true);
    expect(perms.has("true")).toBe(true);
    expect(perms.has(123 as any)).toBe(false);
    expect(perms.has(true as any)).toBe(false);
  });

  it("a decision using Set.has('123') succeeds after event with numeric 123", async () => {
    const cache = new PermissionCache();
    await applyUpsert(cache, { roleId: "ROLE_Y", permissions: [123] as any });
    expect(cache.permissionsForRole("ROLE_Y").has("123")).toBe(true);
  });

  it("mixed event ['read', 123, true] stores exactly ['read','123','true'] (regression)", async () => {
    const cache = new PermissionCache();
    await applyUpsert(cache, { roleId: "MIXED", permissions: ["read", 123, true] as any });
    const perms = cache.permissionsForRole("MIXED");
    expect([...perms].sort()).toEqual(["123", "read", "true"]);
  });
});

// ---------------------------------------------------------------------------
// B11 — stop() clears pending timer so loop exits promptly
// ---------------------------------------------------------------------------

describe("B11 — stop() clears pending setTimeout so reconciler exits promptly", () => {
  it("stop() prevents any further fullSync calls after invocation", async () => {
    let syncCount = 0;
    const client: RoleServiceClient = {
      fetchSnapshot: async () => {
        syncCount++;
        return { R: ["P"] };
      },
    };
    const file = path.join(os.tmpdir(), `b11-${Date.now()}.json`);
    const cache = new PermissionCache();
    const boot = new CacheBootstrap(cache, client, new DiskCache(file));
    await boot.start();

    boot.startReconciler(30); // 30ms interval
    await new Promise((r) => setTimeout(r, 15));
    boot.stop(); // stop immediately — should clear the pending timer
    const syncAtStop = syncCount;

    await new Promise((r) => setTimeout(r, 80));
    const syncAfterWait = syncCount;

    expect(syncAfterWait).toBe(syncAtStop);
    cleanupFile(file);
  });
});

// ---------------------------------------------------------------------------
// D5 — atomic copy-on-replace: in-flight reader sees consistent snapshot
// ---------------------------------------------------------------------------

describe("D5 — cache atomic copy-on-replace consistency", () => {
  it("an in-flight reader holds a stable reference across a replaceAll()", async () => {
    const cache = new PermissionCache({ VIEWER: ["READ_ORDER", "LIST_ORDER"] });
    const snapshot = cache.permissionsForRole("VIEWER");
    await cache.replaceAll({ VIEWER: ["WRITE_ORDER"], ADMIN: ["DELETE_ORDER"] });

    expect(snapshot.has("READ_ORDER")).toBe(true);
    expect(snapshot.has("LIST_ORDER")).toBe(true);
    expect(snapshot.has("WRITE_ORDER")).toBe(false);
  });

  it("new readers after replaceAll() see the new consistent state", async () => {
    const cache = new PermissionCache({ VIEWER: ["READ_ORDER"] });
    await cache.replaceAll({ VIEWER: ["WRITE_ORDER"], ADMIN: ["DELETE_ORDER"] });

    expect(cache.permissionsForRole("VIEWER").has("WRITE_ORDER")).toBe(true);
    expect(cache.permissionsForRole("VIEWER").has("READ_ORDER")).toBe(false);
    expect(cache.permissionsForRole("ADMIN").has("DELETE_ORDER")).toBe(true);
  });

  it("upsertRole is also copy-on-replace: in-flight reader is unaffected", async () => {
    const cache = new PermissionCache({ VIEWER: ["READ_ORDER"] });
    const before = cache.permissionsForRole("VIEWER");
    await cache.upsertRole("VIEWER", ["WRITE_ORDER"]);

    expect(before.has("READ_ORDER")).toBe(true);
    expect(before.has("WRITE_ORDER")).toBe(false);
    expect(cache.permissionsForRole("VIEWER").has("WRITE_ORDER")).toBe(true);
  });

  it("deleteRole is also copy-on-replace: in-flight reader still has the deleted role", async () => {
    const cache = new PermissionCache({ VIEWER: ["READ_ORDER"] });
    const before = cache.permissionsForRole("VIEWER");
    await cache.deleteRole("VIEWER");

    expect(before.has("READ_ORDER")).toBe(true);
    expect(cache.permissionsForRole("VIEWER").size).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// N6 — forced-refresh must not overwrite a concurrent upsert
// ---------------------------------------------------------------------------

describe("N6 — forceRefresh must not overwrite a concurrent role-update upsert", () => {
  it("upsert enqueued AFTER forceRefresh survives after forcedRefresh completes", async () => {
    // Resolve handle so the test can detect when the blocked fetch has started
    let signalFetchStarted!: () => void;
    const fetchStarted = new Promise<void>((resolve) => { signalFetchStarted = resolve; });

    let unblockFetch!: () => void;
    const fetchUnblocked = new Promise<void>((resolve) => { unblockFetch = resolve; });

    let fetchCallCount = 0;
    const client: RoleServiceClient = {
      fetchSnapshot: async () => {
        fetchCallCount++;
        if (fetchCallCount === 1) return { EXISTING: ["PERM_A"] };
        signalFetchStarted();
        await fetchUnblocked;
        return { EXISTING: ["PERM_A"] }; // NEW_ROLE absent from refresh snapshot
      },
    };

    const tmpFile = path.join(os.tmpdir(), `n6-${Date.now()}-${Math.random()}.json`);
    const cache = new PermissionCache();
    const boot = new CacheBootstrap(cache, client, new DiskCache(tmpFile));

    await boot.start();

    // Trigger forced refresh — enqueues on applyChain
    boot.forceRefresh();

    // Wait until the refresh fetch has actually started
    await fetchStarted;

    // While refresh is blocked, enqueue a upsert (queued BEHIND the refresh)
    boot.applyUpsert({ roleId: "NEW_ROLE", permissions: ["PERM_NEW"] });

    // Unblock the refresh fetch
    unblockFetch();

    // Wait for chain to drain
    await new Promise((r) => setTimeout(r, 50));

    // NEW_ROLE must survive even though the refresh snapshot didn't include it
    expect(cache.permissionsForRole("NEW_ROLE").has("PERM_NEW")).toBe(true);
    expect(cache.permissionsForRole("EXISTING").has("PERM_A")).toBe(true);

    cleanupFile(tmpFile);
  });
});

// ---------------------------------------------------------------------------
// L2 — rejecting forceRefresh must not produce an unhandled promise rejection
// ---------------------------------------------------------------------------

describe("L2 — rejecting forceRefresh does not escape as unhandled rejection", () => {
  it("an error thrown inside forcedRefresh is caught; no unhandled rejection event fires", async () => {
    let unhandledRejectionFired = false;
    const onUnhandled = () => { unhandledRejectionFired = true; };
    process.on("unhandledRejection", onUnhandled);

    let refreshCallCount = 0;
    const client: RoleServiceClient = {
      fetchSnapshot: async () => {
        refreshCallCount++;
        if (refreshCallCount === 1) return { R: ["P"] }; // startup OK
        throw new Error("forced-refresh exploded"); // all subsequent fail
      },
    };

    const tmpFile = path.join(os.tmpdir(), `l2-${Date.now()}.json`);
    const cache = new PermissionCache();
    const boot = new CacheBootstrap(cache, client, new DiskCache(tmpFile));
    await boot.start();

    // Trigger the refresh — this will reject inside forcedRefresh
    boot.forceRefresh();

    await new Promise((r) => setTimeout(r, 30));

    process.removeListener("unhandledRejection", onUnhandled);

    expect(unhandledRejectionFired).toBe(false);

    cleanupFile(tmpFile);
  });
});
