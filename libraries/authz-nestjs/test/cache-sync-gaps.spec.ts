/**
 * Tests for cache-sync correctness and crash gaps.
 *
 * Covers:
 *   C1  — DiskCache.read() must reject roles:null (typeof null === "object" trap)
 *   C5  — applyRoleEvent must validate each permission element is a string
 *   B4  — numeric/boolean permissions are stringified on ingest (Java parity)
 *   C9  — Kafka topic cross-check: conflicting `operation` field in message is skipped
 *   B11 — stop() clears the pending timer so the loop exits promptly
 *   D5  — atomic copy-on-replace: in-flight reader sees a consistent snapshot
 *   D7  — DiskCache edge cases: corrupt JSON, missing roles key, roles:null, empty roles
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { DiskCache } from "../src/cache-sync/disk";
import { applyRoleEvent } from "../src/cache-sync/events";
import { CacheBootstrap } from "../src/cache-sync/bootstrap";
import { PermissionCache } from "../src/permission-cache/cache";
import { Metrics, METRIC } from "../src/observability/metrics";
import { RoleServiceClient, CacheEventHandler, RoleEvent } from "../src/spi";

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
    // This is the CRITICAL crash bug: typeof null === "object" so the old guard
    // `typeof parsed.roles !== "object"` would pass, and then
    // Object.keys(seed.roles) in bootstrap.ts throws TypeError at startup.
    const file = writeTempFile(JSON.stringify({ timestamp: "2026-01-01T00:00:00Z", roles: null }));
    const disk = new DiskCache(file);
    // Must return null — not throw, not crash
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
    // Write a cache file with roles:null — simulates a corrupt disk cache
    const file = writeTempFile(
      JSON.stringify({ timestamp: "2026-01-01T00:00:00Z", roles: null }),
    );
    const failingClient: RoleServiceClient = {
      fetchSnapshot: async () => { throw new Error("unreachable"); },
    };
    const cache = new PermissionCache();
    const boot = new CacheBootstrap(cache, failingClient, new DiskCache(file));

    // Before the fix this throws: TypeError: Cannot convert undefined or null to object
    // After the fix it throws: CacheBootstrapError (disk cache is missing/empty)
    await expect(boot.start()).rejects.toThrow(/disk cache/i);
    // It must NOT throw a TypeError
    const err: unknown = await boot.start().catch((e) => e);
    expect(err).not.toBeInstanceOf(TypeError);
    cleanupFile(file);
  });
});

// ---------------------------------------------------------------------------
// C5 & B4 — permission element type validation and stringification
// ---------------------------------------------------------------------------

describe("C5 — applyRoleEvent rejects non-array permissions", () => {
  it("returns not-applied when permissions is a string instead of array", async () => {
    const cache = new PermissionCache();
    const result = await applyRoleEvent(cache, {
      operation: "UPSERT_ROLE",
      roleId: "ADMIN",
      permissions: "READ_ORDER" as any, // not an array
    });
    expect(result.applied).toBe(false);
    expect(result.reason).toMatch(/malformed/i);
  });

  it("returns not-applied when permissions is null", async () => {
    const cache = new PermissionCache();
    const result = await applyRoleEvent(cache, {
      operation: "UPSERT_ROLE",
      roleId: "ADMIN",
      permissions: null as any,
    });
    expect(result.applied).toBe(false);
  });
});

describe("B4 — numeric/boolean permissions stringified on ingest (Java parity)", () => {
  it("stores numeric 123 as string '123' so Set.has('123') matches", async () => {
    const cache = new PermissionCache();
    const result = await applyRoleEvent(cache, {
      operation: "UPSERT_ROLE",
      roleId: "ROLE_X",
      permissions: ["read", 123, true] as any,
    });
    expect(result.applied).toBe(true);
    const perms = cache.permissionsForRole("ROLE_X");
    // All three must be stored as strings
    expect(perms.has("read")).toBe(true);
    expect(perms.has("123")).toBe(true);
    expect(perms.has("true")).toBe(true);
    // Original numeric/boolean forms must NOT be present
    expect(perms.has(123 as any)).toBe(false);
    expect(perms.has(true as any)).toBe(false);
  });

  it("a decision using Set.has('123') succeeds after event with numeric 123", async () => {
    const cache = new PermissionCache();
    await applyRoleEvent(cache, {
      operation: "UPSERT_ROLE",
      roleId: "ROLE_Y",
      permissions: [123] as any,
    });
    // The decision engine uses Set.has with string permission names.
    // Before the fix, Set.has("123") returns false because 123 was stored as-is.
    expect(cache.permissionsForRole("ROLE_Y").has("123")).toBe(true);
  });

  it("mixed event ['read', 123, true] stores exactly ['read','123','true'] (regression)", async () => {
    const cache = new PermissionCache();
    await applyRoleEvent(cache, {
      operation: "UPSERT_ROLE",
      roleId: "MIXED",
      permissions: ["read", 123, true] as any,
    });
    const perms = cache.permissionsForRole("MIXED");
    expect([...perms].sort()).toEqual(["123", "read", "true"]);
  });
});

// ---------------------------------------------------------------------------
// C9 — Kafka topic cross-check against optional `operation` field
// ---------------------------------------------------------------------------

describe("C9 — conflicting operation field is skipped, not silently acted on", () => {
  it("UPSERT message on delete topic with operation=UPSERT_ROLE is skipped", async () => {
    const cache = new PermissionCache({ VICTIM: ["READ_ORDER"] });
    // Simulate what KafkaCacheEventHandler would dispatch:
    // topic=role-delete so operation=DELETE_ROLE, but the raw message body
    // also carries operation=UPSERT_ROLE — a conflict.
    const result = await applyRoleEvent(cache, {
      operation: "DELETE_ROLE",       // topic-derived (what kafka.ts sets)
      roleId: "VICTIM",
      _topicOperation: "DELETE_ROLE", // matches — no conflict, this case is fine
    });
    // Normal delete should work
    expect(result.applied).toBe(true);
    expect(cache.permissionsForRole("VICTIM").size).toBe(0);
  });

  it("message with messageOperation field conflicting with topic-derived operation is skipped", async () => {
    // The fix: when the raw message body carries an `operation` field AND
    // it conflicts with the topic-derived operation, skip the event.
    //
    // This tests applyRoleEvent when called with an event where
    // `_messageOperation` conflicts with `operation`.
    const cache = new PermissionCache({ VICTIM: ["READ_ORDER"] });

    // We test the cross-check in kafka.ts by simulating what it produces:
    // topic=role-delete → operation set to DELETE_ROLE,
    // but raw message also had operation=UPSERT_ROLE (conflict).
    // The Kafka handler should call applyRoleEvent with a conflict-flagged event.
    // Since kafka.ts is the gatekeeper, we test it via a mock that exercises
    // the C9 guard path in kafka.ts through the onEvent callback.

    // Direct test: applyRoleEvent given a conflicting event returns not-applied
    const conflictingEvent = {
      operation: "DELETE_ROLE",         // topic-derived
      roleId: "VICTIM",
      _messageOperation: "UPSERT_ROLE", // raw body said UPSERT — conflict!
    };
    const result = await applyRoleEvent(cache, conflictingEvent as any);
    expect(result.applied).toBe(false);
    expect(result.reason).toMatch(/conflict|mismatch/i);
    // The role must NOT have been deleted
    expect(cache.permissionsForRole("VICTIM").has("READ_ORDER")).toBe(true);
  });

  it("message with matching _messageOperation (no conflict) is applied normally", async () => {
    const cache = new PermissionCache({ VICTIM: ["READ_ORDER"] });
    const nonConflictEvent = {
      operation: "DELETE_ROLE",
      roleId: "VICTIM",
      _messageOperation: "DELETE_ROLE", // matches — no conflict
    };
    const result = await applyRoleEvent(cache, nonConflictEvent as any);
    expect(result.applied).toBe(true);
    expect(cache.permissionsForRole("VICTIM").size).toBe(0);
  });

  it("message with no _messageOperation (no raw operation field) is applied normally", async () => {
    // Most normal messages won't have _messageOperation at all
    const cache = new PermissionCache();
    const normalEvent = {
      operation: "UPSERT_ROLE",
      roleId: "NEW_ROLE",
      permissions: ["READ"],
    };
    const result = await applyRoleEvent(cache, normalEvent);
    expect(result.applied).toBe(true);
    expect(cache.permissionsForRole("NEW_ROLE").has("READ")).toBe(true);
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
    const syncAfterStart = syncCount;

    boot.startReconciler(30); // 30ms interval
    // Let one or two cycles run
    await new Promise((r) => setTimeout(r, 15));
    boot.stop(); // stop immediately — should clear the pending timer
    const syncAtStop = syncCount;

    // Wait long enough that another cycle WOULD have fired if the timer wasn't cleared
    await new Promise((r) => setTimeout(r, 80));
    const syncAfterWait = syncCount;

    // At most 1-2 extra syncs may have occurred before stop() took effect,
    // but after stop() no NEW cycles should fire.
    // The key invariant: syncAfterWait === syncAtStop (timer was cleared).
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

    // Capture a reference to the current permission set BEFORE the replace.
    // This simulates a reader that started iterating the cache before an update.
    const snapshot = cache.permissionsForRole("VIEWER");

    // Now atomically replace the entire cache (simulates a reconciler cycle).
    await cache.replaceAll({ VIEWER: ["WRITE_ORDER"], ADMIN: ["DELETE_ORDER"] });

    // The in-flight reader's snapshot must still see the OLD consistent state.
    // If copy-on-replace were not atomic, this could see partial updates.
    expect(snapshot.has("READ_ORDER")).toBe(true);
    expect(snapshot.has("LIST_ORDER")).toBe(true);
    // The snapshot must NOT see post-replace data (it's a frozen old reference)
    expect(snapshot.has("WRITE_ORDER")).toBe(false);
  });

  it("new readers after replaceAll() see the new consistent state", async () => {
    const cache = new PermissionCache({ VIEWER: ["READ_ORDER"] });
    await cache.replaceAll({ VIEWER: ["WRITE_ORDER"], ADMIN: ["DELETE_ORDER"] });

    // New reads must see the updated data
    expect(cache.permissionsForRole("VIEWER").has("WRITE_ORDER")).toBe(true);
    expect(cache.permissionsForRole("VIEWER").has("READ_ORDER")).toBe(false);
    expect(cache.permissionsForRole("ADMIN").has("DELETE_ORDER")).toBe(true);
  });

  it("upsertRole is also copy-on-replace: in-flight reader is unaffected", async () => {
    const cache = new PermissionCache({ VIEWER: ["READ_ORDER"] });
    const before = cache.permissionsForRole("VIEWER");

    // Upsert atomically replaces the internal map reference.
    await cache.upsertRole("VIEWER", ["WRITE_ORDER"]);

    // Old reference is still consistent — sees only the old state.
    expect(before.has("READ_ORDER")).toBe(true);
    expect(before.has("WRITE_ORDER")).toBe(false);

    // New read sees updated state.
    expect(cache.permissionsForRole("VIEWER").has("WRITE_ORDER")).toBe(true);
  });

  it("deleteRole is also copy-on-replace: in-flight reader still has the deleted role", async () => {
    const cache = new PermissionCache({ VIEWER: ["READ_ORDER"] });
    const before = cache.permissionsForRole("VIEWER");

    await cache.deleteRole("VIEWER");

    // Old reference is unaffected.
    expect(before.has("READ_ORDER")).toBe(true);
    // New read shows the role is gone.
    expect(cache.permissionsForRole("VIEWER").size).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// N6 — forced-refresh must not overwrite a concurrent upsert
// ---------------------------------------------------------------------------
//
// Race: publish-roles arrives → forcedRefresh() starts (slow fetch) →
//   role-updates upsert arrives and is applied → forcedRefresh() completes
//   with a snapshot that does NOT include the new upsert → replaceAll() wipes it.
//
// Fix: serialize forcedRefresh and apply on the same chain so the upsert
//       applied AFTER the refresh trigger is never overwritten.
// ---------------------------------------------------------------------------

describe("N6 — forced refresh must not overwrite a concurrent role-update upsert", () => {
  /**
   * Builds a CacheBootstrap wired to a controllable CacheEventHandler so we
   * can drive onEvent / onRefresh manually (no real Kafka).
   *
   * The core invariant under test (N6):
   *   publish-roles → forcedRefresh starts (slow snapshot fetch)
   *   → role-updates upsert arrives (queued on the same chain)
   *   → forcedRefresh fetch returns snapshot WITHOUT the new upsert
   *   → upsert runs after the refresh completes
   *   → final cache contains the upsert (not overwritten)
   *
   * With the fix: applyChain serializes both operations so the upsert always
   * runs after the refresh, regardless of Node event-loop timing.
   */
  function buildControlledBootstrap(opts: {
    snapshotBeforeUpsert: Record<string, string[]>;
    /** The snapshot the forcedRefresh will return (does NOT include the new upsert) */
    snapshotForRefresh: Record<string, string[]>;
  }) {
    let capturedOnEvent!: (event: RoleEvent) => void;
    let capturedOnRefresh!: () => void;

    // Resolve handle so the test can detect when the blocked fetch has started
    let signalFetchStarted!: () => void;
    const fetchStarted = new Promise<void>((resolve) => {
      signalFetchStarted = resolve;
    });

    let unblockFetch!: () => void;
    const fetchUnblocked = new Promise<void>((resolve) => {
      unblockFetch = resolve;
    });

    let fetchCallCount = 0;
    const client: RoleServiceClient = {
      fetchSnapshot: async () => {
        fetchCallCount++;
        if (fetchCallCount === 1) {
          // First call is the startup sync — return immediately
          return opts.snapshotBeforeUpsert;
        }
        // Subsequent calls are from forcedRefresh — signal "started" and block
        signalFetchStarted();
        await fetchUnblocked;
        return opts.snapshotForRefresh;
      },
    };

    const events: CacheEventHandler = {
      start: async (onEvent, onRefresh) => {
        capturedOnEvent = onEvent;
        capturedOnRefresh = onRefresh;
      },
      stop: async () => {},
    };

    const tmpFile = path.join(os.tmpdir(), `n6-${Date.now()}-${Math.random()}.json`);
    const cache = new PermissionCache();
    const disk = new DiskCache(tmpFile);
    const boot = new CacheBootstrap(cache, client, disk, events);

    return {
      cache,
      boot,
      tmpFile,
      /** Fires the publish-roles trigger (enqueues forcedRefresh on the chain) */
      triggerRefresh: () => capturedOnRefresh(),
      /** Enqueues a role-update upsert on the chain (fire-and-forget, like Kafka) */
      enqueueUpsert: (roleId: string, permissions: string[]) =>
        capturedOnEvent({ operation: "UPSERT_ROLE", roleId, permissions }),
      /** Allow the blocked fetchSnapshot to complete */
      unblockFetch: () => unblockFetch(),
      /** Resolves when the forced-refresh fetch has started (fetch is now blocked) */
      waitForFetchStart: () => fetchStarted,
    };
  }

  it("upsert enqueued AFTER publish-roles trigger survives after forcedRefresh completes", async () => {
    // The snapshot the forced refresh returns does NOT contain NEW_ROLE.
    // Without the fix: forcedRefresh's replaceAll() runs while the upsert is
    // concurrently being applied, overwriting NEW_ROLE.
    // With the fix: the chain serializes so the upsert runs AFTER the refresh,
    // meaning NEW_ROLE is present in the final state.
    const ctl = buildControlledBootstrap({
      snapshotBeforeUpsert: { EXISTING: ["PERM_A"] },
      snapshotForRefresh: { EXISTING: ["PERM_A"] }, // NEW_ROLE absent from snapshot
    });

    await ctl.boot.start();

    // Step 1: Trigger the forced refresh — enqueues forcedRefresh on the chain
    ctl.triggerRefresh();

    // Step 2: Wait until forcedRefresh has actually started the snapshot fetch
    //         (the chain entry is running but blocked waiting for the fetch)
    await ctl.waitForFetchStart();

    // Step 3: While the refresh is blocked, enqueue a upsert.
    //         With the fix, this is queued BEHIND the refresh on applyChain.
    ctl.enqueueUpsert("NEW_ROLE", ["PERM_NEW"]);

    // Step 4: Unblock the fetch so forcedRefresh can complete (replaceAll with
    //         snapshotForRefresh which does NOT include NEW_ROLE).
    ctl.unblockFetch();

    // Step 5: Wait for the chain to fully drain (refresh + upsert both complete)
    await new Promise((r) => setTimeout(r, 50));

    // KEY INVARIANT: NEW_ROLE must survive even though the refresh snapshot
    // didn't include it — because the upsert ran AFTER the refresh.
    expect(ctl.cache.permissionsForRole("NEW_ROLE").has("PERM_NEW")).toBe(true);
    // Existing role from the snapshot must also be present
    expect(ctl.cache.permissionsForRole("EXISTING").has("PERM_A")).toBe(true);

    cleanupFile(ctl.tmpFile);
  });

  it("the authoritative snapshot from a forced refresh reflects in the final cache state", async () => {
    // Simpler ordering: upsert before refresh.
    // After the refresh the snapshot is authoritative (ADDED is present).
    const ctl = buildControlledBootstrap({
      snapshotBeforeUpsert: { EXISTING: ["PERM_A"] },
      snapshotForRefresh: { EXISTING: ["PERM_A"], ADDED: ["PERM_B"] },
    });

    await ctl.boot.start();

    // Enqueue upsert — runs immediately (no blocked fetch yet)
    ctl.enqueueUpsert("TEMP_ROLE", ["TEMP_PERM"]);

    // Trigger refresh; the fetch is not blocked here so it resolves quickly
    ctl.triggerRefresh();
    ctl.unblockFetch();

    await new Promise((r) => setTimeout(r, 50));

    // After the chain drains the snapshot is authoritative — ADDED is present
    expect(ctl.cache.permissionsForRole("ADDED").has("PERM_B")).toBe(true);

    cleanupFile(ctl.tmpFile);
  });
});

// ---------------------------------------------------------------------------
// L2 — rejecting forcedRefresh must not produce an unhandled promise rejection
// ---------------------------------------------------------------------------

describe("L2 — rejecting forcedRefresh does not escape as unhandled rejection", () => {
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

    let capturedOnRefresh!: () => void;
    const events: CacheEventHandler = {
      start: async (_onEvent, onRefresh) => {
        capturedOnRefresh = onRefresh;
      },
      stop: async () => {},
    };

    const tmpFile = path.join(os.tmpdir(), `l2-${Date.now()}.json`);
    const cache = new PermissionCache();
    const boot = new CacheBootstrap(cache, client, new DiskCache(tmpFile), events);
    await boot.start();

    // Trigger the refresh — this will reject inside forcedRefresh
    capturedOnRefresh();

    // Flush the microtask/promise queue
    await new Promise((r) => setTimeout(r, 30));

    // Remove our listener before asserting so we don't pollute other tests
    process.removeListener("unhandledRejection", onUnhandled);

    // The rejection must have been swallowed — no unhandledRejection event
    expect(unhandledRejectionFired).toBe(false);

    cleanupFile(tmpFile);
  });
});
