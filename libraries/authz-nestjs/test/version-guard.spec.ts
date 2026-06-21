/**
 * T24 — Version-aware cache application unit tests.
 *
 * Covers:
 *  - VersionStore.check(): apply-iff-strictly-greater, stale/equal ignored, missing-version → apply+warn-once
 *  - applyRoleEvent() with a VersionStore: UPSERT_ROLE version guard, DELETE_ROLE clears stored version
 *  - Backward-compat: missing version field → apply + one-time warning, no hard fail
 *  - HttpRoleServiceClient.fetchNormalisedSnapshot(): legacy bare-array + versioned-entry shapes
 *  - NormalisedSnapshot.versions populated only for versioned entries
 */
import { PermissionCache } from "../src/permission-cache/cache.js";
import { applyUpsert, applyDelete, VersionStore } from "../src/cache-sync/events.js";
import { HttpRoleServiceClient } from "../src/role-service-client/client.js";
import * as http from "http";
import { AddressInfo } from "net";

// ---------------------------------------------------------------------------
// VersionStore unit tests
// ---------------------------------------------------------------------------

describe("VersionStore", () => {
  it("applies first event for a key (no stored version)", () => {
    const store = new VersionStore();
    const result = store.check("ADMIN", 1);
    expect(result.shouldApply).toBe(true);
    store.record("ADMIN", 1);
  });

  it("applies event when incoming version > stored", () => {
    const store = new VersionStore();
    store.record("ADMIN", 5);
    const result = store.check("ADMIN", 6);
    expect(result.shouldApply).toBe(true);
  });

  it("rejects event when incoming version === stored (idempotent)", () => {
    const store = new VersionStore();
    store.record("ADMIN", 5);
    const result = store.check("ADMIN", 5);
    expect(result.shouldApply).toBe(false);
    expect(result.reason).toMatch(/stale version/);
  });

  it("rejects event when incoming version < stored (out-of-order)", () => {
    const store = new VersionStore();
    store.record("ADMIN", 10);
    const result = store.check("ADMIN", 3);
    expect(result.shouldApply).toBe(false);
    expect(result.reason).toMatch(/stale version/);
  });

  it("allows event when version is null (legacy — missing version)", () => {
    const store = new VersionStore();
    const result = store.check("ADMIN", null);
    expect(result.shouldApply).toBe(true);
  });

  it("allows event when version is undefined (legacy — missing version)", () => {
    const store = new VersionStore();
    const result = store.check("ADMIN", undefined);
    expect(result.shouldApply).toBe(true);
  });

  it("calls onMissingVersionWarn exactly once across multiple missing-version events", () => {
    const store = new VersionStore();
    let warnCount = 0;
    const warn = () => { warnCount++; };
    store.check("A", null, warn);
    store.check("B", null, warn);
    store.check("C", undefined, warn);
    expect(warnCount).toBe(1);
  });

  it("delete() removes stored version so future event with any version is accepted", () => {
    const store = new VersionStore();
    store.record("ADMIN", 5);
    store.delete("ADMIN");
    const result = store.check("ADMIN", 3); // version 3 < 5 but stored is gone
    expect(result.shouldApply).toBe(true);
  });

  it("tracks versions per key independently", () => {
    const store = new VersionStore();
    store.record("ADMIN", 10);
    store.record("VIEWER", 2);
    expect(store.check("ADMIN", 11).shouldApply).toBe(true);
    expect(store.check("VIEWER", 3).shouldApply).toBe(true);
    expect(store.check("ADMIN", 9).shouldApply).toBe(false);
    expect(store.check("VIEWER", 2).shouldApply).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// applyUpsert / applyDelete with VersionStore
// ---------------------------------------------------------------------------

describe("applyUpsert/applyDelete — T24 version guard", () => {
  let cache: PermissionCache;
  let store: VersionStore;

  beforeEach(() => {
    cache = new PermissionCache();
    store = new VersionStore();
  });

  it("applies upsert with version 1 (no prior version)", async () => {
    const result = await applyUpsert(
      cache,
      { roleId: "ADMIN", permissions: ["READ"], version: 1 },
      store,
    );
    expect(result.applied).toBe(true);
    expect(cache.permissionsForRole("ADMIN").has("READ")).toBe(true);
  });

  it("applies upsert with version 2 after version 1", async () => {
    await applyUpsert(cache, { roleId: "ADMIN", permissions: ["READ"], version: 1 }, store);
    const result = await applyUpsert(
      cache,
      { roleId: "ADMIN", permissions: ["READ", "WRITE"], version: 2 },
      store,
    );
    expect(result.applied).toBe(true);
    expect(cache.permissionsForRole("ADMIN").has("WRITE")).toBe(true);
  });

  it("rejects stale upsert (version <= stored)", async () => {
    await applyUpsert(cache, { roleId: "ADMIN", permissions: ["READ"], version: 5 }, store);
    // Simulate out-of-order Kafka: version 3 arrives after 5
    const result = await applyUpsert(
      cache,
      { roleId: "ADMIN", permissions: ["DOWNGRADED"], version: 3 },
      store,
    );
    expect(result.applied).toBe(false);
    expect(result.reason).toMatch(/stale version/);
    expect(cache.permissionsForRole("ADMIN").has("READ")).toBe(true);
    expect(cache.permissionsForRole("ADMIN").has("DOWNGRADED")).toBe(false);
  });

  it("rejects duplicate upsert (same version)", async () => {
    await applyUpsert(cache, { roleId: "ADMIN", permissions: ["READ"], version: 5 }, store);
    const result = await applyUpsert(
      cache,
      { roleId: "ADMIN", permissions: ["READ"], version: 5 },
      store,
    );
    expect(result.applied).toBe(false);
    expect(result.reason).toMatch(/stale version/);
  });

  it("applies upsert without version (legacy — backward-compat) and calls warn once", async () => {
    let warned = false;
    const warnFn = () => { warned = true; };
    const result = await applyUpsert(
      cache,
      { roleId: "VIEWER", permissions: ["GET"] },
      store,
      warnFn,
    );
    expect(result.applied).toBe(true);
    expect(warned).toBe(true);
    expect(cache.permissionsForRole("VIEWER").has("GET")).toBe(true);
  });

  it("warns only once across multiple missing-version events", async () => {
    let warnCount = 0;
    const warnFn = () => { warnCount++; };
    await applyUpsert(cache, { roleId: "A", permissions: [] }, store, warnFn);
    await applyUpsert(cache, { roleId: "B", permissions: [] }, store, warnFn);
    await applyUpsert(cache, { roleId: "C", permissions: [] }, store, warnFn);
    expect(warnCount).toBe(1);
  });

  it("applyDelete clears stored version so re-add with any version is accepted", async () => {
    await applyUpsert(cache, { roleId: "ADMIN", permissions: ["READ"], version: 10 }, store);
    await applyDelete(cache, { roleId: "ADMIN" }, store);
    // After delete, version 3 < 10 but stored version was cleared — must apply
    const result = await applyUpsert(
      cache,
      { roleId: "ADMIN", permissions: ["RESTORED"], version: 3 },
      store,
    );
    expect(result.applied).toBe(true);
    expect(cache.permissionsForRole("ADMIN").has("RESTORED")).toBe(true);
  });

  it("without VersionStore — applies all events regardless of version field (backward-compat)", async () => {
    // No versionStore passed — always-apply path
    await applyUpsert(cache, { roleId: "ADMIN", permissions: ["A"], version: 10 });
    const result = await applyUpsert(cache, { roleId: "ADMIN", permissions: ["B"], version: 1 });
    expect(result.applied).toBe(true);
    expect(cache.permissionsForRole("ADMIN").has("B")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// HttpRoleServiceClient.fetchNormalisedSnapshot — versioned + legacy shapes
// ---------------------------------------------------------------------------

async function startJsonServer(body: unknown): Promise<{ url: string; close: () => Promise<void> }> {
  const server = http.createServer((_req, res) => {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(body));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

describe("HttpRoleServiceClient.fetchNormalisedSnapshot — T24", () => {
  it("legacy format (bare string[]) → roles populated, versions map empty", async () => {
    const srv = await startJsonServer({ ADMIN: ["READ", "WRITE"], VIEWER: ["READ"] });
    try {
      const client = new HttpRoleServiceClient({ baseUrl: srv.url });
      const { roles, versions } = await client.fetchNormalisedSnapshot();
      expect(roles).toEqual({ ADMIN: ["READ", "WRITE"], VIEWER: ["READ"] });
      expect(versions.size).toBe(0);
    } finally {
      await srv.close();
    }
  });

  it("versioned format ({ permissions, version }) → roles + versions populated", async () => {
    const srv = await startJsonServer({
      ADMIN: { permissions: ["READ", "WRITE"], version: 7 },
      VIEWER: { permissions: ["READ"], version: 3 },
    });
    try {
      const client = new HttpRoleServiceClient({ baseUrl: srv.url });
      const { roles, versions } = await client.fetchNormalisedSnapshot();
      expect(roles).toEqual({ ADMIN: ["READ", "WRITE"], VIEWER: ["READ"] });
      expect(versions.get("ADMIN")).toBe(7);
      expect(versions.get("VIEWER")).toBe(3);
    } finally {
      await srv.close();
    }
  });

  it("mixed format (some versioned, some legacy) → versions only for versioned entries", async () => {
    const srv = await startJsonServer({
      ADMIN: { permissions: ["READ"], version: 5 },
      VIEWER: ["GET"],
    });
    try {
      const client = new HttpRoleServiceClient({ baseUrl: srv.url });
      const { roles, versions } = await client.fetchNormalisedSnapshot();
      expect(roles["ADMIN"]).toEqual(["READ"]);
      expect(roles["VIEWER"]).toEqual(["GET"]);
      expect(versions.get("ADMIN")).toBe(5);
      expect(versions.has("VIEWER")).toBe(false);
    } finally {
      await srv.close();
    }
  });

  it("fetchSnapshot() still returns plain RoleMap (backward-compat with SPI)", async () => {
    const srv = await startJsonServer({
      ADMIN: { permissions: ["READ"], version: 5 },
    });
    try {
      const client = new HttpRoleServiceClient({ baseUrl: srv.url });
      const roles = await client.fetchSnapshot();
      expect(roles).toEqual({ ADMIN: ["READ"] });
    } finally {
      await srv.close();
    }
  });
});
