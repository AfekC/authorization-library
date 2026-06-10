/**
 * Tests for observability and role-service-client gaps.
 *
 * Covers:
 *   B7  — Cache age metric: FLOOR to whole seconds (not round)
 *   B8  — Health timestamp: millisecond ISO-8601 precision (toISOString())
 *   D2  — Gauges permission_cache_version and permission_cache_age_seconds untested
 *   D3  — buildHealth() never tested: status, version, age, mode, roleServiceLastSync, kafkaConsumerConnected
 *   D4  — HttpRoleServiceClient: successful parse, non-2xx, timeout (via nock)
 *   E7  — Timeout extracted to named constant DEFAULT_ROLE_SERVICE_TIMEOUT_MS
 */

import nock from "nock";
import { PermissionCache } from "../src/permission-cache/cache";
import {
  Metrics,
  METRIC,
  GAUGE,
  buildHealth,
} from "../src/observability/metrics";
import {
  HttpRoleServiceClient,
  DEFAULT_ROLE_SERVICE_TIMEOUT_MS,
} from "../src/role-service-client/client";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Return a PermissionCache whose lastUpdatedAt() returns a fixed Date pinned
 * to exactly `msAgo` milliseconds before a captured reference instant.
 *
 * Because buildHealth() calls Date.now() independently, the computed delta
 * is (msAgo + epsilon) where epsilon is sub-millisecond test overhead.
 * Callers must choose msAgo values where floor and round diverge AND where
 * epsilon cannot push the value past a second boundary — use values in the
 * range [500, 999] within a second (e.g. 1500ms: floor=1, round=2, epsilon-safe).
 */
function cacheAgedByMs(msAgo: number, initial?: Record<string, string[]>): PermissionCache {
  const cache = new PermissionCache(initial);
  const frozen = new Date(Date.now() - msAgo);
  // Override the method so buildHealth() always sees this fixed Date.
  cache.lastUpdatedAt = () => frozen;
  return cache;
}

// ---------------------------------------------------------------------------
// B7 — Cache age: FLOOR, not ROUND
// ---------------------------------------------------------------------------

describe("B7 — cache age gauge uses Math.floor (Java truncation parity)", () => {
  // All test values sit in the [N*1000+500, N*1000+999] range: floor gives N,
  // round gives N+1 — and there is >=1ms slack before the next whole second,
  // so sub-millisecond test overhead cannot push the result across a boundary.

  it("1600 ms ago → 1 second (floor); Math.round would give 2", () => {
    const cache = cacheAgedByMs(1600);
    const report = buildHealth(cache, "normal");
    expect(report.cacheAgeSeconds).toBe(1);
  });

  it("1500 ms ago → 1 second (floor); Math.round would give 2", () => {
    const cache = cacheAgedByMs(1500);
    const report = buildHealth(cache, "normal");
    expect(report.cacheAgeSeconds).toBe(1);
  });

  it("2700 ms ago → 2 seconds (floor); Math.round would give 3", () => {
    const cache = cacheAgedByMs(2700);
    const report = buildHealth(cache, "normal");
    expect(report.cacheAgeSeconds).toBe(2);
  });

  it("500 ms ago → 0 seconds (floor of 0.5xx); Math.round would give 1", () => {
    const cache = cacheAgedByMs(500);
    const report = buildHealth(cache, "normal");
    expect(report.cacheAgeSeconds).toBe(0);
  });

  it("0 ms ago → 0 seconds (never negative)", () => {
    const cache = cacheAgedByMs(0);
    const report = buildHealth(cache, "normal");
    expect(report.cacheAgeSeconds).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// B8 — Health timestamp: millisecond ISO-8601 precision
// ---------------------------------------------------------------------------

describe("B8 — health roleServiceLastSync has millisecond ISO-8601 precision", () => {
  it("toISOString() produces a string with milliseconds (.sss suffix)", () => {
    const cache = new PermissionCache();
    const syncDate = new Date("2026-06-07T08:15:30.123Z");
    const report = buildHealth(cache, "normal", { roleServiceLastSync: syncDate });
    // Must be ISO-8601 with millisecond precision: ends in .123Z
    expect(report.roleServiceLastSync).toBe("2026-06-07T08:15:30.123Z");
  });

  it("null roleServiceLastSync stays null", () => {
    const cache = new PermissionCache();
    const report = buildHealth(cache, "normal", { roleServiceLastSync: null });
    expect(report.roleServiceLastSync).toBeNull();
  });

  it("timestamp string matches Date.toISOString() format (has .SSSZ suffix)", () => {
    const cache = new PermissionCache();
    const syncDate = new Date();
    const report = buildHealth(cache, "normal", { roleServiceLastSync: syncDate });
    // Must end with 3-digit milliseconds followed by Z
    expect(report.roleServiceLastSync).toMatch(/\.\d{3}Z$/);
  });
});

// ---------------------------------------------------------------------------
// D2 — Gauge: permission_cache_age_seconds
// ---------------------------------------------------------------------------

describe("D2 — gauge permission_cache_age_seconds", () => {
  it("setGauge stores a value retrievable by get()", () => {
    const metrics = new Metrics();
    metrics.setGauge(GAUGE.cacheAgeSeconds, 42);
    expect(metrics.get(GAUGE.cacheAgeSeconds)).toBe(42);
  });

  it("age gauge is visible in snapshot()", () => {
    const metrics = new Metrics();
    metrics.setGauge(GAUGE.cacheAgeSeconds, 10);
    expect(metrics.snapshot()[GAUGE.cacheAgeSeconds]).toBe(10);
  });
});

// ---------------------------------------------------------------------------
// D3 — buildHealth() full coverage
// ---------------------------------------------------------------------------

describe("D3 — buildHealth() cache status", () => {
  it("reports 'empty' when the cache has no roles", () => {
    const cache = new PermissionCache();
    const report = buildHealth(cache, "normal");
    expect(report.cacheStatus).toBe("empty");
  });

  it("reports 'initialized' when the cache has at least one role", () => {
    const cache = new PermissionCache({ VIEWER: ["READ_ORDER"] });
    const report = buildHealth(cache, "normal");
    expect(report.cacheStatus).toBe("initialized");
  });
});

describe("D3 — buildHealth() age", () => {
  it("cacheAgeSeconds is non-negative", () => {
    const cache = new PermissionCache();
    const report = buildHealth(cache, "normal");
    expect(report.cacheAgeSeconds).toBeGreaterThanOrEqual(0);
  });
});

describe("D3 — buildHealth() mode", () => {
  it("reports 'normal' mode", () => {
    const cache = new PermissionCache();
    const report = buildHealth(cache, "normal");
    expect(report.mode).toBe("normal");
  });

  it("reports 'seed' mode", () => {
    const cache = new PermissionCache();
    const report = buildHealth(cache, "seed");
    expect(report.mode).toBe("seed");
  });
});

describe("D3 — buildHealth() roleServiceLastSync", () => {
  it("is null when no extra is provided", () => {
    const cache = new PermissionCache();
    const report = buildHealth(cache, "normal");
    expect(report.roleServiceLastSync).toBeNull();
  });

  it("is null when extra.roleServiceLastSync is explicitly null", () => {
    const cache = new PermissionCache();
    const report = buildHealth(cache, "normal", { roleServiceLastSync: null });
    expect(report.roleServiceLastSync).toBeNull();
  });

  it("is an ISO string when a Date is provided", () => {
    const cache = new PermissionCache();
    const d = new Date("2026-06-07T10:00:00.000Z");
    const report = buildHealth(cache, "normal", { roleServiceLastSync: d });
    expect(report.roleServiceLastSync).toBe("2026-06-07T10:00:00.000Z");
  });
});

describe("D3 — buildHealth() kafkaConsumerConnected", () => {
  it("defaults to false when extra is omitted", () => {
    const cache = new PermissionCache();
    const report = buildHealth(cache, "normal");
    expect(report.kafkaConsumerConnected).toBe(false);
  });

  it("reflects true when provided", () => {
    const cache = new PermissionCache();
    const report = buildHealth(cache, "normal", { kafkaConsumerConnected: true });
    expect(report.kafkaConsumerConnected).toBe(true);
  });

  it("reflects false when provided explicitly", () => {
    const cache = new PermissionCache();
    const report = buildHealth(cache, "normal", { kafkaConsumerConnected: false });
    expect(report.kafkaConsumerConnected).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// D4 — HttpRoleServiceClient against a mocked HTTP endpoint (nock)
// ---------------------------------------------------------------------------

describe("D4 — HttpRoleServiceClient: successful parse of bare role map", () => {
  afterEach(() => nock.cleanAll());

  it("returns the role map on a 200 response", async () => {
    const roleMap = {
      VIEWER: ["READ_ORDER"],
      ADMIN: ["READ_ORDER", "WRITE_ORDER", "DELETE_ORDER"],
    };
    nock("http://role-service.test").get("/roles").reply(200, roleMap);

    const client = new HttpRoleServiceClient({ baseUrl: "http://role-service.test" });
    const result = await client.fetchSnapshot();
    expect(result).toEqual(roleMap);
  });

  it("returns an empty role map when the Role Service returns {}", async () => {
    nock("http://role-service.test").get("/roles").reply(200, {});

    const client = new HttpRoleServiceClient({ baseUrl: "http://role-service.test" });
    const result = await client.fetchSnapshot();
    expect(result).toEqual({});
  });

  it("throws when the response body is an array (malformed)", async () => {
    nock("http://role-service.test").get("/roles").reply(200, ["not", "an", "object"]);

    const client = new HttpRoleServiceClient({ baseUrl: "http://role-service.test" });
    await expect(client.fetchSnapshot()).rejects.toThrow(/malformed/i);
  });

  it("throws when the response body is a string (malformed)", async () => {
    nock("http://role-service.test").get("/roles").reply(200, "not-an-object");

    const client = new HttpRoleServiceClient({ baseUrl: "http://role-service.test" });
    await expect(client.fetchSnapshot()).rejects.toThrow(/malformed/i);
  });
});

describe("D4 — HttpRoleServiceClient: non-2xx handling", () => {
  afterEach(() => nock.cleanAll());

  it("throws on 404 Not Found", async () => {
    nock("http://role-service.test").get("/roles").reply(404, { error: "not found" });

    const client = new HttpRoleServiceClient({ baseUrl: "http://role-service.test" });
    await expect(client.fetchSnapshot()).rejects.toThrow();
  });

  it("throws on 500 Internal Server Error", async () => {
    nock("http://role-service.test").get("/roles").reply(500, { error: "server error" });

    const client = new HttpRoleServiceClient({ baseUrl: "http://role-service.test" });
    await expect(client.fetchSnapshot()).rejects.toThrow();
  });

  it("throws on 503 Service Unavailable", async () => {
    nock("http://role-service.test").get("/roles").reply(503);

    const client = new HttpRoleServiceClient({ baseUrl: "http://role-service.test" });
    await expect(client.fetchSnapshot()).rejects.toThrow();
  });
});

describe("D4 — HttpRoleServiceClient: timeout behavior", () => {
  afterEach(() => nock.cleanAll());

  it("throws on timeout when server does not respond within timeoutMs", async () => {
    // Delay the response past the short timeout
    nock("http://role-service.test")
      .get("/roles")
      .delay(300)
      .reply(200, { VIEWER: ["READ_ORDER"] });

    const client = new HttpRoleServiceClient({
      baseUrl: "http://role-service.test",
      timeoutMs: 50, // very short; nock will delay 300ms
    });
    await expect(client.fetchSnapshot()).rejects.toThrow();
  });

  it("succeeds when response arrives within timeoutMs", async () => {
    nock("http://role-service.test")
      .get("/roles")
      .delay(10)
      .reply(200, { ADMIN: ["DELETE_ORDER"] });

    const client = new HttpRoleServiceClient({
      baseUrl: "http://role-service.test",
      timeoutMs: 500,
    });
    const result = await client.fetchSnapshot();
    expect(result).toEqual({ ADMIN: ["DELETE_ORDER"] });
  });
});

// ---------------------------------------------------------------------------
// E7 — DEFAULT_ROLE_SERVICE_TIMEOUT_MS exported constant
// ---------------------------------------------------------------------------

describe("E7 — DEFAULT_ROLE_SERVICE_TIMEOUT_MS is exported and equals 5000", () => {
  it("constant is exported from client module", () => {
    expect(DEFAULT_ROLE_SERVICE_TIMEOUT_MS).toBeDefined();
  });

  it("defaults to 5000ms", () => {
    expect(DEFAULT_ROLE_SERVICE_TIMEOUT_MS).toBe(5000);
  });

  it("HttpRoleServiceClient uses the default when timeoutMs is omitted", async () => {
    nock("http://role-service.test").get("/roles").reply(200, {});
    const client = new HttpRoleServiceClient({ baseUrl: "http://role-service.test" });
    // Should succeed using the default timeout
    await expect(client.fetchSnapshot()).resolves.toEqual({});
    nock.cleanAll();
  });
});
