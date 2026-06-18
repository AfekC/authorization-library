/**
 * Tests for O4 — StripHeadersOptions extension parameters:
 *   - additionalPrefixes: custom header prefixes stripped in addition to defaults
 *   - additionalExactNames: custom exact header names stripped in addition to defaults
 *   - Case-insensitive matching (mixed-case header names)
 *   - Overlap case: a name already in the default deny-list plus a custom one
 *   - Unrelated headers are preserved in all cases
 *
 * Also covers P3 re-export reachability: extractBearer, sanitizeHeadersInPlace,
 * and StripHeadersOptions must be importable from the package index (src/index.ts).
 */

import {
  sanitizeHeadersInPlace,
  stripUntrustedHeaders,
} from "../src/inbound-auth/context.js";

// ---------------------------------------------------------------------------
// O4 — StripHeadersOptions extension: additionalPrefixes
// ---------------------------------------------------------------------------

describe("O4 — StripHeadersOptions: additionalPrefixes", () => {
  it("strips headers matching a custom prefix in addition to the default deny-list", () => {
    const headers: Record<string, unknown> = {
      "x-internal-secret": "leaked",
      "x-user-id": "spoof",          // default deny-list
      "content-type": "application/json",
      authorization: "Bearer tok",
    };
    sanitizeHeadersInPlace(headers, { additionalPrefixes: ["x-internal-"] });

    expect(headers["x-internal-secret"]).toBeUndefined();   // custom prefix — stripped
    expect(headers["x-user-id"]).toBeUndefined();           // default prefix — still stripped
    expect(headers["content-type"]).toBe("application/json"); // unrelated — preserved
    expect(headers["authorization"]).toBe("Bearer tok");     // validator header — preserved
  });

  it("multiple custom prefixes are all applied", () => {
    const headers: Record<string, unknown> = {
      "x-debug-flag": "true",
      "x-private-data": "sensitive",
      "accept": "application/json",
    };
    sanitizeHeadersInPlace(headers, {
      additionalPrefixes: ["x-debug-", "x-private-"],
    });

    expect(headers["x-debug-flag"]).toBeUndefined();
    expect(headers["x-private-data"]).toBeUndefined();
    expect(headers["accept"]).toBe("application/json");
  });

  it("same behaviour via stripUntrustedHeaders with additionalPrefixes", () => {
    const source: Record<string, unknown> = {
      "x-internal-secret": "leaked",
      "host": "example.com",
    };
    const result = stripUntrustedHeaders(source, { additionalPrefixes: ["x-internal-"] });

    expect(result["x-internal-secret"]).toBeUndefined();
    expect(result["host"]).toBe("example.com");
  });
});

// ---------------------------------------------------------------------------
// O4 — StripHeadersOptions extension: additionalExactNames
// ---------------------------------------------------------------------------

describe("O4 — StripHeadersOptions: additionalExactNames", () => {
  it("strips a custom exact-name header not in the default deny-list", () => {
    const headers: Record<string, unknown> = {
      "x-forwarded-user": "spoof",
      "x-request-id": "trace-999",
      "content-length": "42",
    };
    sanitizeHeadersInPlace(headers, { additionalExactNames: ["x-forwarded-user"] });

    expect(headers["x-forwarded-user"]).toBeUndefined();  // custom exact — stripped
    expect(headers["x-request-id"]).toBe("trace-999");   // trace id — preserved
    expect(headers["content-length"]).toBe("42");         // unrelated — preserved
  });

  it("multiple custom exact names are all stripped", () => {
    const headers: Record<string, unknown> = {
      "x-auth-override": "evil",
      "x-impersonate": "admin",
      "cache-control": "no-cache",
    };
    sanitizeHeadersInPlace(headers, {
      additionalExactNames: ["x-auth-override", "x-impersonate"],
    });

    expect(headers["x-auth-override"]).toBeUndefined();
    expect(headers["x-impersonate"]).toBeUndefined();
    expect(headers["cache-control"]).toBe("no-cache");
  });

  it("same behaviour via stripUntrustedHeaders with additionalExactNames", () => {
    const source: Record<string, unknown> = {
      "x-forwarded-user": "spoof",
      "host": "example.com",
    };
    const result = stripUntrustedHeaders(source, { additionalExactNames: ["x-forwarded-user"] });

    expect(result["x-forwarded-user"]).toBeUndefined();
    expect(result["host"]).toBe("example.com");
  });
});

// ---------------------------------------------------------------------------
// O4 — Case-insensitive matching (mixed-case header names)
// ---------------------------------------------------------------------------

describe("O4 — Case-insensitive matching for custom and default deny-list entries", () => {
  it("mixed-case default identity header is stripped (X-User-Id → lower → x-user-id)", () => {
    const headers: Record<string, unknown> = {
      "X-User-Id": "SPOOF",          // title-case — must still match default prefix
      "Content-Type": "text/plain",
    };
    sanitizeHeadersInPlace(headers);

    expect(headers["X-User-Id"]).toBeUndefined();
    expect(headers["Content-Type"]).toBe("text/plain");
  });

  it("mixed-case custom prefix is matched case-insensitively", () => {
    // The key is stored in the object with mixed case; the library lowercases it
    // before comparing against the (already lower-cased) additionalPrefixes entry.
    const headers: Record<string, unknown> = {
      "X-Internal-Secret": "leaked",  // mixed-case key
      "Host": "example.com",
    };
    // Custom prefix is supplied lower-cased (as documented)
    sanitizeHeadersInPlace(headers, { additionalPrefixes: ["x-internal-"] });

    expect(headers["X-Internal-Secret"]).toBeUndefined();
    expect(headers["Host"]).toBe("example.com");
  });

  it("mixed-case custom exact name is matched case-insensitively", () => {
    const headers: Record<string, unknown> = {
      "X-Forwarded-User": "spoof",   // mixed-case key
      "Accept": "application/json",
    };
    sanitizeHeadersInPlace(headers, { additionalExactNames: ["x-forwarded-user"] });

    expect(headers["X-Forwarded-User"]).toBeUndefined();
    expect(headers["Accept"]).toBe("application/json");
  });

  it("stripUntrustedHeaders also handles mixed-case keys correctly", () => {
    const source: Record<string, unknown> = {
      "X-Role": "admin",             // mixed-case default exact name
      "X-Internal-Flag": "1",
      "Authorization": "Bearer tok",
    };
    const result = stripUntrustedHeaders(source, { additionalPrefixes: ["x-internal-"] });

    expect(result["X-Role"]).toBeUndefined();
    expect(result["X-Internal-Flag"]).toBeUndefined();
    expect(result["Authorization"]).toBe("Bearer tok");
  });
});

// ---------------------------------------------------------------------------
// O4 — Overlap case: custom entry duplicates a default deny-list entry
// ---------------------------------------------------------------------------

describe("O4 — Overlap case: custom entry duplicates default deny-list", () => {
  it("sanitizeHeadersInPlace is idempotent when custom prefix overlaps default", () => {
    // "x-user-" is already in the default prefix list; adding it as a custom
    // prefix must not break anything — the header is still stripped exactly once.
    const headers: Record<string, unknown> = {
      "x-user-id": "spoof",
      "x-extra-custom": "also-spoof",
      "content-type": "application/json",
    };
    sanitizeHeadersInPlace(headers, {
      additionalPrefixes: ["x-user-", "x-extra-"],  // x-user- duplicates default
    });

    expect(headers["x-user-id"]).toBeUndefined();
    expect(headers["x-extra-custom"]).toBeUndefined();
    expect(headers["content-type"]).toBe("application/json");
  });

  it("sanitizeHeadersInPlace is idempotent when custom exact name overlaps default", () => {
    // "x-role" is already in DEFAULT_IDENTITY_HEADERS_EXACT; duplicating it
    // as a custom exact name must not break anything.
    const headers: Record<string, unknown> = {
      "x-role": "admin",
      "x-custom-spoofed": "evil",
      "host": "example.com",
    };
    sanitizeHeadersInPlace(headers, {
      additionalExactNames: ["x-role", "x-custom-spoofed"],  // x-role duplicates default
    });

    expect(headers["x-role"]).toBeUndefined();
    expect(headers["x-custom-spoofed"]).toBeUndefined();
    expect(headers["host"]).toBe("example.com");
  });

  it("stripUntrustedHeaders overlap: duplicate prefix yields same result as default only", () => {
    const source: Record<string, unknown> = {
      "x-user-id": "spoof",
      "host": "example.com",
    };
    const withOverlap = stripUntrustedHeaders({ ...source }, {
      additionalPrefixes: ["x-user-"],  // already default
    });
    const withoutOverlap = stripUntrustedHeaders({ ...source });

    expect(Object.keys(withOverlap).sort()).toEqual(Object.keys(withoutOverlap).sort());
  });
});

// ---------------------------------------------------------------------------
// P3 — Re-export reachability from the package index
// ---------------------------------------------------------------------------

describe("P3 — extractBearer and sanitizeHeadersInPlace re-exported from package index", () => {
  it("extractBearer is a function exported from src/index", async () => {
    // Dynamic import so a compile-time type error in index.ts surfaces as a test failure
    const idx = await import("../src/index");
    expect(typeof (idx as any).extractBearer).toBe("function");
  });

  it("sanitizeHeadersInPlace is a function exported from src/index", async () => {
    const idx = await import("../src/index");
    expect(typeof (idx as any).sanitizeHeadersInPlace).toBe("function");
  });

  it("extractBearer extracted from index works correctly end-to-end", async () => {
    const { extractBearer } = await import("../src/index") as any;
    expect(extractBearer("Bearer my-token")).toBe("my-token");
    expect(extractBearer("bearer lowercase")).toBe("lowercase");
    expect(extractBearer(undefined)).toBeUndefined();
    expect(extractBearer("NotBearer foo")).toBeUndefined();
  });

  it("sanitizeHeadersInPlace extracted from index works correctly end-to-end", async () => {
    const { sanitizeHeadersInPlace: sip } = await import("../src/index") as any;
    const headers: Record<string, unknown> = { "x-user-id": "spoof", "content-type": "text/html" };
    sip(headers);
    expect(headers["x-user-id"]).toBeUndefined();
    expect(headers["content-type"]).toBe("text/html");
  });
});
