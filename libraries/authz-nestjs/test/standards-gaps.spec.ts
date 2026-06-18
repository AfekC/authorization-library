/**
 * Tests for standards-audit gap fixes (general best-practice alignment):
 *   GAP-1  — DiskCache.write() is atomic (temp file + rename); no partial file on failure
 *   GAP-3  — Kafka unparseable events: logged + counted via injected hooks (not console)
 *   GAP-4  — Service-token provider onError callback that throws must not break retry
 *   GAP-5  — Role Service snapshot: blank role id is rejected
 *   GAP-9  — CacheBootstrap.stop() disconnects the Kafka consumer; stop() is idempotent
 *   GAP-10 — Outbound: blank/whitespace service token is not attached
 *   GAP-8  — createAuthz: whitespace-only audience is rejected
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { DiskCache } from "../src/cache-sync/disk.js";
import { CacheBootstrap } from "../src/cache-sync/bootstrap.js";
import { KafkaCacheEventHandler } from "../src/cache-sync/kafka.js";
import { PermissionCache } from "../src/permission-cache/cache.js";
import { HttpRoleServiceClient } from "../src/role-service-client/client.js";
import { ClientCredentialsProvider } from "../src/service-token/provider.js";
import { buildOutboundHeaders } from "../src/outbound/propagation.js";
import { RequestContext } from "../src/inbound-auth/context.js";
import { RoleServiceClient, CacheEventHandler, ServiceIdentityProvider } from "../src/spi.js";
import { createAuthzFromOptions as createAuthz } from "../src/bootstrap/create-authz.js";
import { ConfigError } from "../src/rule-config/types.js";
import nock from "nock";

// ---------------------------------------------------------------------------
// GAP-1 — atomic disk write
// ---------------------------------------------------------------------------

describe("GAP-1 — DiskCache.write() is atomic", () => {
  it("leaves no .tmp sibling behind on success", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "authz-atomic-"));
    const target = path.join(dir, "cache.json");
    const disk = new DiskCache(target);

    expect(disk.write(new PermissionCache({ ADMIN: ["READ"] }))).toBeNull();
    expect(fs.existsSync(target)).toBe(true);

    const leftovers = fs.readdirSync(dir).filter((f) => f.endsWith(".tmp"));
    expect(leftovers).toHaveLength(0);

    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("creates no partial target file when the write fails", () => {
    // Target lives in a non-existent directory, so the temp write fails. The
    // atomic approach means the target file is never created (no partial/empty
    // file), the temp file is cleaned up, and write() returns the error.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "authz-atomic-"));
    const target = path.join(dir, "missing-subdir", "cache.json");
    const disk = new DiskCache(target);

    const err = disk.write(new PermissionCache({ ADMIN: ["READ"] }));
    expect(err).toBeInstanceOf(Error);
    expect(fs.existsSync(target)).toBe(false);

    fs.rmSync(dir, { recursive: true, force: true });
  });
});

// ---------------------------------------------------------------------------
// GAP-3 — unparseable Kafka events go through logger + metric hook
// ---------------------------------------------------------------------------

describe("GAP-3 — unparseable role events are logged and counted, not console", () => {
  it("invokes onSkippedEvent and logger.warn for a malformed message", async () => {
    const warns: string[] = [];
    let skipped = 0;
    const handler = new KafkaCacheEventHandler({
      brokers: ["localhost:9092"],
      logger: { warn: (m) => warns.push(m) },
      onSkippedEvent: () => skipped++,
    });

    // Drive the eachMessage handler directly by stubbing consumer.run to
    // capture the callback, then feed it a malformed message.
    let eachMessage: any;
    const fakeConsumer = {
      connect: async () => {},
      subscribe: async () => {},
      run: async (opts: any) => {
        eachMessage = opts.eachMessage;
      },
      disconnect: async () => {},
    };
    (handler as any).kafka = { consumer: () => fakeConsumer };

    await handler.start(
      () => {
        throw new Error("onEvent should not be called for a bad message");
      },
      () => {},
    );
    await eachMessage({
      topic: "role-updates",
      message: { value: Buffer.from("not json{{{") },
    });

    expect(skipped).toBe(1);
    expect(warns.some((w) => w.includes("unparseable"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// GAP-4 — onError callback that throws must not break acquisition retry
// ---------------------------------------------------------------------------

describe("GAP-4 — throwing onError callback is contained", () => {
  afterEach(() => nock.cleanAll());

  it("still acquires a token even when onError throws on each failed attempt", async () => {
    const tokenHost = "https://sso.example.test";
    // First attempt 500 (triggers onError), second attempt succeeds.
    nock(tokenHost).post("/token").reply(500, "fail");
    nock(tokenHost)
      .post("/token")
      .reply(200, { access_token: "tok-123", token_type: "bearer", expires_in: 3600 });

    const warns: string[] = [];
    const provider = new ClientCredentialsProvider({
      tokenUrl: `${tokenHost}/token`,
      clientId: "id",
      clientSecret: "secret",
      maxRetries: 3,
      retryMinTimeoutMs: 1,
      onError: () => {
        throw new Error("metrics sink blew up");
      },
      logger: { warn: (m) => warns.push(m) },
    });

    const token = await provider.getServiceToken();
    expect(token).toBe("tok-123");
    expect(warns.some((w) => w.includes("onError callback threw"))).toBe(true);
    provider.close();
  });
});

// ---------------------------------------------------------------------------
// GAP-5 — blank role id in snapshot is rejected
// ---------------------------------------------------------------------------

describe("GAP-5 — Role Service snapshot rejects a blank role id", () => {
  afterEach(() => nock.cleanAll());

  it("throws when a role id is an empty string", async () => {
    const base = "https://roles.example.test";
    nock(base).get("/roles").reply(200, { "": ["READ"], ADMIN: ["WRITE"] });
    const client = new HttpRoleServiceClient({ baseUrl: base, timeoutMs: 2000 });
    await expect(client.fetchSnapshot()).rejects.toThrow(/non-empty string/i);
  });
});

// ---------------------------------------------------------------------------
// GAP-9 — stop() disconnects Kafka and is idempotent
// ---------------------------------------------------------------------------

describe("GAP-9 — CacheBootstrap.stop() disconnects Kafka", () => {
  it("calls events.stop() on shutdown", async () => {
    let stopped = 0;
    const events: CacheEventHandler = {
      start: async () => {},
      stop: async () => {
        stopped++;
      },
    };
    const cache = new PermissionCache({ ADMIN: ["READ"] });
    const role: RoleServiceClient = { fetchSnapshot: async () => ({ ADMIN: ["READ"] }) };
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "authz-stop-"));
    const disk = new DiskCache(path.join(dir, "c.json"));

    const boot = new CacheBootstrap(cache, role, disk, events);
    await boot.start();
    boot.stop();
    // stop() fires events.stop() without awaiting; let the microtask settle.
    await new Promise((r) => setTimeout(r, 0));
    expect(stopped).toBeGreaterThanOrEqual(1);

    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("KafkaCacheEventHandler.stop() is idempotent (no double-disconnect)", async () => {
    let disconnects = 0;
    const handler = new KafkaCacheEventHandler({ brokers: ["localhost:9092"] });
    (handler as any).consumer = {
      disconnect: async () => {
        disconnects++;
      },
    };
    await handler.stop();
    await handler.stop();
    expect(disconnects).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// GAP-10 — blank service token is not attached as a header
// ---------------------------------------------------------------------------

describe("GAP-10 — blank service token is not attached", () => {
  const ctx = {
    correlationId: "corr-1",
    requestId: "req-1",
  } as RequestContext;

  it("omits X-Service-Token when the provider returns whitespace", async () => {
    const provider: ServiceIdentityProvider = {
      getServiceToken: async () => "   ",
    };
    const headers = await buildOutboundHeaders({ ctx, serviceIdentity: provider });
    expect(headers["X-Service-Token"]).toBeUndefined();
  });

  it("attaches X-Service-Token when the provider returns a real token", async () => {
    const provider: ServiceIdentityProvider = {
      getServiceToken: async () => "real-token",
    };
    const headers = await buildOutboundHeaders({ ctx, serviceIdentity: provider });
    expect(headers["X-Service-Token"]).toBe("real-token");
  });
});

// ---------------------------------------------------------------------------
// GAP-8 — whitespace-only audience is rejected at startup
// ---------------------------------------------------------------------------

describe("GAP-8 — createAuthz rejects a whitespace-only audience", () => {
  it("throws ConfigError for audience of spaces", async () => {
    await expect(
      createAuthz({
        authorizationYaml: "rules: []",
        userIssuer: "https://auth.example.test",
        userJwksUri: "https://auth.example.test/jwks",
        serviceIssuer: "https://sso.example.test",
        serviceJwksUri: "https://sso.example.test/jwks",
        roleServiceUrl: "https://roles.example.test",
        audience: "   ",
      }),
    ).rejects.toBeInstanceOf(ConfigError);
  });
});

// ---------------------------------------------------------------------------
// Second pass — graceful shutdown: stop() cancels the proactive token timer
// ---------------------------------------------------------------------------

describe("Lifecycle — createAuthz().stop() cancels the proactive token timer", () => {
  afterEach(() => nock.cleanAll());

  it("calls serviceIdentity.close() on stop so no timer leaks", async () => {
    const sso = "https://sso.example.test";
    const roles = "https://roles.example.test";
    nock(sso)
      .post("/token")
      .reply(200, { access_token: "t", token_type: "bearer", expires_in: 3600 });
    nock(roles).get("/roles").reply(200, {});

    const authz = await createAuthz({
      authorizationYaml: "rules: []",
      userIssuer: "https://auth.example.test",
      userJwksUri: "https://auth.example.test/jwks",
      serviceIssuer: sso,
      serviceJwksUri: `${sso}/jwks`,
      roleServiceUrl: roles,
      audience: "api://aud",
      serviceToken: { tokenUrl: `${sso}/token`, clientId: "id", clientSecret: "secret" },
    });

    // Startup token acquisition arms the proactive-refresh timer.
    expect((authz.serviceIdentity as any)._proactiveTimer).not.toBeNull();
    await authz.stop();
    expect((authz.serviceIdentity as any)._proactiveTimer).toBeNull();
  });
});
