import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { AuthorizationEngine, auditPermission } from "../src/decision-engine/engine.js";
import { loadAuthorizationConfig } from "../src/rule-config/loader.js";
import { PermissionCache } from "../src/permission-cache/cache.js";
import { AuthzGuard } from "../src/nest/authz.guard.js";
import { Metrics, METRIC } from "../src/observability/metrics.js";
import { LoggingAuditSink } from "../src/audit/audit.js";
import { CacheBootstrap } from "../src/cache-sync/bootstrap.js";
import { DiskCache } from "../src/cache-sync/disk.js";
import { CacheEventHandler, RoleMap, RoleServiceClient, TokenValidator } from "../src/spi.js";
import { runWithOutboundContext } from "../src/outbound/context-store.js";
import { attachOutboundPropagation } from "../src/outbound/propagation.js";
import { buildRequestContext } from "../src/inbound-auth/context.js";

const silentAudit = new LoggingAuditSink({ info: () => {}, debug: () => {} });

function fakeCtx(headers: Record<string, unknown>, method = "GET", url = "/x"): any {
  const req = { headers, method, url, path: url };
  return { switchToHttp: () => ({ getRequest: () => req }) };
}

describe("audit permission is surfaced from the matched rule (§10.1)", () => {
  const engine = loadAuthorizationConfig(`
rules:
  - path: /orders
    methods: [POST]
    permissions: [WRITE_ORDER, ADMIN]
    decision: ANY
  - path: /internal/reconcile
    methods: [POST]
    allowedServices: [scheduler]
`);

  it("ALLOW carries the rule's required permissions", () => {
    const cache = new PermissionCache({ M: ["WRITE_ORDER"] });
    const r = engine.evaluate(
      { method: "POST", path: "/orders", authType: "USER", role: "M" },
      cache,
    );
    expect(r.decision).toBe("ALLOW");
    expect(auditPermission(r.matchedRule)).toBe("WRITE_ORDER,ADMIN");
  });

  it("service-only rule -> null permission", () => {
    const cache = new PermissionCache();
    const r = engine.evaluate(
      { method: "POST", path: "/internal/reconcile", authType: "SERVICE", serviceName: "scheduler" },
      cache,
    );
    expect(r.decision).toBe("ALLOW");
    expect(auditPermission(r.matchedRule)).toBeNull();
  });

  it("no matching rule -> DENY with null permission", () => {
    const r = engine.evaluate(
      { method: "GET", path: "/nope", authType: "USER", role: "M" },
      new PermissionCache(),
    );
    expect(r.decision).toBe("DENY");
    expect(auditPermission(r.matchedRule)).toBeNull();
  });
});

describe("inbound token-failure metrics are split by token kind (§10.2)", () => {
  const engine = loadAuthorizationConfig(`
rules:
  - path: /x
    methods: [GET]
    permissions: [READ]
`);
  const throwingValidator: TokenValidator = {
    validateUserToken: async () => {
      throw new Error("bad user token");
    },
    validateServiceToken: async () => {
      throw new Error("bad service token");
    },
  };

  it("user JWT failure increments jwt_validation_failures_total only", async () => {
    const metrics = new Metrics();
    const guard = new AuthzGuard({
      engine, cache: new PermissionCache(), validator: throwingValidator,
      audit: silentAudit, metrics,
    });
    await expect(guard.canActivate(fakeCtx({ authorization: "Bearer x" }))).rejects.toThrow();
    expect(metrics.get(METRIC.jwtValidationFailures)).toBe(1);
    expect(metrics.get(METRIC.serviceTokenFailures)).toBe(0);
  });

  it("service-token failure increments service_token_failures_total only", async () => {
    const metrics = new Metrics();
    const guard = new AuthzGuard({
      engine, cache: new PermissionCache(), validator: throwingValidator,
      audit: silentAudit, metrics,
    });
    await expect(guard.canActivate(fakeCtx({ "x-service-token": "y" }))).rejects.toThrow();
    expect(metrics.get(METRIC.serviceTokenFailures)).toBe(1);
    expect(metrics.get(METRIC.jwtValidationFailures)).toBe(0);
  });
});

describe("axios outbound auto-propagation (§9/§12)", () => {
  it("attaches headers only within an authorized request context", async () => {
    const provider = { getServiceToken: async () => "svc-tok" };
    const axiosLike: any = {
      interceptors: { request: { use: (fn: any) => { axiosLike._fn = fn; return 0; } } },
    };
    attachOutboundPropagation(axiosLike, { serviceIdentity: provider });

    // Outside any request context: no propagation headers added.
    const outside = await axiosLike._fn({ headers: {} });
    expect(outside.headers["X-Service-Token"]).toBeUndefined();
    expect(outside.headers["Authorization"]).toBeUndefined();

    const ctx = buildRequestContext({
      user: { userId: "u", roleId: "M" },
      service: null,
      correlationId: "c-1",
      requestId: "r-1",
    });
    await new Promise<void>((resolve, reject) => {
      runWithOutboundContext(ctx, "user-jwt", () => {
        axiosLike
          ._fn({ headers: {} })
          .then((cfg: any) => {
            expect(cfg.headers["Authorization"]).toBe("Bearer user-jwt");
            expect(cfg.headers["X-Service-Token"]).toBe("svc-tok");
            expect(cfg.headers["X-Correlation-Id"]).toBe("c-1");
            expect(cfg.headers["X-Request-Id"]).toBe("r-1");
            resolve();
          })
          .catch(reject);
      });
    });
  });
});

describe("Kafka unreachable at startup is fail-open (§8.4)", () => {
  const okClient = (roles: RoleMap): RoleServiceClient => ({
    fetchSnapshot: async () => roles,
  });

  it("startup still reaches READY when the broker is down", async () => {
    const file = path.join(os.tmpdir(), `kafka-down-${Date.now()}.json`);
    const failingEvents: CacheEventHandler = {
      start: async () => {
        throw new Error("broker down");
      },
      stop: async () => {},
    };
    const cache = new PermissionCache();
    const boot = new CacheBootstrap(
      cache,
      okClient({ VIEWER: ["READ_ORDER"] }),
      new DiskCache(file),
      failingEvents,
    );
    const res = await boot.start();
    expect(res.mode).toBe("normal");
    expect(boot.isKafkaConnected()).toBe(false);
    expect(cache.permissionsForRole("VIEWER").has("READ_ORDER")).toBe(true);
    fs.unlinkSync(file);
  });
});
