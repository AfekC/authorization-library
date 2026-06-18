import { decideRequest, DecideDeps } from "../src/decision-engine/decide.js";
import { loadAuthorizationConfig } from "../src/rule-config/loader.js";
import { PermissionCache } from "../src/permission-cache/cache.js";
import { Metrics } from "../src/observability/metrics.js";
import { LoggingAuditSink } from "../src/audit/audit.js";

const yaml = `
rules:
  - path: /orders/**
    methods: [GET]
    allowedServices: [billing]
`;

function deps(): DecideDeps {
  return {
    engine: loadAuthorizationConfig(yaml),
    cache: new PermissionCache(),
    metrics: new Metrics(),
    audit: new LoggingAuditSink(),
    validator: {
      validateUserToken: async () => { throw new Error("no user"); },
      validateServiceToken: async () => ({ sub: "billing", token_use: "service", azp: "billing" } as any),
    },
    userAuthEnabled: true,
  };
}

it("denies when no credentials are present", async () => {
  const out = await decideRequest(
    { method: "GET", rawPath: "/orders/7", headers: {} },
    deps(),
  );
  expect(out.kind).toBe("deny");
  if (out.kind === "deny") expect(out.status).toBe(401);
});

it("allows a valid service token against the allow-list", async () => {
  const out = await decideRequest(
    { method: "GET", rawPath: "/orders/7", headers: { "x-service-token": "svc" } },
    deps(),
  );
  expect(out.kind).toBe("allow");
  if (out.kind === "allow") expect(out.ctx.serviceName).toBe("billing");
});
