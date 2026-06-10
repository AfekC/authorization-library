/**
 * NestJS demo service.
 *
 * Adopting the library is three steps:
 *   1. call `createAuthz()` with `AUTHZ_*` environment variables set,
 *   2. register the returned middleware globally (`app.use(authz.middleware)`),
 *   3. write your business routes — they carry NO authorization code.
 *
 * `createAuthz` does all the wiring: it compiles authorization.yaml (fail-fast),
 * validates user JWTs and service tokens against their JWKS, runs the startup
 * state machine (Role Service snapshot -> disk-seed fallback -> Kafka subscribe),
 * and emits an audit event per decision.
 *
 * A5: outbound propagation via authz.attachOutbound(axiosInstance) — the library
 * automatically attaches user JWT, service token, and trace headers on every
 * outbound call made from within an authorized request context.
 */
const path = require("path");
const { initObservability } = require("authz-nestjs");

const OTEL_ENV = (process.env.ENV_NAME || process.env.ENVIRONMENT || "drill").toLowerCase();

initObservability({
  enabled: true,
  serviceName: process.env.SERVICE_NAME || "nestjs-demo",
  systemName: process.env.SYSTEM_NAME || process.env.SYSTEM || "auth-library",
  envName: OTEL_ENV,
  otelExporterOtlpEndpoint: process.env.OTEL_EXPORTER_OTLP_ENDPOINT,
});

const express = require("express");
const axios = require("axios");
const { createAuthz } = require("authz-nestjs");

const PORT = process.env.PORT || 5001;
const MOCK = process.env.MOCK_URL || "http://localhost:4000";
const DOWNSTREAM = process.env.DOWNSTREAM_URL || "http://localhost:5002";

/**
 * Seed process.env with AUTHZ_* defaults derived from demo/e2e vars
 * (MOCK_URL, API_AUDIENCE, KAFKA_BROKERS, CLIENT_*). Explicit AUTHZ_* vars win.
 */
function ensureAuthzEnv() {
  const set = (key, value) => { if (!process.env[key]) process.env[key] = value; };
  set("AUTHZ_USER_ISSUER", `${MOCK}/auth`);
  set("AUTHZ_USER_JWKS_URI", `${MOCK}/auth/jwks`);
  set("AUTHZ_SERVICE_ISSUER", `${MOCK}/sso`);
  set("AUTHZ_SERVICE_JWKS_URI", `${MOCK}/sso/jwks`);
  set("AUTHZ_USER_AUDIENCE", process.env.API_AUDIENCE || "orders-api");
  set("AUTHZ_ROLE_SERVICE_URL", MOCK);
  set("AUTHZ_AUTHORIZATION_YAML_PATH", path.join(__dirname, "..", "authorization.yaml"));
  set("AUTHZ_DISK_CACHE_PATH", process.env.AUTHZ_DISK_CACHE_PATH || "/tmp/authorization-cache.json");
  if (process.env.AUTHZ_KAFKA_BROKERS === undefined && process.env.KAFKA_BROKERS !== undefined) {
    process.env.AUTHZ_KAFKA_BROKERS = process.env.KAFKA_BROKERS;
  }
  set("AUTHZ_TOKEN_URL", `${MOCK}/sso/token`);
  set("AUTHZ_CLIENT_ID", process.env.CLIENT_ID || "nestjs-demo-id");
  set("AUTHZ_CLIENT_SECRET", process.env.CLIENT_SECRET || "nestjs-demo-secret");
  set("AUTHZ_OTEL_ENABLED", "true");
  set("AUTHZ_OTEL_SERVICE_NAME", process.env.SERVICE_NAME || "nestjs-demo");
  set("AUTHZ_OTEL_SYSTEM_NAME", process.env.SYSTEM_NAME || process.env.SYSTEM || "auth-library");
  set("AUTHZ_OTEL_ENV_NAME", OTEL_ENV);
  if (process.env.OTEL_EXPORTER_OTLP_ENDPOINT) {
    set("AUTHZ_OTEL_EXPORTER_OTLP_ENDPOINT", process.env.OTEL_EXPORTER_OTLP_ENDPOINT);
  }
}

async function main() {
  ensureAuthzEnv();
  const authz = await createAuthz();

  // A5: Create a dedicated axios instance for downstream forwarding and register
  // the library's outbound propagation interceptor on it. The interceptor
  // automatically attaches the user JWT, service token, and correlation/request
  // ids for every request made through this instance while handling an authorized
  // inbound request — no manual buildOutboundHeaders() needed.
  const downstreamClient = axios.create({ timeout: 5000 });
  authz.attachOutbound(downstreamClient);

  const app = express();
  app.use(express.json());
  app.get("/health", (_req, res) => res.json({ ok: true, ...authz.health() }));

  // Global enforcement — every route below is authorized automatically.
  app.use(authz.middleware);

  // Business routes (no authorization annotations; `req.authz` is the context).
  app.get("/orders/:id", (req, res) => res.json({ id: req.params.id, by: req.authz.userId }));
  app.get("/orders/:id/audit", (req, res) => res.json({ id: req.params.id, audit: true }));
  app.post("/orders", (_req, res) => res.status(201).json({ created: true }));
  app.post("/orders/:id", (req, res) => res.status(201).json({
    id: req.params.id,
    updated: true,
    seenServiceName: req.authz?.serviceName || "none",
    seenAuthType: req.authz?.authenticationType || "none",
    seenCorrelationId: req.authz?.correlationId || "none",
    seenUserId: req.authz?.userId || "none",
  }));
  app.post("/internal/reconcile", (req, res) => res.json({ reconciled: true, by: req.authz.serviceName }));

  // Downstream forwarding: propagate the user's call to spring-demo, attaching
  // this service's token + the user JWT + the correlation id automatically via
  // the outbound interceptor registered above (A5 — proves the interceptor path).
  app.post("/orders/:id/forward", async (req, res) => {
    try {
      // A5: use the axios instance with the attached interceptor — no manual
      // buildOutboundHeaders() needed. The library injects all propagation headers.
      const r = await downstreamClient.post(
        `${DOWNSTREAM}/orders/${req.params.id}`,
        req.body ?? {},
      );
      res.status(r.status).json({
        forwarded: true,
        downstreamStatus: r.status,
        sentHeaders: {
          hasServiceToken: !!(r.config?.headers?.["X-Service-Token"] || r.config?.headers?.["x-service-token"]),
          hasAuthorization: !!(r.config?.headers?.["Authorization"] || r.config?.headers?.["authorization"]),
          correlationId: r.config?.headers?.["X-Correlation-Id"] || r.config?.headers?.["x-correlation-id"],
          requestId: r.config?.headers?.["X-Request-Id"] || r.config?.headers?.["x-request-id"],
        },
        downstream: r.data,
      });
    } catch (error) {
      if (error.response) {
        // Downstream returned an HTTP error — surface the status
        res.status(error.response.status).json({
          forwarded: false,
          downstreamStatus: error.response.status,
          downstream: error.response.data,
        });
      } else {
        res.status(502).json({ error: "downstream service unavailable" });
      }
    }
  });

  app.listen(PORT, () => console.log(`nestjs-demo listening on :${PORT} (mock ${MOCK}, mode=${authz.mode})`));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
