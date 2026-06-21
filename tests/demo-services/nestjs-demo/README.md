# nestjs-demo — using `authz-nestjs`

The simplest possible Express adoption: env-driven bootstrap, global middleware,
zero authorization code in business routes, and automatic outbound propagation
to spring-demo via axios.

## The entire integration

All wiring is in [`src/main.js`](src/main.js):

1. **Bootstrap from environment** — `createAuthz()` reads `AUTHZ_*` variables
   from `process.env`. [`ensureAuthzEnv()`](src/main.js) seeds defaults from
   demo/e2e vars (`MOCK_URL`, `API_AUDIENCE`, `KAFKA_BROKERS`, `CLIENT_ID`,
   `CLIENT_SECRET`); explicit `AUTHZ_*` always wins. Rules live in
   [`authorization.yaml`](authorization.yaml).

2. **Enforce globally** — `app.use(authz.middleware)`; no per-route opt-in.

3. **Outbound propagation** — `authz.attachOutbound(downstreamClient)` registers
   an axios interceptor. `POST /orders/:id/forward` calls spring-demo through
   that client — user JWT, service token, and trace headers are attached with no
   manual header code.

4. **Business routes** — handlers read `req.authz`; authorization logic stays in
   the yaml file only.

The library owns no observability SDK config — that's a service concern, so this
demo wires none. It uses the default `LoggingAuditSink` and the in-process
`Metrics` registry. A real service would initialize its own telemetry SDK and
optionally pass an `auditSink`.

For the full `AUTHZ_*` variable list, `CreateAuthzOptions`, and library API
(`req.authz`, `authz.health()`, SPI overrides, etc.), see
[`authz-nestjs` → Getting Started](../../libraries/authz-nestjs/README.md#getting-started).

## Run

```bash
# from the repo root, with mock-service on :4000
PORT=5001 MOCK_URL=http://localhost:4000 node tests/demo-services/nestjs-demo/src/main.js
```

Or use the full cross-language stack in [`tests/e2e`](../../e2e) — it
drives the same scenarios against both demos and asserts identical outcomes
(including outbound propagation).
