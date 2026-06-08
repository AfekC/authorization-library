# nestjs-demo — using `authz-nestjs`

This demo shows the **simplest possible** adoption of the library. The entire
integration is three steps in [`src/main.js`](src/main.js):

```js
const { createAuthz } = require("authz-nestjs");

// 1. One call wires everything: compiles authorization.yaml (fail-fast),
//    validates JWTs against JWKS, runs the startup state machine
//    (Role Service snapshot -> disk-seed fallback -> Kafka subscribe),
//    and emits an audit event per decision.
const authz = await createAuthz({
  authorizationYamlPath: "./authorization.yaml",
  userIssuer, userJwksUri,            // Auth Service (user JWTs)
  serviceIssuer, serviceJwksUri,      // SSO/OIDC (service tokens)
  audience,
  roleServiceUrl,                     // authoritative Role Service
  kafkaBrokers,                       // optional: live incremental role events
  reconcileIntervalMs: 5000,          // optional: reconciler cadence (default 5000)
  serviceToken: {                     // optional: enables authz.serviceIdentity
    tokenUrl, clientId, clientSecret, // outbound OAuth2 client-credentials
  },
});

// 2. Register the middleware globally — every route is now enforced.
app.use(authz.middleware);

// 3. Write business routes with NO authorization code.
app.get("/orders/:id", (req, res) => res.json({ by: req.authz.userId }));
```

That's the whole integration. Authorization rules live entirely in
[`authorization.yaml`](authorization.yaml) — no annotations, no per-route checks.
On startup `createAuthz` also subscribes to Kafka and starts the reconciler.
A message on the `publish-roles` topic forces a full re-fetch from the Role Service.

## What you get

- `req.authz` — the validated `RequestContext` (identity from token claims only;
  spoofed `X-User-*` / `X-Role` headers are stripped).
- `req.authzUserJwt` — the raw user JWT (set on ALLOW), for outbound propagation.
- `authz.health()` — cache status, version, age, mode, `roleServiceLastSync`,
  `kafkaConsumerConnected`.
- `authz.serviceIdentity` — the outbound token provider (present when `serviceToken` is set).
- `authz.attachOutbound(axiosInstance)` — register **automatic** outbound propagation on an
  axios instance (requires `serviceToken`); see below.
- `authz.engine` / `authz.cache` / `authz.metrics` / `authz.stop()` — for advanced use.

## Outbound propagation

Two ways, both attaching this service's own client-credentials token, the user JWT, and the
correlation/request ids so the downstream Spring service sees a combined `USER_AND_SERVICE`
request:

- **Automatic (axios):** `authz.attachOutbound(axios)` registers a request interceptor; any
  call made while handling an authorized request is propagated with no per-call code. The
  inbound context is carried via `AsyncLocalStorage` (the Express middleware / `AuthzGuard` +
  `AuthzOutboundInterceptor` establish it). This is the library behaviour described in the
  architecture (§9/§12).
- **Manual (any client):** `buildOutboundHeaders({ ctx, userJwt, serviceIdentity })` returns the
  header map to merge yourself. `POST /orders/:id/forward` in this demo uses the manual helper
  with `fetch` (`req.authzUserJwt` + `authz.serviceIdentity`).

The e2e (`tests/e2e/run.mjs`) asserts the service token, user JWT, and correlation id arrive intact.

## Run

```
# from the repo root, with the mock service running on :4000
PORT=5001 MOCK_URL=http://localhost:4000 node demo-services/nestjs-demo/src/main.js
```

Or use the full stack in [`tests/e2e`](../../tests/e2e).
