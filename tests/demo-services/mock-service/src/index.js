/**
 * mock-service — Express server providing:
 *   Auth Service (user JWTs + JWKS), SSO (service tokens + JWKS),
 *   Role Service, Kafka publisher, and admin control endpoints.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * EXISTING ENDPOINTS (unchanged)
 * ─────────────────────────────────────────────────────────────────────────────
 *   GET  /auth/jwks                — Auth Service JWKS (user JWT verification keys)
 *   GET  /sso/jwks                 — SSO JWKS (service token verification keys)
 *   GET  /.well-known/auth         — Auth Service OpenID discovery fragment
 *   POST /auth/login               — Issue a user JWT  { userId, roleId, aud? }
 *   POST /sso/token                — Issue a service token (client_credentials grant)
 *   GET  /roles                    — Role Service: full role map (503 when toggled down)
 *   POST /admin/role-event         — Publish a role upsert/delete + Kafka event
 *   POST /admin/roles              — Replace role state silently (no Kafka event)
 *   POST /admin/publish-roles      — Fire publish-roles Kafka trigger
 *   POST /admin/role-service/:state — Toggle Role Service reachability (up|down)
 *   GET  /health                   — Service health
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * NEW ENDPOINTS — G13: JWKS Key Rotation
 * ─────────────────────────────────────────────────────────────────────────────
 *   POST /admin/rotate-keys
 *     Body: { issuer: "auth"|"sso" }
 *     Generates a new RSA keypair for the given issuer, publishes old+new in the
 *     JWKS (overlap window for in-flight token validation), and starts signing
 *     new tokens with the new kid.
 *     Default state: keys are NOT rotated (single static keypair per issuer).
 *     Returns: { issuer, newKid, previousKid, jwksKeyCount }
 *
 *   POST /admin/retire-old-keys
 *     Body: { issuer: "auth"|"sso" }
 *     Drops all keys except the current signing key from the JWKS — call this
 *     after the overlap window to simulate full key retirement.
 *     Default state: no-op (only one key present unless rotate-keys was called).
 *     Returns: { issuer, signingKid }
 *
 *   GET  /admin/signing-kid
 *     Query: ?issuer=auth|sso
 *     Returns the kid currently used to sign new tokens for that issuer.
 *     Returns: { issuer, signingKid, jwksKeyCount }
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * NEW ENDPOINTS — G15: Adverse SSO / Token Conditions
 * All faults are OFF by default and must be explicitly enabled via admin endpoints.
 * ─────────────────────────────────────────────────────────────────────────────
 *   POST /admin/sso-fault
 *     Body: { fault: "none"|"slow"|"error"|"expired-token"|"malformed-token" }
 *     Controls what the SSO token endpoint (/sso/token) does on the next request(s):
 *       "none"            — Normal operation (default / resets fault).
 *       "slow"            — Delay the response by `delayMs` milliseconds (default 5000).
 *       "error"           — Return HTTP 503 with error body.
 *       "expired-token"   — Return a structurally valid but already-expired service token.
 *       "malformed-token" — Return the literal string "not.a.jwt" as access_token.
 *     Body also accepts: { delayMs: number } (used when fault="slow", default 5000 ms).
 *     Body also accepts: { sticky: boolean } — if false (default), fault fires once then
 *       auto-resets to "none"; if true, fault persists until explicitly cleared.
 *     Returns: { ok: true, ssoFault }
 *
 *   POST /admin/jwks-fault
 *     Body: { issuer: "auth"|"sso", fault: "none"|"slow"|"error" }
 *     Controls what the JWKS endpoint returns on the next request(s):
 *       "none"  — Normal operation (default / resets fault).
 *       "slow"  — Delay the response by `delayMs` milliseconds (default 5000).
 *       "error" — Return HTTP 503.
 *     Also accepts: { delayMs: number, sticky: boolean } (same semantics as sso-fault).
 *     Returns: { ok: true, issuer, jwksFault }
 *
 *   GET  /admin/fault-status
 *     Returns the current state of all fault injectors:
 *     { ssoFault, jwksFaultAuth, jwksFaultSso }
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * NEW ENDPOINTS — G6: Invalid Service Token Minting
 * ─────────────────────────────────────────────────────────────────────────────
 *   POST /admin/invalid-token
 *     Body: {
 *       issuer:   "auth"|"sso"   (which issuer's key to use; default "sso")
 *       mode:     "expired"|"wrongSignature"|"wrongTokenUse"|"missingTokenUse"|"missingClaims"|"malformed"
 *       claims:   { ... }        (base claims to include; optional)
 *       audience: string         (optional aud claim)
 *     }
 *     Returns a deliberately broken JWT (or "not.a.jwt" for mode=malformed) that
 *     the demo services' inbound validation should reject.
 *     Returns: { token, mode, issuer }
 *
 *     Mode meanings:
 *       "expired"        — iat+exp both in the past, real signature (timing wrong only)
 *       "wrongSignature" — signed with a throwaway key not in the JWKS
 *       "wrongTokenUse"  — valid token but token_use = "INVALID_USE"
 *       "missingTokenUse" — correctly signed, non-expired token, no token_use claim
 *       "missingClaims"  — no iss/aud/exp; bogus signature (structurally a JWT)
 *       "malformed"      — literal string "not.a.jwt" (not even a JWT)
 */

const express = require("express");
const { createIssuer } = require("./keys");

const PORT = process.env.PORT || 4000;
const AUTH_ISSUER = process.env.AUTH_ISSUER || `http://localhost:${PORT}/auth`;
const SSO_ISSUER = process.env.SSO_ISSUER || `http://localhost:${PORT}/sso`;
const AUDIENCE = process.env.API_AUDIENCE || "orders-api";
const KAFKA_BROKERS = (process.env.KAFKA_BROKERS || "").split(",").filter(Boolean);
const ROLE_UPDATES_TOPIC = process.env.ROLE_UPDATES_TOPIC || "role-updates";
const ROLE_DELETE_TOPIC = process.env.ROLE_DELETE_TOPIC || "role-delete";
const PUBLISH_ROLES_TOPIC = process.env.PUBLISH_ROLES_TOPIC || "publish-roles";

// In-memory authoritative role state (mutable via /admin endpoints).
let roleState = {
  roles: {
    MANAGER: ["READ_ORDER", "WRITE_ORDER", "DELETE_ORDER"],
    VIEWER: ["READ_ORDER"],
    AUDITOR: ["READ_ORDER", "ADMIN"],
  },
};

// Known service clients for client-credentials.
const SERVICE_CLIENTS = {
  "scheduler-id": { secret: "scheduler-secret", serviceName: "scheduler" },
  "batch-id": { secret: "batch-secret", serviceName: "batch" },
  // Identities for the demos when they forward calls downstream.
  "nestjs-demo-id": { secret: "nestjs-demo-secret", serviceName: "nestjs-demo" },
  "spring-demo-id": { secret: "spring-demo-secret", serviceName: "spring-demo" },
};

let roleServiceReachable = true; // toggle for failover testing

// ─── Fault injection state (G15) ─────────────────────────────────────────────
// All faults default to "none" (off). They can be made "sticky" (persist across
// requests) or single-shot (auto-reset after one triggered response).

/** @type {{ fault: string, delayMs: number, sticky: boolean }} */
let ssoFault = { fault: "none", delayMs: 5000, sticky: false };

/** @type {Map<string, { fault: string, delayMs: number, sticky: boolean }>} */
const jwksFaults = new Map([
  ["auth", { fault: "none", delayMs: 5000, sticky: false }],
  ["sso", { fault: "none", delayMs: 5000, sticky: false }],
]);

/** Apply a delay (for "slow" fault). Returns a Promise that resolves after ms. */
function _delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Process a fault state for one request.
 * Returns { handled: true } if the response was already sent (error/slow+error),
 * or { handled: false } if normal processing should continue.
 * Resets the fault to "none" if not sticky.
 */
async function _applyFault(faultState, res) {
  const { fault, delayMs, sticky } = faultState;

  if (fault === "none") return { handled: false };

  // Auto-reset single-shot faults before we act (so concurrent requests don't
  // accidentally double-trigger, and we can still read the original fault value).
  if (!sticky) {
    faultState.fault = "none";
  }

  if (fault === "slow") {
    await _delay(delayMs);
    return { handled: false }; // continue with normal response, just slow
  }

  if (fault === "error") {
    res.status(503).json({ error: "service_unavailable", message: "Fault injected" });
    return { handled: true };
  }

  return { handled: false };
}

async function main() {
  const auth = await createIssuer(AUTH_ISSUER, "auth-key-1");
  const sso = await createIssuer(SSO_ISSUER, "sso-key-1");

  // Helper: resolve "auth"|"sso" string to the issuer object.
  function _issuerFor(name) {
    if (name === "auth") return auth;
    if (name === "sso") return sso;
    return null;
  }

  let producer = null;
  if (KAFKA_BROKERS.length) {
    const { Kafka } = require("kafkajs");
    const kafka = new Kafka({ clientId: "mock-service", brokers: KAFKA_BROKERS });
    producer = kafka.producer();
    await producer.connect().catch((e) => {
      console.error("Kafka connect failed (continuing without):", e.message);
      producer = null;
    });
  }

  const app = express();
  app.use(express.json({ limit: "256kb" }));
  app.use(express.urlencoded({ extended: true }));

  // ── JWKS endpoints (with G15 fault injection) ──────────────────────────────

  app.get("/auth/jwks", async (req, res) => {
    const f = jwksFaults.get("auth");
    const { handled } = await _applyFault(f, res);
    if (!handled) res.json(auth.jwks);
  });

  app.get("/sso/jwks", async (req, res) => {
    const f = jwksFaults.get("sso");
    const { handled } = await _applyFault(f, res);
    if (!handled) res.json(sso.jwks);
  });

  app.get("/.well-known/auth", (_req, res) =>
    res.json({ issuer: AUTH_ISSUER, jwks_uri: `${AUTH_ISSUER}/jwks` }),
  );

  // ── Auth Service: issue a user JWT ─────────────────────────────────────────

  app.post("/auth/login", async (req, res) => {
    const body = req.body || {};
    // Identity claims are userId/roleId (sub/role accepted as legacy aliases).
    const userId = body.userId ?? body.sub;
    const roleId = body.roleId ?? body.role;
    const aud = body.aud;
    if (!userId || !roleId) return res.status(400).json({ error: "userId and roleId required" });
    const token = await auth.sign(
      { userId, roleId },
      { audience: aud || AUDIENCE }, // aud override enables audience-rejection tests
    );
    res.json({ access_token: token, token_type: "Bearer" });
  });

  // ── SSO: client-credentials service token (with G15 fault injection) ───────

  app.post("/sso/token", async (req, res) => {
    // Apply fault BEFORE authentication so the test can also exercise pre-auth errors.
    const { fault, delayMs, sticky } = ssoFault;

    if (fault === "slow") {
      if (!sticky) ssoFault.fault = "none";
      await _delay(delayMs);
      // Fall through to normal processing after delay.
    } else if (fault === "error") {
      if (!sticky) ssoFault.fault = "none";
      return res.status(503).json({ error: "service_unavailable", message: "Fault injected" });
    } else if (fault === "expired-token" || fault === "malformed-token") {
      // Still validate the client first so the fault is realistic.
      const clientId = req.body.client_id;
      const clientSecret = req.body.client_secret;
      const client = SERVICE_CLIENTS[clientId];
      if (!client || client.secret !== clientSecret) {
        if (!sticky) ssoFault.fault = "none";
        return res.status(401).json({ error: "invalid_client" });
      }

      let badToken;
      if (fault === "malformed-token") {
        badToken = await sso.signInvalid({}, { mode: "malformed" });
      } else {
        badToken = await sso.signInvalid(
          { token_use: "service", service_name: client.serviceName, client_id: clientId },
          { mode: "expired" },
        );
      }
      if (!sticky) ssoFault.fault = "none";
      return res.json({ access_token: badToken, token_type: "Bearer", expires_in: 600 });
    }

    // Normal path.
    const grant = req.body.grant_type;
    const clientId = req.body.client_id;
    const clientSecret = req.body.client_secret;
    if (grant !== "client_credentials") {
      return res.status(400).json({ error: "unsupported_grant_type" });
    }
    const client = SERVICE_CLIENTS[clientId];
    if (!client || client.secret !== clientSecret) {
      return res.status(401).json({ error: "invalid_client" });
    }
    const token = await sso.sign(
      { token_use: "service", service_name: client.serviceName, client_id: clientId, azp: client.serviceName },
      { expiresIn: "10m" },
    );
    res.json({ access_token: token, token_type: "Bearer", expires_in: 600 });
  });

  // ── Role Service: authoritative full state ─────────────────────────────────

  app.get("/roles", (_req, res) => {
    if (!roleServiceReachable) {
      return res.status(503).json({ error: "service_unavailable", message: "Role Service unreachable" });
    }
    res.json(roleState.roles);
  });

  // ── Admin: publish a role change (updates state + emits Kafka event) ───────
  // The wire event carries only roleId (+ permissions); the operation is conveyed
  // by the topic: role-updates for upserts, role-delete for deletes.
  app.post("/admin/role-event", async (req, res) => {
    const { operation, roleId, permissions } = req.body || {};
    let topic, message;
    if (operation === "UPSERT_ROLE") {
      roleState.roles[roleId] = permissions;
      topic = ROLE_UPDATES_TOPIC;
      message = { roleId, permissions };
    } else if (operation === "DELETE_ROLE") {
      delete roleState.roles[roleId];
      topic = ROLE_DELETE_TOPIC;
      message = { roleId };
    } else {
      return res.status(400).json({ error: "unknown operation" });
    }
    if (producer) {
      await producer.send({ topic, messages: [{ value: JSON.stringify(message) }] });
    }
    res.json({ ok: true, kafka: !!producer });
  });

  // ── Admin: replace role state WITHOUT emitting any Kafka event ─────────────
  // Lets a test change the authoritative state invisibly to the incremental
  // (role-updates/role-delete) path, so a forced refresh can be proven in isolation.
  app.post("/admin/roles", (req, res) => {
    const { roles } = req.body || {};
    if (!roles || typeof roles !== "object") {
      return res.status(400).json({ error: "roles object required" });
    }
    roleState.roles = { ...roleState.roles, ...roles };
    res.json({ ok: true, roles: roleState.roles });
  });

  // ── Admin: fire a forced-refresh trigger on the publish-roles topic ─────────
  app.post("/admin/publish-roles", async (req, res) => {
    if (producer) {
      await producer.send({
        topic: PUBLISH_ROLES_TOPIC,
        messages: [{ value: JSON.stringify({ trigger: Date.now() }) }],
      });
    }
    res.json({ ok: true, kafka: !!producer });
  });

  // ── Admin: toggle Role Service reachability (failover testing) ─────────────
  app.post("/admin/role-service/:state", (req, res) => {
    roleServiceReachable = req.params.state === "up";
    res.json({ roleServiceReachable });
  });

  // ── G13: JWKS Key Rotation endpoints ───────────────────────────────────────

  /**
   * POST /admin/rotate-keys
   * Body: { issuer: "auth"|"sso" }
   * Generates a new RSA keypair, adds it to the JWKS (overlap window), and
   * switches the signing kid to the new key. The old key remains in the JWKS
   * so tokens signed before rotation continue to validate during the window.
   * Call /admin/retire-old-keys after the window to drop the old key.
   */
  app.post("/admin/rotate-keys", async (req, res) => {
    const { issuer: issuerName } = req.body || {};
    const issuer = _issuerFor(issuerName);
    if (!issuer) {
      return res.status(400).json({ error: 'issuer must be "auth" or "sso"' });
    }
    const previousKid = issuer.signingKid;
    const newKid = await issuer.rotate();
    res.json({
      ok: true,
      issuer: issuerName,
      previousKid,
      newKid,
      jwksKeyCount: issuer.jwks.keys.length,
    });
  });

  /**
   * POST /admin/retire-old-keys
   * Body: { issuer: "auth"|"sso" }
   * Drops all keys from the JWKS except the current signing key.
   * Call this after the overlap window has elapsed.
   */
  app.post("/admin/retire-old-keys", (req, res) => {
    const { issuer: issuerName } = req.body || {};
    const issuer = _issuerFor(issuerName);
    if (!issuer) {
      return res.status(400).json({ error: 'issuer must be "auth" or "sso"' });
    }
    issuer.retireOldKeys();
    res.json({
      ok: true,
      issuer: issuerName,
      signingKid: issuer.signingKid,
      jwksKeyCount: issuer.jwks.keys.length,
    });
  });

  /**
   * GET /admin/signing-kid?issuer=auth|sso
   * Returns the kid currently used to sign new tokens for that issuer.
   */
  app.get("/admin/signing-kid", (req, res) => {
    const issuerName = req.query.issuer;
    const issuer = _issuerFor(issuerName);
    if (!issuer) {
      return res.status(400).json({ error: 'issuer query param must be "auth" or "sso"' });
    }
    res.json({
      issuer: issuerName,
      signingKid: issuer.signingKid,
      jwksKeyCount: issuer.jwks.keys.length,
    });
  });

  // ── G15: Adverse SSO / JWKS condition control ──────────────────────────────

  /**
   * POST /admin/sso-fault
   * Body: {
   *   fault: "none"|"slow"|"error"|"expired-token"|"malformed-token",
   *   delayMs?: number,   (used when fault="slow"; default 5000)
   *   sticky?: boolean,   (default false — single-shot; true = persist until cleared)
   * }
   * Controls what /sso/token returns. All faults default to OFF ("none").
   */
  app.post("/admin/sso-fault", (req, res) => {
    const { fault = "none", delayMs = 5000, sticky = false } = req.body || {};
    const allowed = ["none", "slow", "error", "expired-token", "malformed-token"];
    if (!allowed.includes(fault)) {
      return res.status(400).json({ error: `fault must be one of: ${allowed.join(", ")}` });
    }
    ssoFault = { fault, delayMs, sticky };
    res.json({ ok: true, ssoFault });
  });

  /**
   * POST /admin/jwks-fault
   * Body: {
   *   issuer: "auth"|"sso",
   *   fault: "none"|"slow"|"error",
   *   delayMs?: number,   (default 5000)
   *   sticky?: boolean,   (default false)
   * }
   * Controls what /auth/jwks or /sso/jwks returns. All faults default to OFF.
   */
  app.post("/admin/jwks-fault", (req, res) => {
    const { issuer: issuerName, fault = "none", delayMs = 5000, sticky = false } = req.body || {};
    if (!["auth", "sso"].includes(issuerName)) {
      return res.status(400).json({ error: 'issuer must be "auth" or "sso"' });
    }
    const allowed = ["none", "slow", "error"];
    if (!allowed.includes(fault)) {
      return res.status(400).json({ error: `fault must be one of: ${allowed.join(", ")}` });
    }
    jwksFaults.set(issuerName, { fault, delayMs, sticky });
    res.json({ ok: true, issuer: issuerName, jwksFault: jwksFaults.get(issuerName) });
  });

  /**
   * GET /admin/fault-status
   * Returns the current state of all fault injectors.
   */
  app.get("/admin/fault-status", (_req, res) => {
    res.json({
      ssoFault,
      jwksFaultAuth: jwksFaults.get("auth"),
      jwksFaultSso: jwksFaults.get("sso"),
    });
  });

  // ── G6: Invalid / adversarial service token minting ───────────────────────

  /**
   * POST /admin/invalid-token
   * Body: {
   *   issuer:   "auth"|"sso"  (default "sso")
   *   mode:     "expired"|"wrongSignature"|"wrongTokenUse"|"missingClaims"|"malformed"
   *   claims:   { ... }       (base payload claims; optional)
   *   audience: string        (optional aud claim)
   * }
   * Returns a deliberately broken token for use in inbound-validation e2e tests.
   */
  app.post("/admin/invalid-token", async (req, res) => {
    const {
      issuer: issuerName = "sso",
      mode = "expired",
      claims = {},
      audience,
    } = req.body || {};
    const issuer = _issuerFor(issuerName);
    if (!issuer) {
      return res.status(400).json({ error: 'issuer must be "auth" or "sso"' });
    }
    const validModes = ["expired", "wrongSignature", "wrongTokenUse", "missingTokenUse", "missingClaims", "malformed"];
    if (!validModes.includes(mode)) {
      return res.status(400).json({ error: `mode must be one of: ${validModes.join(", ")}` });
    }
    try {
      const token = await issuer.signInvalid(claims, { mode, audience });
      res.json({ ok: true, token, mode, issuer: issuerName });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── Health ─────────────────────────────────────────────────────────────────

  app.get("/health", (_req, res) =>
    res.json({
      ok: true,
      kafka: !!producer,
      authSigningKid: auth.signingKid,
      ssoSigningKid: sso.signingKid,
      ssoFault: ssoFault.fault,
      jwksFaultAuth: jwksFaults.get("auth").fault,
      jwksFaultSso: jwksFaults.get("sso").fault,
    }),
  );

  app.listen(PORT, () => {
    console.log(`mock-service listening on :${PORT}`);
    console.log(`  auth issuer:  ${AUTH_ISSUER} (jwks ${AUTH_ISSUER}/jwks)`);
    console.log(`  sso  issuer:  ${SSO_ISSUER} (jwks ${SSO_ISSUER}/jwks)`);
    console.log(`  kafka:        ${producer ? KAFKA_BROKERS.join(",") : "disabled"}`);
  });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
