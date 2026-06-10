/**
 * End-to-end cross-language parity test.
 * Drives the same request scenarios against the NestJS demo (:5001) and the
 * Spring demo (:5002) and asserts identical HTTP outcomes — proving both
 * library implementations agree on real requests, not just unit vectors.
 *
 * Output policy: stay quiet on success. Each check is recorded; only FAILED
 * checks print a line as they happen, and a grouped summary prints at the end.
 */
const MOCK = process.env.MOCK_URL || "http://localhost:4000";
const NEST = process.env.NEST_URL || "http://localhost:5001";
const SPRING = process.env.SPRING_URL || "http://localhost:5002";

// --- result collection ----------------------------------------------------
// Every assertion in the suite funnels through record(); failures print inline,
// passes stay silent, and report() prints a per-section + grand-total summary.
const results = [];
const sectionOrder = [];

function record(section, name, ok, detail = "") {
  if (!sectionOrder.includes(section)) sectionOrder.push(section);
  results.push({ section, name, ok, detail });
  if (!ok) {
    console.log(`  FAIL  [${section}] ${name}${detail ? `  — ${detail}` : ""}`);
  }
}

function report() {
  const total = results.length;
  const failed = results.filter((r) => !r.ok).length;
  const passed = total - failed;

  console.log(`\n${"=".repeat(60)}`);
  console.log("e2e summary");
  console.log("-".repeat(60));
  for (const section of sectionOrder) {
    const rs = results.filter((r) => r.section === section);
    const f = rs.filter((r) => !r.ok).length;
    const status = f ? "FAIL" : " ok ";
    console.log(`  ${status}  ${section.padEnd(42)} ${rs.length - f}/${rs.length}`);
  }
  console.log("-".repeat(60));
  console.log(`  ${failed ? "FAIL" : "PASS"}  ${`total checks passed`.padEnd(42)} ${passed}/${total}`);
  console.log("=".repeat(60));
  return failed;
}

async function login(role, aud) {
  const r = await fetch(`${MOCK}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ userId: `u-${role}`, roleId: role, aud }),
  });
  return (await r.json()).access_token;
}

async function serviceToken(clientId, clientSecret) {
  const body = new URLSearchParams({ grant_type: "client_credentials", client_id: clientId, client_secret: clientSecret });
  const r = await fetch(`${MOCK}/sso/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  return (await r.json()).access_token;
}

async function call(base, { method, path, bearer, service, extraHeaders }) {
  const headers = { ...(extraHeaders || {}) };
  if (bearer) headers["Authorization"] = `Bearer ${bearer}`;
  if (service) headers["X-Service-Token"] = service;
  const r = await fetch(`${base}${path}`, { method, headers });
  return r.status;
}

async function waitFor(url, attempts = 90) {
  // "up" = any HTTP response below 500 (401/403 still mean the app is serving).
  for (let i = 0; i < attempts; i++) {
    try {
      const r = await fetch(url);
      if (r.status < 500) return true;
    } catch {}
    await new Promise((res) => setTimeout(res, 1000));
  }
  throw new Error(`timeout waiting for ${url}`);
}

async function main() {
  console.log("waiting for services...");
  await waitFor(`${MOCK}/health`);
  await waitFor(`${NEST}/health`);
  await waitFor(`${SPRING}/orders/1`); // spring has no /health; 401 means it's up

  const mgr = await login("MANAGER");
  const viewer = await login("VIEWER");
  const auditor = await login("AUDITOR");
  const scheduler = await serviceToken("scheduler-id", "scheduler-secret");

  const scenarios = [
    { name: "MANAGER GET /orders/7", req: { method: "GET", path: "/orders/7", bearer: mgr }, expect: 200 },
    { name: "VIEWER GET /orders/7", req: { method: "GET", path: "/orders/7", bearer: viewer }, expect: 200 },
    { name: "VIEWER POST /orders (deny)", req: { method: "POST", path: "/orders", bearer: viewer }, expect: 403 },
    { name: "MANAGER POST /orders", req: { method: "POST", path: "/orders", bearer: mgr }, expect: 200 },
    { name: "AUDITOR GET /orders/7/audit (ALL)", req: { method: "GET", path: "/orders/7/audit", bearer: auditor }, expect: 200 },
    { name: "VIEWER GET /orders/7/audit (deny ALL)", req: { method: "GET", path: "/orders/7/audit", bearer: viewer }, expect: 403 },
    { name: "scheduler POST /internal/reconcile", req: { method: "POST", path: "/internal/reconcile", service: scheduler }, expect: 200 },
    { name: "COMBINED MANAGER+scheduler POST /orders/7 (both pass)", req: { method: "POST", path: "/orders/7", bearer: mgr, service: scheduler }, expect: 200 },
    { name: "COMBINED VIEWER+scheduler POST /orders/7 (user fails)", req: { method: "POST", path: "/orders/7", bearer: viewer, service: scheduler }, expect: 403 },
    { name: "MANAGER POST /internal/reconcile (deny user on svc rule)", req: { method: "POST", path: "/internal/reconcile", bearer: mgr }, expect: 403 },
    { name: "no creds GET /orders/7", req: { method: "GET", path: "/orders/7" }, expect: 401 },
    { name: "tamper X-Role ignored", req: { method: "POST", path: "/orders", bearer: viewer, extraHeaders: { "X-Role": "ADMIN" } }, expect: 403 },
    { name: "VIEWER POST /orders/:id/forward (deny)", req: { method: "POST", path: "/orders/7/forward", bearer: viewer }, expect: 403 },
    { name: "no matching route", req: { method: "GET", path: "/customers/1", bearer: mgr }, expect: 403 },
  ];

  for (const s of scenarios) {
    const nest = await call(NEST, s.req);
    const spring = await call(SPRING, s.req);
    // POST /orders returns 201 on nest demo but 200 on spring; normalise 2xx.
    const norm = (c) => (c >= 200 && c < 300 ? (Math.floor(s.expect / 100) === 2 ? s.expect : c) : c);
    const okNorm = norm(nest) === s.expect && norm(spring) === s.expect;
    record("decision matrix", s.name, okNorm, `expect=${s.expect} nest=${nest} spring=${spring}`);
  }

  // --- Live Kafka propagation: BOTH demos consume role-updates events ---
  const beforeNest = await call(NEST, { method: "POST", path: "/orders", bearer: viewer });
  const beforeSpring = await call(SPRING, { method: "POST", path: "/orders", bearer: viewer });
  await fetch(`${MOCK}/admin/role-event`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ operation: "UPSERT_ROLE", roleId: "VIEWER", permissions: ["READ_ORDER", "WRITE_ORDER"] }),
  });
  const ok2xx = (c) => c >= 200 && c < 300;
  let afterNest = 0;
  let afterSpring = 0;
  for (let i = 0; i < 25; i++) {
    await new Promise((r) => setTimeout(r, 1000));
    if (!ok2xx(afterNest)) afterNest = await call(NEST, { method: "POST", path: "/orders", bearer: viewer });
    if (!ok2xx(afterSpring)) afterSpring = await call(SPRING, { method: "POST", path: "/orders", bearer: viewer });
    if (ok2xx(afterNest) && ok2xx(afterSpring)) break;
  }
  record("kafka propagation", "nestjs consumes role-update", beforeNest === 403 && ok2xx(afterNest), `before=${beforeNest} after=${afterNest} (expect 403→2xx)`);
  record("kafka propagation", "spring consumes role-update", beforeSpring === 403 && ok2xx(afterSpring), `before=${beforeSpring} after=${afterSpring} (expect 403→2xx)`);
  // Restore VIEWER to original perms for idempotency.
  await fetch(`${MOCK}/admin/role-event`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ operation: "UPSERT_ROLE", roleId: "VIEWER", permissions: ["READ_ORDER"] }),
  });

  // --- Forced refresh: publish-roles triggers a full re-fetch on BOTH demos ---
  // Establish a deterministic baseline independent of prior tests: silently set
  // VIEWER to READ_ORDER only, force a refresh, and wait until BOTH demos converge
  // to 403 for POST /orders (prior tests may have left the cache stale-high).
  await fetch(`${MOCK}/admin/roles`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ roles: { VIEWER: ["READ_ORDER"] } }),
  });
  await fetch(`${MOCK}/admin/publish-roles`, { method: "POST" });
  let beforeNestR = 0;
  let beforeSpringR = 0;
  for (let i = 0; i < 25; i++) {
    await new Promise((r) => setTimeout(r, 1000));
    beforeNestR = await call(NEST, { method: "POST", path: "/orders", bearer: viewer });
    beforeSpringR = await call(SPRING, { method: "POST", path: "/orders", bearer: viewer });
    if (beforeNestR === 403 && beforeSpringR === 403) break;
  }
  // Silently grant VIEWER WRITE_ORDER in the Role Service — NO role-updates event,
  // so only a forced re-fetch (publish-roles) can make the demos observe it.
  await fetch(`${MOCK}/admin/roles`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ roles: { VIEWER: ["READ_ORDER", "WRITE_ORDER"] } }),
  });
  await fetch(`${MOCK}/admin/publish-roles`, { method: "POST" });
  let afterNestR = 0;
  let afterSpringR = 0;
  for (let i = 0; i < 25; i++) {
    await new Promise((r) => setTimeout(r, 1000));
    if (!ok2xx(afterNestR)) afterNestR = await call(NEST, { method: "POST", path: "/orders", bearer: viewer });
    if (!ok2xx(afterSpringR)) afterSpringR = await call(SPRING, { method: "POST", path: "/orders", bearer: viewer });
    if (ok2xx(afterNestR) && ok2xx(afterSpringR)) break;
  }
  record("forced refresh", "nestjs re-fetches on publish-roles", beforeNestR === 403 && ok2xx(afterNestR), `before=${beforeNestR} after=${afterNestR} (expect 403→2xx)`);
  record("forced refresh", "spring re-fetches on publish-roles", beforeSpringR === 403 && ok2xx(afterSpringR), `before=${beforeSpringR} after=${afterSpringR} (expect 403→2xx)`);
  // Restore VIEWER to original perms for idempotency.
  await fetch(`${MOCK}/admin/roles`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ roles: { VIEWER: ["READ_ORDER"] } }),
  });
  await fetch(`${MOCK}/admin/publish-roles`, { method: "POST" });

  // --- Outbound propagation: nestjs-demo forwards a user call to spring-demo ---
  const fwdResp = await fetch(`${NEST}/orders/7/forward`, {
    method: "POST",
    headers: { Authorization: `Bearer ${mgr}`, "X-Correlation-Id": "corr-e2e-fwd" },
  });
  const fwd = await fwdResp.json().catch(() => ({}));
  const checks = {
    "forward succeeded (2xx)": fwdResp.status >= 200 && fwdResp.status < 300,
    "downstream accepted (2xx)": fwd.downstreamStatus >= 200 && fwd.downstreamStatus < 300,
    "service token attached": fwd.sentHeaders?.hasServiceToken === true,
    "user JWT propagated": fwd.sentHeaders?.hasAuthorization === true,
    "downstream saw combined auth": fwd.downstream?.seenAuthType === "USER_AND_SERVICE",
    "downstream saw caller service": fwd.downstream?.seenServiceName === "nestjs-demo",
    "downstream saw forwarded user": fwd.downstream?.seenUserId === "u-MANAGER",
    "correlation id propagated": fwd.downstream?.seenCorrelationId === "corr-e2e-fwd",
  };
  for (const [label, ok] of Object.entries(checks)) {
    record("outbound nestjs→spring", label, ok);
  }
  if (Object.values(checks).some((v) => !v)) {
    console.log("  raw [outbound nestjs→spring]:", JSON.stringify(fwd));
  }

  // --- Audience enforcement (§2.2): wrong-audience token rejected by BOTH ---
  const wrongAud = await login("MANAGER", "wrong-api");
  const audNest = await call(NEST, { method: "GET", path: "/orders/7", bearer: wrongAud });
  const audSpring = await call(SPRING, { method: "GET", path: "/orders/7", bearer: wrongAud });
  record("audience enforcement", "wrong-aud GET /orders/7 → 401", audNest === 401 && audSpring === 401, `nest=${audNest} spring=${audSpring}`);

  // --- G6: Invalid service token scenarios (all must produce 401) ---
  const invalidModes = ["expired", "wrongSignature", "wrongTokenUse", "missingTokenUse", "malformed"];
  for (const mode of invalidModes) {
    const r = await fetch(`${MOCK}/admin/invalid-token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        issuer: "sso",
        mode,
        claims: { service_name: "scheduler", client_id: "scheduler-id" },
      }),
    });
    const { token } = await r.json();
    const nest = await call(NEST, { method: "POST", path: "/internal/reconcile", service: token });
    const spring = await call(SPRING, { method: "POST", path: "/internal/reconcile", service: token });
    record("invalid service token", `${mode} → 401`, nest === 401 && spring === 401, `nest=${nest} spring=${spring}`);
  }
  // Missing X-Service-Token header on a service-only route.
  {
    const nest = await call(NEST, { method: "POST", path: "/internal/reconcile" });
    const spring = await call(SPRING, { method: "POST", path: "/internal/reconcile" });
    record("invalid service token", "missing X-Service-Token header → 401", nest === 401 && spring === 401, `nest=${nest} spring=${spring}`);
  }

  // --- G7: Reverse outbound propagation (spring-demo -> nestjs-demo) ---
  const revResp = await fetch(`${SPRING}/orders/7/forward`, {
    method: "POST",
    headers: { Authorization: `Bearer ${mgr}`, "X-Correlation-Id": "corr-e2e-rev" },
  });
  const rev = await revResp.json().catch(() => ({}));
  const revChecks = {
    "spring forward succeeded (2xx)": revResp.status >= 200 && revResp.status < 300,
    "downstream accepted (2xx)": rev.downstreamStatus >= 200 && rev.downstreamStatus < 300,
    "downstream saw combined auth": rev.downstream?.seenAuthType === "USER_AND_SERVICE",
    "downstream saw caller service": rev.downstream?.seenServiceName === "spring-demo",
    "downstream saw forwarded user": rev.downstream?.seenUserId === "u-MANAGER",
    "correlation id propagated": rev.downstream?.seenCorrelationId === "corr-e2e-rev",
  };
  for (const [label, ok] of Object.entries(revChecks)) {
    record("outbound spring→nestjs", label, ok);
  }
  if (Object.values(revChecks).some((v) => !v)) {
    console.log("  raw [outbound spring→nestjs]:", JSON.stringify(rev));
  }

  const failures = report();
  if (failures) {
    console.error(`\n${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log("\nAll e2e scenarios passed on BOTH implementations (cross-language parity)");
  console.log("plus live Kafka role-update propagation, invalid service token rejection,");
  console.log("and bidirectional outbound propagation.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
