# Auth Library — Project Context

## Project Structure

```
auth-library/
├── contracts/                  # Shared API contracts (REST, Kafka, config files)
│   └── test-vectors/           # Language-neutral *.vectors.json (the parity spine)
├── libraries/
│   ├── authz-spring-boot/      # Spring Boot library (Java, Maven)
│   │   └── src/test/java/      # JUnit 5 unit tests + SharedVectorsTest
│   └── authz-nestjs/           # NestJS library (TypeScript)
│       └── test/               # Jest unit tests + vectors.spec.ts
├── demo-services/
│   ├── spring-demo/            # Spring Boot demo (uses authz-spring-boot auto-config)
│   ├── nestjs-demo/            # Express host using authz-nestjs createAuthz()
│   └── mock-service/           # Mock: SSO + Auth JWKS, Role Service, Kafka publisher
├── tests/
│   └── e2e/                    # docker-compose stack + cross-language parity runner
├── scripts/                    # mvn.sh / mvn.ps1 — Java build in a JDK-21 Docker image
```

> **Toolchain note:** there is no host JDK in this environment, so the Java build runs in a
> `maven:3-eclipse-temurin-21` Docker image via `scripts/mvn.(sh|ps1)`. Node 22 runs natively.

## Key Design Decisions

- **Config-driven authorization** — `authorization.yaml` per service, no annotations in business code
- **Permission distribution** — Role Service (authoritative) + Kafka (incremental events) + disk cache (fallback)
- **Combined auth** — user JWT AND service token must both pass when both are present
- **Local decisions** — all authorization is in-memory, no remote calls on the request path
- **Global enforcement** — Spring: global filter; NestJS: global guard; no per-route opt-in

## Request Types & Decision Matrix

| authenticationType | User permission check | Service allow-list check | Both required |
|---|---|---|---|
| `USER` | role's permissions vs rule's `permissions` | — | no |
| `SERVICE` | — | `serviceName ∈ allowedServices` | no |
| `USER_AND_SERVICE` | role's permissions vs rule's `permissions` | `serviceName ∈ allowedServices` | yes |

Edge cases (all DENY):
- USER request, rule has no `permissions` (service-only rule)
- SERVICE request, rule has no `allowedServices`
- USER_AND_SERVICE request, rule missing either dimension
- Unknown role → empty permission set (no implicit grants)
- No matching rule found

Permission evaluation: `ANY` = at least one required; `ALL` = every required.

## Rule Matching (wildcard scoring)

Path patterns scored segment-by-segment: **literal=2**, **\*=1**, **\*\*=0**.
Compare left-to-right; tie → more literal segments wins; tie → longer pattern wins.
Tie at end → config rejected at startup (ambiguity error).

`**` is only valid as the final path segment. No-match → DENY.

## Startup Sequence

```
authorization.yaml (fail-fast on config error)
  → Fetch full role state from Role Service (GET /roles → bare role map)
    → Success? → atomic cache replace → write disk cache → subscribe Kafka → READY
    → Failure? → disk cache present & non-empty → READY (seed mode); else FAIL FAST (refuse to start)
  → start periodic reconciler (seed-retry + unconditional full re-fetch)
```

**Seed mode:** If Role Service is unreachable at startup, the disk cache seeds the in-memory cache so the service becomes READY and serves traffic. The reconciler then retries until a full sync succeeds and promotes to normal mode.

**Reconciler:** A periodic loop (default 5s) unconditionally re-fetches the full role map from the Role Service each cycle (the response carries no version), healing any missed/out-of-order Kafka events, and promotes seed→normal once reachable.

## Security

- **No-match → DENY**; unknown role → empty permissions → DENY
- **Global enforcement** — no per-route opt-in possible (Spring: global filter; NestJS: global guard)
- **Context tampering prevention** — `RequestContext` built only from validated token claims; inbound `X-User-*`, `X-Role`, `X-*` identity headers stripped/ignored
- **Service spoofing prevention** — service tokens verified against SSO JWKS; `X-Service-Token` never trusted as-is; service tokens must carry `token_use: service`
- **User JWT checks** — signature (Auth Service JWKS), issuer, **audience**, expiry, `alg:none` rejected
- **Performance** — every decision is memory-only: no DB, no remote call, JWKS keys and tokens cached, Kafka off the request path

## Cross-Language Correctness

Both implementations (Spring Boot Java + NestJS TypeScript) must pass the same **language-neutral test vectors** (`contracts/test-vectors/*.vectors.json`, 46 vectors) in CI before release. Each vector = `authorization.yaml` fragment + role cache + request params + expected decision (or `expectCompileError`). Covers: wildcard precedence, decision modes, every cell of the decision matrix above, edge cases (no match, unknown role, `*` service, missing dimensions).

Beyond the vectors, `tests/e2e/run.mjs` drives the **same HTTP requests against both demo services** and asserts identical outcomes (decision matrix, live Kafka propagation, outbound propagation, audience rejection) — runtime cross-language parity.

## Observability, Outbound & Resilience (both libraries)

- **Audit** — per-decision event, INFO one-liner + DEBUG structured JSON, including the governing permission of the matched rule; pluggable `AuditSink`.
- **Metrics** — counters (`authz_success_total`, `authz_failure_total`, `authz_permission_denied_total`, `jwt_validation_failures_total` [user JWT], `service_token_failures_total` [service-token inbound validation + outbound acquisition], `role_event_skipped_total`, `role_refresh_failures_total`) + gauges (`permission_cache_version`, `permission_cache_age_seconds`).
- **Health** — cache status/version/age, mode, `roleServiceLastSync`, `kafkaConsumerConnected`.
- **Outbound** — OAuth2 client-credentials service token (cached, reactive refresh within a clock-skew buffer, retry/backoff) + propagation of the user JWT and `X-Correlation-Id`/`X-Request-Id` downstream, **auto-attached** via framework interceptors (Spring `RestClient`/`RestTemplate` customizers; NestJS axios interceptor + `AsyncLocalStorage`). Backed by Spring Security OAuth2 Client + Resilience4j (Java) and `simple-oauth2` + `p-retry` (NestJS).
- **Forced refresh** — a `publish-roles` Kafka topic triggers a full Role Service re-fetch (cache + disk), fail-open.

## Tech Stack

| Component | Language | Framework | Build / Test |
|-----------|----------|-----------|--------------|
| Library (Java) | Java 21 | Spring Boot 3.x (auto-configuration) | Maven (via Docker) + JUnit 5 |
| Library (TS) | TypeScript 5.x | NestJS guard + framework-agnostic core | npm + Jest |
| spring-demo | Java | Spring Boot (auto-config + spring-kafka) | Maven |
| nestjs-demo | TypeScript/JS | Express host using `createAuthz()` | npm / node |
| Mock service | Node.js / Express | HTTP JWKS + Kafka publisher | npm / node |
| Demo client | Node | — | node |
| Kafka (e2e) | Redpanda | docker-compose | — |

## Commands

Java builds run in Docker (no host JDK): `scripts/mvn.sh <module-dir> <args>` (bash) or
`scripts\mvn.ps1 -ModuleDir <module-dir> <args>` (PowerShell).

- `npm test --workspace=authz-nestjs` — NestJS library unit tests (379)
- `scripts/mvn.sh libraries/authz-spring-boot test` — Spring library unit tests (254)
- `node demo-services/mock-service/src/index.js` — start mock (:4000)
- `node demo-services/nestjs-demo/src/main.js` — start NestJS demo (:5001; env `MOCK_URL`, `KAFKA_BROKERS`)
- `scripts/mvn.sh demo-services/spring-demo spring-boot:run` — start Spring demo (:5002)
- `cd tests/e2e && docker compose up --build -d && node run.mjs && docker compose down -v` — full e2e
  (14 matrix scenarios ×2 langs + dual-demo Kafka propagation + outbound propagation + audience checks)

## Coding Conventions

- Follow existing patterns in each library — don't refactor adjacent code
- Write tests first for bug fixes (reproduce → fix → pass)
- Audit events emitted on every decision — always include relevant context
- Immutable data structures for the permission cache (copy-on-replace)

## SPI Interfaces (extensibility points)

`TokenValidator`, `ServiceIdentityProvider`, `RoleResolver`, `PolicyEngine`, `AttributeProvider`, `RoleServiceClient`, `CacheEventHandler`, `AuditSink` — all behind interfaces; swap implementations without touching auth logic.
