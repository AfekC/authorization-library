# Auth Library — Project Context

## Project Structure

```
auth-library/
├── docs/
│   ├── contracts/              # Shared API contracts (REST, Kafka, config files)
│   │   └── test-vectors/       # Language-neutral *.vectors.json (the parity spine)
│   └── standards/              # Language/framework coding standards
├── libraries/
│   ├── authz-spring-boot/      # Spring Boot library (Java, Maven)
│   │   └── src/test/java/      # JUnit 5 unit tests + SharedVectorsTest
│   └── authz-nestjs/           # NestJS library (TypeScript)
│       └── test/               # Jest unit tests + vectors.spec.ts
└── tests/
    ├── e2e/                    # docker-compose stack + cross-language parity runner
    ├── scripts/                # mvn.sh / mvn.ps1 — Java build in a JDK-21 Docker image
    └── demo-services/
        ├── spring-demo/        # Spring Boot demo (uses authz-spring-boot auto-config)
        ├── nestjs-demo/        # Express host using authz-nestjs createAuthz()
        └── mock-service/       # Mock: SSO + Auth JWKS, Role Service, Kafka publisher
```

> **Toolchain note:** there is no host JDK in this environment, so the Java build runs in a
> `maven:3-eclipse-temurin-21` Docker image via `tests/scripts/mvn.(sh|ps1)`. Node 22 runs natively.

## Key Design Decisions

- **Config-driven authorization** — `authorization.yaml` per service, no annotations in business code
- **Permission distribution** — Role Service (authoritative) + Kafka (incremental events) + disk cache (fallback)
- **Service-only mode (§0.5)** — user JWTs ignored, role machinery off; selected by omitting all user-auth fields, or **explicitly** via NestJS `serviceOnly: true` / Spring `authz.service-only=true` (fail-fast if combined with any user-auth field or external-source flag).
- **External permission source (§0.5b)** — a service may opt out of the built-in distribution and supply role→permissions from its own store (Redis/Infinispan/Postgres) by providing a custom `RoleResolver`. Toggle: NestJS `externalPermissionSource: true` (with `roleResolver`/`policyEngine`); Spring `authz.external-permission-source=true` (with a `Spi.RoleResolver` bean). User-JWT validation stays on; Role Service fetch, reconciler, seed-retry, disk cache, and Kafka role events are all disabled; `roleServiceUrl` is not required. The resolver must serve from an in-memory snapshot the service refreshes itself (no remote call on the request path).
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
  → startSeedRetry (2s/4s/8s backoff until SEED→NORMAL promotion)
  → startReconciler (periodic unconditional full re-fetch, default 5min)
```

**Seed mode:** If Role Service is unreachable at startup, the disk cache seeds the in-memory cache so the service becomes READY and serves traffic. The seed-retry loop retries with exponential backoff (2s, 4s, 8s, 8s…) until a full sync succeeds and promotes to normal mode.

**Reconciler:** A periodic loop (default 5min) unconditionally re-fetches the full role map from the Role Service each cycle (the response carries no version), healing any missed/out-of-order Kafka events. Errors increment `role_refresh_failures_total`.

## Security

- **No-match → DENY**; unknown role → empty permissions → DENY
- **Global enforcement** — no per-route opt-in possible (Spring: global filter; NestJS: global guard)
- **Context tampering prevention** — `RequestContext` built only from validated token claims; inbound `X-User-*`, `X-Role`, `X-*` identity headers stripped/ignored
- **Service spoofing prevention** — service tokens verified against SSO JWKS; `X-Service-Token` never trusted as-is; service tokens must carry `token_use: service`
- **User JWT checks** — signature (Auth Service JWKS), issuer, **audience**, expiry, `alg:none` rejected
- **Performance** — every decision is memory-only: no DB, no remote call, JWKS keys and tokens cached, Kafka off the request path

## Cross-Language Correctness

Both implementations (Spring Boot Java + NestJS TypeScript) must pass the same **language-neutral test vectors** (`docs/contracts/test-vectors/*.vectors.json`, 46 vectors) in CI before release. Each vector = `authorization.yaml` fragment + role cache + request params + expected decision (or `expectCompileError`). Covers: wildcard precedence, decision modes, every cell of the decision matrix above, edge cases (no match, unknown role, `*` service, missing dimensions).

Beyond the vectors, `tests/e2e/run.mjs` drives the **same HTTP requests against both demo services** and asserts identical outcomes (decision matrix, live Kafka propagation, outbound propagation, audience rejection) — runtime cross-language parity.

## Observability, Outbound & Resilience (both libraries)

- **Observability ownership** — the libraries own **no** otel/o11y SDK config; that is a service concern. They expose seams only: a pluggable `AuditSink`, an in-process `Metrics` registry (Spring auto-mirrors to a service-provided Micrometer `MeterRegistry` via optional `micrometer-core`), and a health snapshot. Services configure tracing/metrics/log export themselves.
- **Audit** — per-decision event, INFO one-liner + DEBUG structured JSON, including the governing permission of the matched rule; pluggable `AuditSink`.
- **Metrics** — counters (`authz_success_total`, `authz_failure_total`, `authz_permission_denied_total`, `jwt_validation_failures_total` [user JWT], `service_token_failures_total` [service-token inbound validation + outbound acquisition], `role_event_skipped_total`, `role_refresh_failures_total`, `disk_cache_write_failures_total`) + gauge (`permission_cache_age_seconds`).
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

Java builds run in Docker (no host JDK): `tests/scripts/mvn.sh <module-dir> <args>` (bash) or
`tests\scripts\mvn.ps1 -ModuleDir <module-dir> <args>` (PowerShell).

- `cd libraries/authz-nestjs && npm test` — NestJS library unit tests
- `tests/scripts/mvn.sh libraries/authz-spring-boot test` — Spring library unit tests
- `node tests/demo-services/mock-service/src/index.js` — start mock (:4000)
- `node tests/demo-services/nestjs-demo/src/main.js` — start NestJS demo (:5001; env `MOCK_URL`, `KAFKA_BROKERS`)
- `tests/scripts/mvn.sh tests/demo-services/spring-demo spring-boot:run` — start Spring demo (:5002)
- `cd tests/e2e && docker compose up --build -d && node run.mjs && docker compose down -v` — full e2e
  (14 matrix scenarios ×2 langs + dual-demo Kafka propagation + outbound propagation + audience checks)

## Coding Conventions

- **Standards & best practices** — see [`docs/standards/spring-java-standards.md`](docs/standards/spring-java-standards.md) (Java/Spring Boot) and [`docs/standards/nestjs-standards.md`](docs/standards/nestjs-standards.md) (TypeScript/NestJS). General, code-agnostic language/framework standards (style, types, DI, config, error handling, security, observability, testing).
- Follow existing patterns in each library — don't refactor adjacent code
- Write tests first for bug fixes (reproduce → fix → pass)
- Audit events emitted on every decision — always include relevant context
- Immutable data structures for the permission cache (copy-on-replace)

## SPI Interfaces (extensibility points)

`TokenValidator`, `ServiceIdentityProvider`, `RoleResolver`, `PolicyEngine`, `AttributeProvider`, `RoleServiceClient`, `CacheEventHandler`, `AuditSink` — all behind interfaces; swap implementations without touching auth logic.
