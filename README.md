# Auth Library

Config-driven authorization middleware, implemented twice — **Spring Boot (Java)** and
**NestJS (TypeScript)** — against one shared contract, and proven to behave identically by a
language-neutral vector suite plus a cross-language end-to-end test.

See [`authz-middleware-architecture.md`](authz-middleware-architecture.md) for the full design
and [`contracts/`](contracts/) for the wire/config contracts.

## Layout

```
contracts/                     Shared REST/Kafka/config contracts + test-vectors/
libraries/
  authz-spring-boot/           Java 21 / Spring Boot 3 library (Maven, JUnit 5)
  authz-nestjs/                TypeScript 5 / NestJS library (Jest)
demo-services/
  mock-service/                SSO + Auth JWKS, Role Service snapshot, Kafka publisher
  spring-demo/                 Spring Boot app using authz-spring-boot
  nestjs-demo/                 Express host using authz-nestjs (global enforcement + Kafka sync)
tests/e2e/                     docker-compose stack + cross-language parity runner
scripts/mvn.(sh|ps1)           Run the Java build in a JDK-21 Docker image (no host JDK needed)
```

## The parity spine

`contracts/test-vectors/*.vectors.json` are language-neutral vectors (rules + role cache +
request → expected decision, or `expectCompileError`). Both libraries load the *same* files:

- **NestJS:** `libraries/authz-nestjs/test/vectors.spec.ts`
- **Spring:** `libraries/authz-spring-boot/src/test/java/com/example/authz/SharedVectorsTest.java`

46 vectors cover wildcard precedence, ANY/ALL, every decision-matrix cell, and edge cases.

## Adopting the library (kept deliberately simple)

- **NestJS / Node:** one call — `const authz = await createAuthz({...}); app.use(authz.middleware);`. See [`demo-services/nestjs-demo`](demo-services/nestjs-demo/README.md).
- **Spring Boot:** zero wiring code — add the dependency, an `authorization.yaml`, and `authz.*` properties; auto-configuration registers the global filter. See [`demo-services/spring-demo`](demo-services/spring-demo/README.md).

In both, business routes contain **no** authorization code; rules live entirely in `authorization.yaml`.

## Capabilities (identical in both libraries)

- **Inbound auth** — user JWTs verified against the Auth Service JWKS (signature, issuer,
  audience, expiry); service tokens against the SSO JWKS (signature, issuer, expiry, `token_use`).
- **Decision engine** — wildcard rule matching + the full `USER` / `SERVICE` / `USER_AND_SERVICE`
  decision matrix; no-match → DENY; unknown role → empty permissions.
- **Distribution** — Role Service snapshot at startup, **live Kafka** `UPSERT_ROLE`/`DELETE_ROLE`
  consumption, disk-cache seed fallback, a `publish-roles` forced-refresh topic, and a periodic **reconciler** (seed-retry + unconditional full re-fetch).
- **Outbound** — OAuth2 client-credentials service token (cached, proactive refresh, retry/backoff)
  + propagation of the user JWT and correlation/request ids to downstream services, attached
  **automatically** via framework interceptors (Spring `RestClient`/`RestTemplate` customizers;
  NestJS axios interceptor) — no per-call header building.
- **Security** — global enforcement, identity-header stripping, `alg:none` rejected.
- **Observability** — per-decision audit (INFO + DEBUG, including the governing permission),
  metrics counters/gauges, health snapshot.

## Running the tests

NestJS library (Node 22):
```
npm install
npm test --workspace=authz-nestjs        # 379 tests (46 shared vectors + module/outbound/arch-fix tests)
```

Spring library (no host JDK required — uses Docker):
```
scripts/mvn.sh libraries/authz-spring-boot test      # bash
scripts\mvn.ps1 -ModuleDir libraries/authz-spring-boot test   # PowerShell
# -> 254 tests (46 shared vectors + module/outbound/arch-fix tests)
```

## End-to-end (both demos + mock + Kafka)

```
cd tests/e2e
docker compose up --build -d     # redpanda + mock + nestjs-demo (:5001) + spring-demo (:5002)
node run.mjs                      # full cross-language parity suite
docker compose down -v
```

`run.mjs` asserts, against **both** demos:
- **14 decision-matrix scenarios** (USER / SERVICE / USER_AND_SERVICE, edge cases, tamper, no-match);
- **live Kafka propagation** — a role change flows Role Service → Kafka → each demo's cache;
- **outbound propagation** — nestjs-demo forwards a user call to spring-demo with its own service
  token + the user JWT + correlation id; the downstream sees a combined `USER_AND_SERVICE` request;
- **audience enforcement** — a wrong-audience token is rejected (401) by both.


## Build the Java library on a host with a JDK

The Docker wrapper is only for convenience. With a JDK 21 + Maven installed you can run
`mvn test` directly in `libraries/authz-spring-boot`.

## Using graphify & understand-anything in Claude

Both tools are available as Claude Code skills. Use them inside a Claude session:

```
/graphify          — generate interactive HTML knowledge graph (graphify-out/graph.html)
/understand        — scan codebase and produce structured knowledge graph
/understand-chat   — ask questions about the codebase via the knowledge graph
/understand-explain — deep-dive explanation of a specific file or module
/understand-diff   — analyze what changed in a diff or PR
/understand-domain — extract business domain flow graph
/understand-onboard — generate an onboarding guide for new team members
```

Results persist in `graphify-out/` and `.understand-anything/` and are reused across sessions.

### Q&A


**Q: I made changes and want to see if I broke anything. What do I run?**

`/understand-diff` — it reads the git diff against the main branch and highlights affected components and risks.

**Q: I need to explain how the cache + Kafka event system works to a new teammate.**

`/understand-explain` and point it at the cache/Kafka modules, or run `/understand-onboard` to generate a full onboarding doc.
