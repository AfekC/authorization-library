# TypeScript & NestJS — Standards & Best Practices

General coding standards and best practices for TypeScript 5.x and NestJS 10+.
These are framework- and project-agnostic guidelines; apply them to any module.

---

## Part 1 — TypeScript Language Standards

### Compiler & tooling
- Enable **`strict` mode** (and `noImplicitAny`, `strictNullChecks`, `noUncheckedIndexedAccess`, `noImplicitReturns`). Treat type errors as build failures.
- Lint with ESLint (`@typescript-eslint`) and format with Prettier; enforce both in CI. Fix warnings, don't suppress them.
- Target a modern ES version with proper module resolution; keep `tsconfig` strict and shared across the workspace.

### Types
- **Type the public boundary explicitly** — exported functions, classes, and module APIs get explicit parameter and return types. Let inference handle obvious internal locals.
- Avoid `any`; prefer `unknown` for truly dynamic input and narrow it. Avoid non-null assertions (`!`) unless an invariant is proven.
- Prefer `interface`/`type` aliases over inline shapes for reused structures. Use `readonly` and `ReadonlyArray`/`ReadonlyMap` for shared/immutable data; `as const` for literal config.
- Model variants with **discriminated unions** and exhaustive `switch` (with a `never` default to catch missing cases at compile time). Prefer union string literals over loose `string`.
- Use generics for reusable abstractions; constrain type parameters (`extends`) rather than leaving them open.

### Null & undefined
- Be explicit about absence: return `T | undefined`/`T | null` and handle it; don't paper over with `!`.
- Use optional chaining (`?.`) and nullish coalescing (`??`) instead of truthiness checks that misfire on `0`/`""`.

### Functions & immutability
- Keep functions small and pure where possible; avoid mutating arguments. Prefer returning new values over in-place mutation.
- Use `const` by default, `let` only when reassignment is required; never `var`.
- Prefer immutable data flow; freeze or copy-on-write shared state rather than editing it in place.

### Async correctness
- Use `async/await` over raw `.then()` chains. **Never leave floating promises** — always `await` or explicitly handle them (`void`/`.catch`).
- Use `Promise.all` for independent concurrent work; don't serialize unnecessarily. Never block the event loop with synchronous heavy work on a request path.
- Always handle rejections; wrap awaited calls that can fail in `try/catch` and add context.

### Errors
- Throw `Error` (or subclasses), never strings or plain objects. Define typed error classes for domains you handle distinctly.
- Don't swallow errors in empty `catch` blocks; log with context or rethrow. Preserve the original cause (`new Error(msg, { cause })`).
- Distinguish expected/recoverable conditions (return a result) from exceptional ones (throw).

### Style & naming
- `PascalCase` for types/classes/enums, `camelCase` for variables/functions, `UPPER_SNAKE_CASE` for constants.
- Organize by feature; keep modules cohesive and re-export a clean public surface from an index barrel. Avoid deep relative-path spaghetti and circular imports.
- Prefer named exports over default exports for refactorability.

---

## Part 2 — NestJS Standards

### Architecture & modularity
- Organize the app into cohesive **feature modules**; keep a clear module graph and avoid circular module dependencies.
- Separate concerns by layer: **controllers** (HTTP/transport) → **services/providers** (business logic) → data-access. Keep business logic out of controllers.
- Keep modules' public surface explicit via `exports`; don't reach into another module's internals.
- For shared library code, keep a framework-agnostic core decoupled from Nest specifics where feasible, so the logic is portable and easily unit-tested.

### Dependency injection
- Use Nest's DI with **constructor injection**; mark injected dependencies `private readonly`.
- Depend on abstractions: inject by interface/token and provide implementations via providers, so they can be swapped (and mocked in tests).
- Be deliberate about provider scope (default singleton); avoid request-scoped providers unless necessary (they have a performance cost).

### Configuration & validation
- Use `@nestjs/config` with typed configuration; **validate environment variables at startup** (Joi or class-validator) and fail fast on invalid config.
- Never hardcode secrets or environment values; load from environment/secrets manager. Don't commit `.env` files.
- Validate all incoming DTOs with `class-validator` + a global `ValidationPipe` (`whitelist: true`, `forbidNonWhitelisted: true`, `transform: true`).

### Request lifecycle constructs
- Use the right construct for the job: **pipes** for validation/transformation, **guards** for authorization, **interceptors** for cross-cutting concerns (logging, timing, response shaping), **filters** for exception handling, **middleware** for low-level request processing.
- Prefer **global guards/pipes/filters** for cross-cutting policy (e.g. enforce auth everywhere) rather than per-route opt-in, so nothing is accidentally left unprotected.
- Use `AsyncLocalStorage` (or Nest's request context) for request-scoped data like correlation IDs — never module-level globals.

### Error handling & responses
- Throw Nest `HttpException` subclasses (`BadRequestException`, `UnauthorizedException`, …) so status codes are correct and consistent.
- Implement a global exception filter for uniform error responses; never leak stack traces or internals to clients.
- Return DTOs, not raw persistence entities; use serialization (`ClassSerializerInterceptor`, `@Exclude`) to keep secrets out of responses.

### Security
- Validate and sanitize all input; never trust client-supplied headers or identity claims without verification.
- Validate JWTs fully (signature against JWKS, issuer, audience, expiry); reject `alg:none`. Cache JWKS keys with timeouts.
- Apply standard hardening (helmet, CORS allow-list, rate limiting). Hash passwords with bcrypt/argon2.
- Keep dependencies patched; run `npm audit` / SCA in CI.

### Observability & resilience
- Use a structured logger (Nest `Logger`, pino) with correlation IDs; log levels appropriately; never log secrets/PII.
- Expose health checks (`@nestjs/terminus`) and metrics (Prometheus); keep metric names stable.
- Set explicit timeouts on all outbound calls (axios/HTTP); add retries with capped backoff + jitter (e.g. `p-retry`) and circuit breaking. Decide fail-open vs fail-closed explicitly.
- Implement graceful shutdown (`enableShutdownHooks`): close servers, brokers, and clear timers/intervals.

---

## Part 3 — Testing Standards (TypeScript / NestJS)

- Use **Jest** (with `ts-jest` or SWC). Follow Arrange-Act-Assert; one behavior per `it` with a descriptive name.
- **Write tests first for bug fixes** (reproduce → fix → green). Keep tests deterministic and independent — no shared mutable state, no order dependence, control time and randomness.
- Favor fast unit tests of pure logic; mock collaborators via injected tokens. Mock HTTP at the network layer (`nock`/MSW) rather than monkey-patching clients.
- Use `@nestjs/testing` `Test.createTestingModule` for wiring/integration tests of guards, pipes, and modules; use Testcontainers for real databases/brokers in e2e.
- Avoid floating promises in tests — `await` async assertions. Clean up timers, intervals, and open handles so the suite exits cleanly.
- Track coverage as a signal, not a target; deliberately cover edge cases and error paths.

---

## Part 4 — Domain Topic Standards

General best practices for the kinds of problems this domain involves. Language-neutral
principles with TypeScript/NestJS idioms where relevant; no reference to any specific implementation.

### Authorization & access control
- **Deny by default.** Every decision path must terminate in an explicit allow or deny; an unmatched, unknown, or error case is a deny. Never let absence of a rule imply permission.
- Keep authorization logic **pure and centralized** — a single function that takes a request + policy state and returns a decision, with no I/O. Easy to test exhaustively, impossible to bypass.
- Make the policy **declarative and external** to business code (config/data), not scattered decorators or inline `if` checks. Route handlers should not contain authorization branches.
- Enforce **globally** with a single construct (a global guard via `APP_GUARD`, or global middleware) rather than per-route opt-in, so nothing ships unprotected by omission.
- Resolve identity from **verified sources only** (validated token claims). Never derive roles/permissions from unauthenticated input.
- Return a **rich decision result** (allow/deny + which rule matched + the governing reason) so auditing and debugging don't have to recompute it.
- Cover the full decision matrix with tests, including every "missing dimension" edge case.

### Token & JWT validation
- Validate **every** dimension: signature, issuer, audience, expiry/not-before, and token type. A missing check is a vulnerability.
- **Reject `alg:none`** and pin allowed algorithms to an allow-list; never let the token's header dictate the verification algorithm.
- Verify signatures against a trusted **JWKS** (e.g., `jose` remote key set); cache keys and refresh on unknown key IDs (`kid`). Set a **configurable timeout** on key fetches; never fetch keys per request without caching.
- Treat clock skew explicitly with a small leeway window; don't make it unbounded.
- Distinguish token *use* (user vs service) and validate the appropriate claims for each. Handle array-valued headers when extracting bearer tokens.
- On any validation failure, fail closed (deny) and emit a metric/log; surface it as the correct `HttpException`, never leak a raw throw to the host.

### Outbound auth & service-to-service tokens
- Acquire machine-to-machine tokens via a **standard OAuth2 client-credentials flow** with a maintained library (e.g., `simple-oauth2`); do not hand-roll token HTTP/refresh.
- **Cache the token and refresh proactively** within a clock-skew buffer before expiry, with a reactive fallback on 401. Never attach an expired token.
- Propagate context (auth token, correlation/request IDs) to downstream calls **automatically** via an axios interceptor, reading request scope from `AsyncLocalStorage` — not manual per-call wiring or module globals.
- Keep credentials in a secrets manager; never log tokens.

### In-memory caching & immutable state
- For read-hot, write-rare data, hold an **immutable snapshot** and replace it by reassigning the reference. Reads are synchronous and always see a consistent version.
- Never mutate a live cache object in place; build the new state (freeze it), then swap.
- Expose cache **age** for observability and staleness detection.
- Define the lookup-miss semantics explicitly and safely (e.g., unknown key → empty/denied, not a permissive default).

### Configuration-driven policy
- Parse external config into **typed, validated objects** (interfaces + a validator); reject unknown/ambiguous/malformed config **at startup (fail-fast)**, never at request time.
- Separate **load → validate → compile** stages. Compile expensive structures (parsed rules, matchers) once at startup, never per request.
- Treat config schema as a contract: validate required fields, enum-like unions, and value ranges; produce clear, actionable error messages.

### Pattern / route matching
- Define a **deterministic precedence** for overlapping patterns (e.g., more-specific beats wildcard) and document it precisely.
- Detect genuine ambiguity (two equally-specific matches) and **reject it at startup** rather than resolving it arbitrarily at runtime.
- Compile patterns into an efficient matching structure once; keep the matching algorithm in one well-tested place.

### Startup bootstrap, fallback & reconciliation
- Define a clear, ordered **startup sequence** with explicit success/failure branches. Decide deliberately whether to fail-fast or start degraded.
- Provide a **fallback source** (local/disk cache) so a dependency outage at startup degrades gracefully into a seed mode instead of failing — but only when safe.
- Run a periodic **reconciler** that re-fetches authoritative state to heal missed/out-of-order events and promote degraded → normal. Make it idempotent and guard against overlapping runs; clear timers on shutdown.
- Persisted fallback writes must be **atomic** (temp file + rename) so a crash never leaves a half-written file; handle write errors without aborting a successful sync.

### Event-driven sync (Kafka & messaging)
- Keep event consumption **off the request path** — events update cached state asynchronously; request handling never blocks on the broker.
- **Validate every event payload**; drop malformed/blank events (with a metric) rather than corrupting state.
- Make the consumer integration **optional and degrade gracefully** — the system must function (via reconciliation) if messaging is unavailable.
- Choose consumer group semantics intentionally: use a **unique group per instance** for broadcast fan-out so every instance receives every event.
- **Fail open** on event-processing errors for cache-sync (don't crash the consumer); fail closed only where security requires it.
- Treat messaging as a best-effort accelerator on top of an authoritative full re-fetch, not the sole source of truth.

### Resilience
- Wrap every remote call in **explicit timeouts, capped exponential backoff + jitter retries** (e.g., `p-retry`), and circuit breaking.
- A slow or down dependency must never block the event loop or hang the hot path. Keep the request path local/in-memory.
- Make degraded behavior explicit and observable (which mode, why).

### Observability (audit, metrics, health)
- **Audit every security decision** (allow and deny) with structured context including the governing reason; route through a pluggable sink and a structured logger, never `console.log`.
- Publish **stable, well-named metrics** for successes, failures by category, cache age, refresh failures, and skipped events. Metric names are a contract — don't rename casually.
- Expose a **health check** (`@nestjs/terminus`) reporting cache status/age, mode, last successful sync, and dependency connectivity.
- Never log secrets, tokens, or PII. Use correlation IDs (via `AsyncLocalStorage`) to trace a request across services.

### Extensibility (SPI / plugin interfaces)
- Put every swappable behavior behind a **narrow interface** (token validation, identity provision, policy evaluation, role resolution, audit sink, etc.).
- Core logic depends only on the interface; ship sensible defaults that consumers can override by passing an implementation at composition time. Never reference a concrete implementation from core logic.
- Keep interfaces small and cohesive (interface-segregation); re-export them from the public barrel and version them carefully since they're a public contract.

### Cross-language / contract parity
- When the same behavior is implemented in multiple languages, drive both from a **single language-neutral test suite** (shared vectors / golden files) so they cannot drift.
- Treat the shared vectors as the source of truth: never tweak a vector to make one language pass — fix the implementation (or change the contract for all languages deliberately).
- Back unit-level parity with end-to-end tests that exercise the real services identically.
