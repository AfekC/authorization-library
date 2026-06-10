# Java & Spring Boot — Standards & Best Practices

General coding standards and best practices for Java (17/21+) and Spring Boot 3.x.
These are framework- and project-agnostic guidelines; apply them to any module.

---

## Part 1 — Java Language Standards

### Code style & formatting
- Follow a published style guide (Google Java Style or the Spring framework style) and enforce it with a formatter (Spotless, google-java-format) in CI.
- One top-level public type per file; file name matches the type.
- `PascalCase` types, `camelCase` methods/fields, `UPPER_SNAKE_CASE` constants, lowercase dotted packages.
- Keep methods short and single-purpose; keep cyclomatic complexity low. Prefer early returns over deep nesting.
- Order class members consistently: static fields, instance fields, constructors, public methods, then private helpers.

### Types & immutability
- **Prefer immutability.** Make fields `final`; use `record` for data carriers and value objects.
- Expose unmodifiable views (`List.copyOf`, `Collections.unmodifiableMap`); never return references to internal mutable collections.
- Program to interfaces (`List`, `Map`, `Collection`) in signatures, not concrete types (`ArrayList`).
- Use `enum` for fixed sets of constants; use sealed classes/interfaces to model closed hierarchies.
- Use generics correctly; avoid raw types. Apply bounded wildcards (PECS: producer-`extends`, consumer-`super`).

### Null safety & Optional
- Avoid returning `null`. Return `Optional<T>` for "maybe absent" results and empty collections instead of `null`.
- Do not use `Optional` for fields or method parameters; it is a return type.
- Validate arguments early with `Objects.requireNonNull(x, "x must not be null")` and guard clauses.
- Consider nullability annotations (`@Nullable`/`@NonNull`, JSpecify) to document intent and enable static analysis.

### Modern language features (Java 17/21)
- Use `var` for local variables when the type is obvious from the right-hand side; avoid it where it hurts readability.
- Use records, pattern matching for `instanceof` and `switch`, sealed types, text blocks, and enhanced `switch` expressions where they improve clarity.
- Prefer the Streams API for transformations, but use plain loops when they read more clearly or on hot paths. Avoid side effects inside stream operations.

### Exceptions & error handling
- Throw specific, meaningful exception types; never throw or catch bare `Exception`/`Throwable` without good reason.
- Use unchecked exceptions for programming/configuration errors; reserve checked exceptions for recoverable conditions.
- Never swallow exceptions silently. Either handle, rethrow with context, or log with the stack trace.
- Don't use exceptions for normal control flow. Clean up resources with try-with-resources (`AutoCloseable`).
- Preserve causes (`throw new XException("context", cause)`); never log-and-rethrow the same exception twice.

### Concurrency
- Prefer immutable objects and stateless components — the simplest path to thread safety.
- Use `java.util.concurrent` (`ConcurrentHashMap`, `AtomicReference`, `ExecutorService`) over `synchronized` and manual locks where possible.
- Never expose mutable static state. Document thread-safety expectations on shared components.
- Shut down executors gracefully; always handle `InterruptedException` (restore the interrupt flag).

### General
- Avoid premature optimization; measure before tuning. Favor clarity first.
- Keep dependencies minimal and explicit. Avoid static utility sprawl.
- `equals`/`hashCode` go together; use records or IDE/library generation. `toString` should be informative and free of secrets.

---

## Part 2 — Spring Boot Standards

### Dependency injection & components
- **Use constructor injection**, not field or setter injection. Declare collaborators as `final`. This yields immutable, testable beans and surfaces missing dependencies at construction.
- Don't put `@Autowired` on fields. A single constructor needs no annotation at all.
- Keep beans stateless where possible. Be deliberate about scopes (`singleton` by default).
- Favor clear stereotypes (`@Service`, `@Repository`, `@Component`, `@RestController`) over generic `@Component` for readability.

### Configuration
- Bind external configuration with **`@ConfigurationProperties`** classes (type-safe, validated) rather than scattering `@Value`.
- Validate configuration with `@Validated` + Bean Validation (`@NotNull`, `@Min`, etc.); fail fast at startup on invalid config.
- Externalize all environment-specific values; never hardcode URLs, credentials, or ports. Use profiles (`application-{profile}.yml`) for environment variants.
- Keep secrets out of source and config files — use a secrets manager or environment injection.
- Prefer YAML for hierarchical config; keep property names kebab-case.

### Application architecture
- Layer cleanly: controller (web) → service (business logic) → repository (persistence). Don't put business logic in controllers or entities.
- Use DTOs at the API boundary; don't expose persistence entities directly to clients.
- For reusable libraries, prefer **auto-configuration** with conditional beans (`@ConditionalOnMissingBean`, `@ConditionalOnClass`, `@ConditionalOnProperty`) so consumers can override and unused integrations stay inert.
- Keep packages cohesive (package-by-feature). Avoid cyclic dependencies between packages/modules.

### Web / REST APIs
- Design RESTful resources: nouns in paths, correct HTTP verbs and status codes.
- Validate request bodies with `@Valid`; handle errors centrally with `@RestControllerAdvice` / `@ExceptionHandler`, returning consistent error responses (RFC 7807 Problem Detail).
- Version APIs explicitly. Document with OpenAPI/Swagger.
- Set timeouts on all outbound HTTP calls; prefer `RestClient`/`WebClient` over the legacy `RestTemplate` for new code.

### Persistence
- Use Spring Data repositories; keep queries readable and indexed. Be aware of the N+1 problem; fetch deliberately.
- Manage transactions at the service layer with `@Transactional`; keep transactions short. Understand propagation and read-only optimization.
- Never build queries with string concatenation — use parameter binding to prevent injection.

### Security
- Use Spring Security; secure by default and open explicitly. Never disable CSRF/auth without justification.
- Validate and sanitize all inputs; never trust client-supplied headers or identity claims without verification.
- Store passwords with a strong adaptive hash (BCrypt/Argon2). Validate JWTs fully (signature, issuer, audience, expiry); reject `alg:none`.
- Keep dependencies patched; scan for known CVEs (OWASP Dependency-Check).

### Observability
- Use SLF4J for logging; never `System.out`. Log at appropriate levels with structured context (MDC for correlation IDs). Never log secrets or PII.
- Expose health, metrics, and info via Spring Boot Actuator. Publish metrics through Micrometer; keep metric names stable (they're a contract).
- Make failures observable: meaningful messages, counters for error paths, and traces for distributed calls.

### Resilience
- Set explicit timeouts, retries with capped exponential backoff + jitter, and circuit breakers (Resilience4j) on remote calls.
- Decide fail-open vs fail-closed deliberately and make the choice explicit in code.
- Design for graceful degradation; don't let one slow dependency exhaust threads.

---

## Part 3 — Testing Standards (Java / Spring)

- Use **JUnit 5** with AssertJ for fluent, readable assertions; Mockito for mocking collaborators.
- **Write tests first for bug fixes** (reproduce → fix → green) and follow Arrange-Act-Assert. One logical assertion/behavior per test; descriptive names.
- Favor fast, isolated unit tests of pure logic. Use Spring test slices (`@WebMvcTest`, `@DataJpaTest`) for focused integration; reserve `@SpringBootTest` for full-context wiring tests.
- Mock external HTTP (`MockRestServiceServer`, WireMock) and use Testcontainers for real databases/brokers in integration tests.
- Keep tests deterministic and independent — no shared mutable state, no ordering dependencies, no real network/clock unless controlled.
- Track coverage as a signal, not a target; cover edge cases and error paths, not just the happy path.

---

## Part 4 — Domain Topic Standards

General best practices for the kinds of problems this domain involves. Language-neutral
principles with Java/Spring idioms where relevant; no reference to any specific implementation.

### Authorization & access control
- **Deny by default.** Every decision path must terminate in an explicit allow or deny; an unmatched, unknown, or error case is a deny. Never let absence of a rule imply permission.
- Keep authorization logic **pure and centralized** — a single component that takes a request + policy state and returns a decision, with no I/O. Easy to test exhaustively, impossible to bypass.
- Make the policy **declarative and external** to business code (config/data), not scattered annotations or inline `if` checks. Business handlers should not contain authorization branches.
- Enforce **globally** at a single choke point (a filter/`SecurityFilterChain`) rather than per-endpoint opt-in, so nothing ships unprotected by omission.
- Resolve identity from **verified sources only** (validated token claims). Never derive roles/permissions from unauthenticated input.
- Return a **rich decision result** (allow/deny + which rule matched + the governing reason) so auditing and debugging don't have to recompute it.
- Cover the full decision matrix with tests, including every "missing dimension" edge case.

### Token & JWT validation
- Validate **every** dimension: signature, issuer, audience, expiry/not-before, and token type. A missing check is a vulnerability.
- **Reject `alg:none`** and pin allowed algorithms to an allow-list; never let the token's header dictate the verification algorithm.
- Verify signatures against a trusted **JWKS**; cache keys and refresh on unknown key IDs (`kid`). Set timeouts on key fetches; never fetch keys synchronously per request without caching.
- Treat clock skew explicitly with a small leeway window; don't make it unbounded.
- Distinguish token *use* (user vs service) and validate the appropriate claims for each.
- On any validation failure, fail closed (deny) and emit a metric/log — never let an unverified token through on error.

### Outbound auth & service-to-service tokens
- Acquire machine-to-machine tokens via a **standard OAuth2 client-credentials flow** with a battle-tested library; do not hand-roll token HTTP/refresh.
- **Cache the token and refresh proactively** within a clock-skew buffer before expiry, with a reactive fallback on 401. Never attach an expired token.
- Propagate context (auth token, correlation/request IDs) to downstream calls **automatically** via client interceptors/customizers, not manual per-call wiring.
- Keep credentials in a secrets manager; never log tokens.

### In-memory caching & immutable state
- For read-hot, write-rare data, hold an **immutable snapshot** and replace it atomically (copy-on-replace via `AtomicReference`). Readers are lock-free and always see a consistent version.
- Never mutate a live cache in place; build the new state, then swap the reference.
- Expose cache **age** for observability and staleness detection.
- Define the lookup-miss semantics explicitly and safely (e.g., unknown key → empty/denied, not a permissive default).

### Configuration-driven policy
- Parse external config into **typed, validated objects**; reject unknown/ambiguous/malformed config **at startup (fail-fast)**, never at request time.
- Separate **load → validate → compile** stages. Compile expensive structures (parsed rules, matchers) once at startup, never per request.
- Treat config schema as a contract: validate required fields, enums, and value ranges; produce clear, actionable error messages.

### Pattern / route matching
- Define a **deterministic precedence** for overlapping patterns (e.g., more-specific beats wildcard) and document it precisely.
- Detect genuine ambiguity (two equally-specific matches) and **reject it at startup** rather than resolving it arbitrarily at runtime.
- Compile patterns into an efficient matching structure once; keep the matching algorithm in one well-tested place.

### Startup bootstrap, fallback & reconciliation
- Define a clear, ordered **startup sequence** with explicit success/failure branches. Decide deliberately whether to fail-fast or start degraded.
- Provide a **fallback source** (local/disk cache) so a dependency outage at startup degrades gracefully into a seed mode instead of failing — but only when safe.
- Run a periodic **reconciler** that re-fetches authoritative state to heal missed/out-of-order events and promote degraded → normal. Make it idempotent and guard against overlapping runs.
- Persisted fallback writes must be **atomic** (temp file + move) so a crash never leaves a half-written file.

### Event-driven sync (Kafka & messaging)
- Keep event consumption **off the request path** — events update cached state asynchronously; request handling never blocks on the broker.
- **Validate every event payload**; drop malformed/blank events (with a metric) rather than corrupting state.
- Make the consumer integration **optional and degrade gracefully** — the system must function (via reconciliation) if messaging is unavailable.
- Choose consumer group semantics intentionally: use a **unique group per instance** for broadcast fan-out so every instance receives every event.
- **Fail open** on event-processing errors for cache-sync (don't crash the consumer); fail closed only where security requires it.
- Treat messaging as a best-effort accelerator on top of an authoritative full re-fetch, not the sole source of truth.

### Resilience
- Wrap every remote call in **explicit timeouts, capped exponential backoff + jitter retries, and circuit breakers** (Resilience4j).
- A slow or down dependency must never exhaust threads or hang the hot path. Keep the request path local/in-memory.
- Make degraded behavior explicit and observable (which mode, why).

### Observability (audit, metrics, health)
- **Audit every security decision** (allow and deny) with structured context including the governing reason; route through a pluggable sink, never `System.out`.
- Publish **stable, well-named metrics** (Micrometer) for successes, failures by category, cache age, refresh failures, and skipped events. Metric names are a contract — don't rename casually.
- Expose a **health endpoint** (Actuator) reporting cache status/age, mode, last successful sync, and dependency connectivity.
- Never log secrets, tokens, or PII. Use correlation IDs (MDC) to trace a request across services.

### Extensibility (SPI / plugin interfaces)
- Put every swappable behavior behind a **narrow interface** (token validation, identity provision, policy evaluation, role resolution, audit sink, etc.).
- Core logic depends only on the interface; ship sensible defaults that consumers can override (`@ConditionalOnMissingBean`). Never reference a concrete implementation from core logic.
- Keep interfaces small and cohesive (interface-segregation); version them carefully since they're a public contract.

### Cross-language / contract parity
- When the same behavior is implemented in multiple languages, drive both from a **single language-neutral test suite** (shared vectors / golden files) so they cannot drift.
- Treat the shared vectors as the source of truth: never tweak a vector to make one language pass — fix the implementation (or change the contract for all languages deliberately).
- Back unit-level parity with end-to-end tests that exercise the real services identically.
