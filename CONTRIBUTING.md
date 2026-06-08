# Contributing to auth-library

## Prerequisites

- **Node 22** — runs natively; used for NestJS library, demo services, and e2e runner.
- **Docker** — required for the Java build and for the e2e stack. There is no host JDK
  requirement; Java builds run in a `maven:3-eclipse-temurin-21` container via the
  wrapper scripts in `scripts/`.

## Building and Testing

### NestJS library

```sh
cd libraries/authz-nestjs
npm test
```

Runs the full Jest unit-test suite. All tests must pass before opening a pull request.

### Java (Spring Boot) library

**PowerShell (Windows):**

```powershell
tests\scripts\mvn.ps1 -ModuleDir libraries/authz-spring-boot test
```

**Bash / macOS / Linux:**

```sh
tests/scripts/mvn.sh libraries/authz-spring-boot test
```

Runs the full JUnit 5 unit-test suite inside a Docker container. Docker must be running.

### Full end-to-end suite

```sh
cd tests/e2e
docker compose up --build -d
node run.mjs
docker compose down -v
```

The e2e suite drives both demo services and asserts identical outcomes for 14 matrix
scenarios, live Kafka propagation, outbound propagation, and audience rejection.

## Test-Vector Parity Requirement

The 29 language-neutral test vectors in `docs/contracts/test-vectors/*.vectors.json` are the
authoritative cross-language parity spine. Every vector must pass in **both** libraries
before a change is merged:

- Java: `SharedVectorsTest` in `libraries/authz-spring-boot/src/test/java/`
- NestJS: `vectors.spec.ts` in `libraries/authz-nestjs/test/`

If you add a feature that changes authorization semantics, add a corresponding vector
(or update an existing one) first. Write the vector, verify both libraries fail, then
fix both implementations.

## Wildcard Rule: Stricter-Wins Parity Convention

When a new behaviour differs between Java and NestJS, the **stricter** implementation
is the reference. The looser implementation must be updated to match, not the other way
around. This preserves the security posture across runtimes.

## Coding Conventions

- Follow existing patterns in each library. Do not refactor adjacent code.
- Write tests first for bug fixes: reproduce → fix → pass.
- Audit events must be emitted on every authorization decision.
- Use immutable data structures for the permission cache (copy-on-replace).
- Both libraries must pass the same test vectors and e2e scenarios — a change that
  fixes one runtime without updating the other will not be accepted.

## Naming

The two libraries use equivalent but differently-named exception types. Do not rename
them; the mapping is documented here for cross-language reference:

| Java | TypeScript | Meaning |
|------|------------|---------|
| `ConfigException` | `ConfigError` | Thrown at startup when `authorization.yaml` is invalid |
| `CacheBootstrapException` | `CacheBootstrapError` | Thrown at startup when there is no usable role state (Role Service unreachable and no disk cache) |

Both Java classes extend `RuntimeException`; both TypeScript classes extend `Error`.
