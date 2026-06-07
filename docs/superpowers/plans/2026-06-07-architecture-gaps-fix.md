# Plan — Fix all architecture gaps (A–G)

Date: 2026-06-07 · Branch: `fix/architecture-gaps` · Source: `architecture-gaps.md`

## Decisions
- **Scope:** every gap A–G (~60 items).
- **Parity rule:** stricter / more-secure behavior wins when Java and NestJS differ.
- **Verification:** failing-first regression test → fix → full suite green (Java `scripts\mvn.ps1`, NestJS `npm test`). New unit tests required per bug.
- **Execution:** autonomous, parallel sonnet sub-agents in waves. One squashed commit at the end.
- **Constraint:** ≤1 agent per build module per wave (Maven `target/` and Jest must not run concurrently on the same module). Java waves run sequentially; NestJS + docs/e2e run in parallel alongside.

Baselines (pre-change, both green): Java 51 tests, NestJS 58 tests.

## Waves
1. **Inbound auth & token validation** — J: A4/G1, A6, B2/G2, C7/G3, G12, D1, G8 · N: A4, A6, B2, B3/G3, B1, C13, F1, G12, D1, G8 · Docs: E1, E5, F3, E2/E3/F5/E6-doc
2. **Cache & Kafka sync** — J: C2, C6, C9, B4, D7(DiskCache) · N: C1, C5, C9, B4, B11, D7
3. **Outbound & service-token** — J: A1, B6/G9, G10, G11, F4/G5, G4, G14 · N: A1, A5, B5, B6, G10, G11, G4, F4/G5 · Demo: A5 wiring
4. **Filter, context, audit, health, metrics, role-client** — J: C3, C12, B9, B10, E4, A3, C11, B7, B8, D2, D3, D4, D6, C10, E7 · N: B9, B10, E4, B7, B8, D2, D3, D4, D6, C10, E7
5. **Compiler, SPI, config-validation, wiring, vectors** — J: C8, E5, A7, A2, C4, E8, E6, F2, F4-cond · N: C8, A7, C4, E8 · Vectors: D8, D9, D10, D11, D12
6. **e2e, mock, adverse, final docs** — E: G6, G7, G13, G15, C10-assert · Docs: E2/E3 reconcile, architecture doc

Between waves: run full Java + NestJS suites. After wave 6: full docker e2e.
