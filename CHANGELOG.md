# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Architecture-gaps remediation in progress.** A full audit of the implementation
  against `authz-middleware-architecture.md` (audit date 2026-06-06) identified gaps
  across documentation, cross-language parity, bugs, and test coverage. Remediation
  work is tracked in `architecture-gaps.md`. The following categories of work are in
  progress or planned:

  - **Documentation / contracts** (E-series gaps) — corrected Kafka wire-protocol
    description (operation is topic-derived, not a wire field), documented partial
    wildcard rejection, clarified Role Service error-body as informational-only, added
    `mode` field to health-indicator contract, documented 401/403 response bodies, and
    added cross-language exception-name equivalence table (see `CONTRIBUTING.md`).

  - **Cross-language parity** (B-series gaps) — several behavioural differences between
    the Java and NestJS implementations are under review: whitespace trace-ID handling
    (B1), algorithm pinning (B2), `token_use` disable behaviour (B3), Kafka permission
    value coercion (B4), whitespace user-JWT propagation (B5), cache-age metric
    rounding (B7), health-timestamp precision (B8), and path extraction (B9).

  - **Bug fixes** (C-series gaps) — NestJS disk-cache null crash (C1), Java
    `PermissionCache` concurrent update race (C2), Java filter double-dispatch on ERROR
    (C3), and others are under review.

  - **Test coverage** (D-series gaps) — token-validator unit tests, metric coverage,
    health-indicator tests, and disk-cache edge cases are planned.
