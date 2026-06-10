# Configuration File Contracts

## authorization.yaml

Each service owns one `authorization.yaml` loaded at startup. Compilation fails fast on errors — the service does not start.

### Full schema

```yaml
rules:
  - path: /orders/**            # ** = deep wildcard (any depth)
    methods: [GET]
    permissions: [READ_ORDER]
    decision: ANY               # ANY | ALL  (default ANY)

  - path: /orders               # exact
    methods: [POST]
    permissions: [WRITE_ORDER, ADMIN]
    decision: ANY               # WRITE_ORDER OR ADMIN

  - path: /orders/*/audit       # * = single segment
    methods: [GET]
    permissions: [READ_ORDER, ADMIN]
    decision: ALL               # READ_ORDER AND ADMIN

  - path: /internal/reconcile
    methods: [POST]
    allowedServices: [scheduler, batch]   # service-only route

  - path: /orders/**
    methods: [POST]
    permissions: [WRITE_ORDER]
    allowedServices: ["*"]      # any validly-authenticated service
```

### Fields

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `path` | yes | string | Route pattern: exact, `*` (one segment), `**` (any depth, final segment only) |
| `methods` | yes | string[] | HTTP methods (e.g. GET, POST, PUT, DELETE) |
| `permissions` | no | string[] | Required permissions. **Only evaluated when user auth is enabled.** In service-only mode the field is silently ignored — the rule behaves as if `permissions` were absent. |
| `decision` | no | `"ANY"` or `"ALL"` | Default `"ANY"`. `ANY` = at least one permission required; `ALL` = every permission required. **Only effective when user auth is enabled.** |
| `allowedServices` | no | string[] | Services permitted to call; `"*"` means any authenticated service |

### Wildcard semantics

- **Literal segment** — matches only itself
- **`*`** — matches exactly one path segment
- **`**`** — matches one or more segments; **only valid as the final segment**

**Partial wildcards are rejected at compile time.** A path segment that contains `*`
but is not exactly `*` or `**` (e.g. `par*`, `*ix`, `v*rs*on`) is a configuration
error and the service will refuse to start. Both the Java (`RuleCompiler.java:103-104`)
and NestJS (`compile.ts:30-33`) compilers enforce this with the message:
`partial wildcards are not supported (segment "<value>" in "<path>")`.

Valid wildcard patterns:

| Pattern | Valid | Explanation |
|---------|-------|-------------|
| `/orders/*` | yes | single-segment wildcard |
| `/orders/**` | yes | deep wildcard as the final segment |
| `/orders/*/audit` | yes | single wildcard in the middle |
| `/v*/orders` | **no** | partial wildcard — rejected at startup |
| `/orders/par*` | **no** | partial wildcard — rejected at startup |
| `/orders/**/detail` | **no** | `**` not in the final segment — rejected at startup |
| `/` | **no** | root path has no segments — always DENY; no rule can match it |

### Startup validation (fail-fast)

- Unknown field present → reject
- Invalid `decision` value → reject
- Two rules are genuinely ambiguous (identical specificity for overlapping path+method) → reject

### Most-specific rule selection

Patterns scored segment-by-segment: literal = 2, `*` = 1, `**` = 0. Compare segment scores left-to-right. On a tie: more total literal segments wins. On further tie: longer pattern wins. If still tied → config rejected at startup.

---

## authorization-cache.json

*This file is only created and loaded when user auth is enabled (§0.5 of the architecture doc). In service-only mode the file is never written.*

Written to disk every time the in-memory cache changes (after full Role Service sync or after each Kafka event). Loaded at startup **only if the Role Service is unreachable** (seed mode). The path defaults to `authorization-cache.json` (current working directory) in both libraries and is configurable.

```jsonc
{
  "timestamp": "2026-06-04T10:00:00Z",
  "roles": {
    "MANAGER": ["READ_ORDER", "DELETE_ORDER"],
    "VIEWER":  ["READ_ORDER"]
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | ISO-8601 | When this snapshot was written |
| `roles` | map of `UUID → string[]` | Full role → permissions map (no versioning) |

### Behaviour

- Only exists when user auth is enabled
- Written on every cache change (sync or Kafka event)
- Loaded at startup **only** as a fallback when Role Service is unreachable
- Seeds the in-memory cache so the service can become READY in degraded mode
- Superseded by authoritative Role Service data once available
