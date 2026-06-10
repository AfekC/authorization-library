# REST API Contracts

## Role Service — Permissions Snapshot

Fetched at library startup and periodically during reconciliation. The authoritative full-state source.

### `GET /roles`

**Response `200 OK`**

```jsonc
{
  "MANAGER": ["READ_ORDER", "DELETE_ORDER"],
  "VIEWER":  ["READ_ORDER"]
}
```

| Field | Type | Description |
|-------|------|-------------|

|  | map of `string(UUID) → string[]` | Role ID → set of permission strings |

**Error response** — see fallback behaviour (§8.4 of architecture):

```jsonc
{
  "error": "service_unavailable",
  "message": "Role Service unreachable"
}
```

> **Informational only.** Neither library reads the error response body from the Role
> Service. Both libraries react only to HTTP status code and/or connection timeout to
> trigger the fallback path (seed mode). The body shape above is a convention for the
> Role Service implementation; it has no effect on library behaviour.

## Health Indicator

Exposed by the library, not an external dependency.

Fields marked with `†` are **only present when user auth is enabled** (§0.5 of the architecture doc). In service-only mode the health indicator reports only basic service reachability; cache-related fields are absent.

| Field | Type | Description |
|-------|------|-------------|
| `cacheStatus` † | string | `"initialized"` or `"empty"` |
| `cacheAgeSeconds` † | integer | Seconds since the last cache write (truncated in Java, rounded in NestJS) |
| `mode` † | string | `"NORMAL"` (synced from Role Service) or `"SEED"` (running from disk cache; Role Service not yet reached) |
| `roleServiceLastSync` † | string \| null | ISO-8601 timestamp of the last successful `GET /roles` fetch, or `null` |
| `kafkaConsumerConnected` † | boolean | Whether the Kafka consumer is running |

The `mode` field is emitted by both libraries when user auth is enabled: Java (`AuthzHealth.Report.mode` —
`CacheBootstrap.Mode.NORMAL` / `SEED`) and NestJS (`HealthReport.mode` — the
`CacheMode` union `"normal"` / `"seed"`).

> Note: Java emits mode values as upper-case (`"NORMAL"`, `"SEED"`); NestJS emits
> lower-case (`"normal"`, `"seed"`). This is a known cross-language inconsistency.

## HTTP Headers

| Header | When | Value |
|--------|------|-------|
| `Authorization: Bearer <jwt>` | User or combined request | User JWT signed by Auth Service |
| `X-Service-Token: <jwt>` | Service or combined request | Service JWT signed by SSO/OIDC |
| `X-Correlation-Id` | Outbound propagation | Trace identifier from inbound |
| `X-Request-Id` | Outbound propagation | Unique request identifier |

## Status Codes and Error Response Bodies

Both libraries return a JSON body on every 401 and 403. The body always contains a
single `error` string field.

### 401 Unauthorized

Returned when credentials are absent or fail validation.

```jsonc
{ "error": "<reason>" }
```

| `error` value | Condition | Java | NestJS |
|---------------|-----------|------|--------|
| `"no credentials"` | No `Authorization` or `X-Service-Token` header | yes | yes |
| `"user token validation failed"` | User JWT is invalid, expired, or fails signature/issuer/audience checks | yes | yes |
| `"service token validation failed"` | Service token is invalid, expired, or fails `token_use` check | yes | yes |

### 403 Forbidden

Returned when the caller is authenticated but lacks the required permission or is not
in the `allowedServices` list.

```jsonc
{ "error": "authorization denied" }
```

Both libraries return exactly `"authorization denied"` as the `error` value.

### Java implementation note

The Java `AuthorizationFilter` uses `response.sendError()`, so the actual response body
is rendered by the servlet container's error handling. In a default Spring Boot setup
this is the `/error` endpoint which wraps the message inside a standard error envelope.
The raw `error` string above is the message passed to `sendError()`; the final HTTP body
may vary by container configuration.

### Summary table

| Code | Meaning |
|------|---------|
| `401` | Invalid/expired JWT, invalid service token, or no credentials presented |
| `403` | Valid authentication but missing required permission(s) or service not allow-listed |
