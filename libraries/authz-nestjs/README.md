# authz-nestjs

Config-driven authorization middleware library for Express and NestJS.

## Install

```bash
npm install authz-nestjs
```

From workspace root during development:

```bash
npm install
```

## Quick start (Express)

```ts
import { createAuthz } from "authz-nestjs";

const authz = await createAuthz({
  userIssuer: "https://auth.example.com",
  userJwksUri: "https://auth.example.com/.well-known/jwks.json",
  serviceIssuer: "https://sso.example.com",
  serviceJwksUri: "https://sso.example.com/.well-known/jwks.json",
  audience: "my-app",
  roleServiceUrl: "http://role-service:8080",
  authorizationYamlPath: "config/authorization.yaml",
});

app.use(authz.middleware); // global enforcement, no per-route opt-in
```

## Quick start (NestJS)

```ts
// main.ts
const authz = await createAuthz({ ... });
app.use(authz.middleware);
```

## Configuration

Use `CreateAuthzOptions` to configure trust roots, permission distribution,
and behavior:

| Option | Required | Description |
|---|---|---|
| `userIssuer` | yes | Issuer of user JWTs |
| `userJwksUri` | yes | JWKS URI for user JWT signature verification |
| `serviceIssuer` | yes | Issuer of service tokens |
| `serviceJwksUri` | yes | JWKS URI for service token verification |
| `audience` | yes | Expected JWT audience |
| `roleServiceUrl` | yes | Role Service base URL |
| `authorizationYaml` | one-of | `authorization.yaml` content as text |
| `authorizationYamlPath` | one-of | Path to `authorization.yaml` on disk |
| `kafkaBrokers` | no | Enable Kafka-based incremental cache sync |
| `serviceToken` | no | Outbound identity (client-credentials) |

### Optional configuration

These fields all have sensible defaults and only need to be set when the defaults do not fit.

| Field | Type | Default | Purpose |
|---|---|---|---|
| `clockSkewSeconds` | `number` | `5` | Allowed clock-skew tolerance (seconds) applied to JWT `exp`/`nbf` validation for both user and service tokens |
| `reconcileIntervalMs` | `number` | `5000` | How often (ms) the background reconciler unconditionally re-fetches the full role map from the Role Service |
| `roleServiceConnectTimeout` | `number` | `5000` | Role Service HTTP connect timeout (ms) |
| `roleServiceReadTimeout` | `number` | `5000` | Role Service HTTP read timeout (ms) |
| `diskCachePath` | `string` | `"authorization-cache.json"` | Path to the on-disk role cache file used as a seed fallback when the Role Service is unreachable at startup |
| `serviceTokenUseClaim` | `string` | `"token_use"` | JWT claim name inspected to identify a service token |
| `serviceTokenUseValue` | `string` | `"service"` | Expected value of `serviceTokenUseClaim` for a token to be accepted as a service token |
| `roleUpdatesTopic` | `string` | `"role-updates"` | Kafka topic carrying role UPSERT events |
| `roleDeleteTopic` | `string` | `"role-delete"` | Kafka topic carrying role DELETE events |
| `publishRolesTopic` | `string` | `"publish-roles"` | Kafka topic that triggers a forced full re-fetch of the role map |
| `kafkaGroupId` | `string` | `"authz-cache-sync"` | Kafka consumer group prefix (a UUID is appended per instance to avoid group conflicts) |
| `kafkaClientId` | `string` | `"authz-cache-sync"` | Kafka consumer client ID |

## SPI extension points

- `TokenValidator` — swap JWT validation logic
- `ServiceIdentityProvider` — custom outbound token acquisition
- `RoleResolver` — resolve role to permission set
- `PolicyEngine` — replace the entire decision engine
- `AuditSink` — custom audit event handler
- `AttributeProvider` — supply ABAC attributes

## Testing

```bash
npm test --workspace=authz-nestjs
```

## Build

```bash
npm run build --workspace=authz-nestjs
```
