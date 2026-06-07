# authz-spring-boot

Spring Boot auto-configuration library for config-driven authorization.

## Build

The project uses Maven but requires a JDK 21 Docker image:

```bash
# Linux/macOS
scripts/mvn.sh libraries/authz-spring-boot clean install

# Windows (PowerShell)
scripts\mvn.ps1 -ModuleDir libraries/authz-spring-boot clean install
```

## Add dependency

```xml
<dependency>
  <groupId>com.example</groupId>
  <artifactId>authz-spring-boot</artifactId>
  <version>0.1.0</version>
</dependency>
```

## Configuration

Set `authz.*` properties in `application.yaml` (see `AuthzProperties`):

```yaml
authz:
  user-issuer: https://auth.example.com
  user-jwks-uri: https://auth.example.com/.well-known/jwks.json
  service-issuer: https://sso.example.com
  service-jwks-uri: https://sso.example.com/.well-known/jwks.json
  audience: my-app
  role-service:
    url: http://role-service:8080
```

Provide `authorization.yaml` on the classpath or via `authz.authorization-yaml-path`.

## Key beans

The auto-configuration registers:

- **`AuthorizationEngine`** — compiled rule engine
- **`PermissionCache`** — in-memory role → permissions store
- **`AuthzFilter`** — global servlet filter (all requests)
- **`Metrics`** — Micrometer counters and gauges
- **`RoleServiceClient`** — HTTP client for the Role Service
- **`DiskCache`** — local file fallback for the role cache
- **`AuditSink`** — logging audit event handler

## Testing

```bash
scripts/mvn.sh libraries/authz-spring-boot test
```
