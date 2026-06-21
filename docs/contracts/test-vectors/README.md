# Shared Test Vectors

Language-neutral authorization test vectors. Both the NestJS (Jest) and Spring Boot
(JUnit) libraries load every `*.vectors.json` file here and must produce identical results.

## Decision vector shape

```jsonc
{
  "name": "human readable",
  "rules": [ /* authorization.yaml rule objects */ ],
  "roleCache": { "ROLE": ["PERM", ...] },
  "request": {
    "method": "GET",
    "path": "/orders/7",
    "authType": "USER" | "SERVICE" | "USER_AND_SERVICE",
    "role": "MANAGER",        // present for USER / USER_AND_SERVICE
    "serviceName": "scheduler" // present for SERVICE / USER_AND_SERVICE
  },
  "expected": "ALLOW" | "DENY",
  "reason": "why"
}
```

## Compile-error vector shape

```jsonc
{ "name": "...", "rules": [ ... ], "expectCompileError": true, "reason": "..." }
```

A file is an array of vectors.

## Ed25519 fixed test keypair (T1 — RFC 8037 §A.2)

`jwt_provider` re-platformed from RS256 to Ed25519 (T1). Consumer implementations that
need to sign test tokens must use the following fixed deterministic Ed25519 key pair
(the RFC 8037 §A.2 well-known test vector):

```
Private key (d, base64url): nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A
Public  key (x, base64url): 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo

As JWK:
{
  "kty": "OKP",
  "crv": "Ed25519",
  "d":   "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
  "x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
  "alg": "EdDSA",
  "use": "sig",
  "kid": "jwt-ed25519:1"
}

Vault publicKeyRaw (base64-std, 32 raw bytes):
  11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=
```

JWT header alg is `EdDSA`; `kid` is pinned to `jwt-ed25519:<vault_key_version>`.
RS256 / RSA is no longer used anywhere in the token path.
