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
