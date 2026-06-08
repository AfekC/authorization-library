# Graph Report - .  (2026-06-08)

## Corpus Check
- 164 files · ~141,093 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 154 nodes · 124 edges · 66 communities (10 shown, 56 thin omitted)
- Extraction: 81% EXTRACTED · 19% INFERRED · 0% AMBIGUOUS · INFERRED: 24 edges (avg confidence: 0.84)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Cross-Language Auth Library|Cross-Language Auth Library]]
- [[_COMMUNITY_Spring Boot & NestJS Modules|Spring Boot & NestJS Modules]]
- [[_COMMUNITY_Authorization Engine Core|Authorization Engine Core]]
- [[_COMMUNITY_Cache Sync & Role Service|Cache Sync & Role Service]]
- [[_COMMUNITY_Claude Code Skills|Claude Code Skills]]
- [[_COMMUNITY_Auth & Outbound Security|Auth & Outbound Security]]
- [[_COMMUNITY_Request & Context Model|Request & Context Model]]
- [[_COMMUNITY_Kafka Event Topics|Kafka Event Topics]]
- [[_COMMUNITY_Decision & Audit Results|Decision & Audit Results]]
- [[_COMMUNITY_SPI Extensibility|SPI Extensibility]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 32|Community 32]]
- [[_COMMUNITY_Community 33|Community 33]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 37|Community 37]]
- [[_COMMUNITY_Community 38|Community 38]]
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 40|Community 40]]
- [[_COMMUNITY_Community 41|Community 41]]
- [[_COMMUNITY_Community 42|Community 42]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 46|Community 46]]
- [[_COMMUNITY_Community 47|Community 47]]
- [[_COMMUNITY_Community 48|Community 48]]
- [[_COMMUNITY_Community 49|Community 49]]
- [[_COMMUNITY_Community 50|Community 50]]
- [[_COMMUNITY_Community 51|Community 51]]
- [[_COMMUNITY_Community 52|Community 52]]
- [[_COMMUNITY_Community 53|Community 53]]
- [[_COMMUNITY_Community 54|Community 54]]
- [[_COMMUNITY_Community 55|Community 55]]
- [[_COMMUNITY_Community 56|Community 56]]
- [[_COMMUNITY_Community 57|Community 57]]
- [[_COMMUNITY_Community 58|Community 58]]
- [[_COMMUNITY_Community 59|Community 59]]
- [[_COMMUNITY_Community 60|Community 60]]
- [[_COMMUNITY_Community 61|Community 61]]
- [[_COMMUNITY_Community 62|Community 62]]
- [[_COMMUNITY_Community 63|Community 63]]
- [[_COMMUNITY_Community 64|Community 64]]
- [[_COMMUNITY_Community 65|Community 65]]

## God Nodes (most connected - your core abstractions)
1. `Authz` - 10 edges
2. `authz-nestjs Library README` - 8 edges
3. `authz-spring-boot Library README` - 8 edges
4. `spring-demo Service README` - 8 edges
5. `AuthzGuardDeps` - 7 edges
6. `Decision Engine` - 6 edges
7. `nestjs-demo Service README` - 6 edges
8. `CreateAuthzOptions` - 5 edges
9. `Shared Test Vectors Spec` - 5 edges
10. `NestJS Standards & Best Practices` - 5 edges

## Surprising Connections (you probably didn't know these)
- `Global Enforcement` --conceptually_related_to--> `authz-nestjs (TypeScript)`  [INFERRED]
  authz-middleware-architecture.md → CLAUDE.md
- `Global Enforcement` --conceptually_related_to--> `authz-spring-boot (Java)`  [INFERRED]
  authz-middleware-architecture.md → CLAUDE.md
- `authz-nestjs Library README` --references--> `README Standards & Best Practices`  [INFERRED]
  libraries/authz-nestjs/README.md → docs/standards/readme-standards.md
- `authz-spring-boot Library README` --references--> `README Standards & Best Practices`  [INFERRED]
  libraries/authz-spring-boot/README.md → docs/standards/readme-standards.md
- `nestjs-demo Service README` --references--> `README Standards & Best Practices`  [INFERRED]
  tests/demo-services/nestjs-demo/README.md → docs/standards/readme-standards.md

## Hyperedges (group relationships)
- **Authorization Decision Flow** — arch_RequestContext, arch_DecisionEngine, arch_PermissionCache, arch_Audit [EXTRACTED 1.00]
- **Permission Distribution Channels** — arch_RoleService, arch_KafkaTopics, arch_DiskCache [EXTRACTED 1.00]
- **Skill Orchestration Stack** — sparc_SPARCMethodology, swarm_SwarmOrchestration, streamchain_StreamChain [INFERRED 0.75]
- **Cross-Language Test Parity System** — test_vectors_readme, authz_nestjs_readme, authz_spring_boot_readme, nestjs_demo_readme, spring_demo_readme, docker_compose_e2e [INFERRED 0.90]
- **Global Enforcement Architecture (both languages)** — global_enforcement_pattern, authz_filter_bean, create_authz_function, nestjs_demo_readme, spring_demo_readme [INFERRED 0.85]
- **Identical authorization.yaml across demo services** — nestjs_demo_authz_yaml, spring_demo_authz_yaml, cross_language_parity_standard [INFERRED 0.90]

## Communities (66 total, 56 thin omitted)

### Community 0 - "Cross-Language Auth Library"
Cohesion: 0.19
Nodes (21): AuthzAutoConfiguration Class, AuthzFilter (Global Servlet Filter), authz-nestjs Library README, authz-spring-boot Library README, Compile-error Vector (test), createAuthz() Bootstrap Function, Cross-Language Parity Standard, Decision Vector (test) (+13 more)

### Community 1 - "Spring Boot & NestJS Modules"
Cohesion: 0.13
Nodes (21): LoggingAuditSink, Authz, CreateAuthzOptions, BootstrapResult, CacheBootstrapDeps, CacheMode, AuthorizationEngine, AuthzGuardDeps (+13 more)

### Community 2 - "Authorization Engine Core"
Cohesion: 0.16
Nodes (15): Audit, authorization.yaml, Authorization Middleware Library, Decision Engine, Decision Matrix (USER/SERVICE/USER_AND_SERVICE), Global Enforcement, Observability (Metrics + Health), Permission Cache (+7 more)

### Community 3 - "Cache Sync & Role Service"
Cohesion: 0.28
Nodes (9): Cache Sync, Disk Cache (authorization-cache.json), Kafka Topics (role-updates/role-delete/publish-roles), Reconciler, Role Service, Role Service Client, Seed Mode, authorization-cache.json schema (+1 more)

### Community 4 - "Claude Code Skills"
Cohesion: 0.29
Nodes (7): Hooks Automation, Pair Programming, SPARC Methodology, Stream Chain, Swarm Orchestration, Swarm Advanced, Verification & Quality Assurance

### Community 5 - "Auth & Outbound Security"
Cohesion: 0.40
Nodes (6): Inbound Auth, Outbound Middleware, RequestContext, Service JWT (SSO), Service Token (OAuth2 Client Credentials), User JWT

### Community 6 - "Request & Context Model"
Cohesion: 0.50
Nodes (4): AuthorizedRequest, RequestContext, OutboundContext, AuthType

### Community 7 - "Kafka Event Topics"
Cohesion: 0.50
Nodes (4): Kafka Event Contracts, publish-roles Topic (Forced Refresh), role-delete Topic (DELETE), role-updates Topic (UPSERT)

### Community 8 - "Decision & Audit Results"
Cohesion: 0.50
Nodes (4): DecisionResult, CompiledRule, Decision, AuditEvent

### Community 9 - "SPI Extensibility"
Cohesion: 0.67
Nodes (3): SPI Interfaces, ServiceIdentityProvider, TokenValidator

## Knowledge Gaps
- **95 isolated node(s):** `LoggingAuditSink`, `formatInfoLine`, `buildAuditEvent`, `AuthorizedRequest`, `createAuthzFromOptions` (+90 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **56 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Decision Engine` connect `Authorization Engine Core` to `Auth & Outbound Security`?**
  _High betweenness centrality (0.013) - this node is a cross-community bridge._
- **Why does `Derived Operation from Topic Pattern` connect `Cross-Language Auth Library` to `Kafka Event Topics`?**
  _High betweenness centrality (0.008) - this node is a cross-community bridge._
- **Are the 3 inferred relationships involving `authz-nestjs Library README` (e.g. with `authz-spring-boot Library README` and `README Standards & Best Practices`) actually correct?**
  _`authz-nestjs Library README` has 3 INFERRED edges - model-reasoned connections that need verification._
- **Are the 3 inferred relationships involving `authz-spring-boot Library README` (e.g. with `authz-nestjs Library README` and `README Standards & Best Practices`) actually correct?**
  _`authz-spring-boot Library README` has 3 INFERRED edges - model-reasoned connections that need verification._
- **Are the 3 inferred relationships involving `spring-demo Service README` (e.g. with `E2E Docker Compose (Cross-Language Stack)` and `nestjs-demo Service README`) actually correct?**
  _`spring-demo Service README` has 3 INFERRED edges - model-reasoned connections that need verification._
- **What connects `LoggingAuditSink`, `formatInfoLine`, `buildAuditEvent` to the rest of the system?**
  _95 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Spring Boot & NestJS Modules` be split into smaller, more focused modules?**
  _Cohesion score 0.12857142857142856 - nodes in this community are weakly interconnected._