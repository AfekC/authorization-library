# Graph Report - .  (2026-06-06)

## Corpus Check
- 117 files · ~83,639 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 131 nodes · 92 edges · 59 communities (8 shown, 51 thin omitted)
- Extraction: 89% EXTRACTED · 11% INFERRED · 0% AMBIGUOUS · INFERRED: 10 edges (avg confidence: 0.77)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Core Authorization Architecture|Core Authorization Architecture]]
- [[_COMMUNITY_NestJS Library Implementation|NestJS Library Implementation]]
- [[_COMMUNITY_Project Structure & Skills|Project Structure & Skills]]
- [[_COMMUNITY_Cache & Kafka Event System|Cache & Kafka Event System]]
- [[_COMMUNITY_Cross-Library SPI Interfaces|Cross-Library SPI Interfaces]]
- [[_COMMUNITY_Request Context Types|Request Context Types]]
- [[_COMMUNITY_Decision Engine Types|Decision Engine Types]]
- [[_COMMUNITY_Decision Engine & Wildcard Scoring|Decision Engine & Wildcard Scoring]]
- [[_COMMUNITY_Kafka Cache Event Handler|Kafka Cache Event Handler]]
- [[_COMMUNITY_Role Service Client|Role Service Client]]
- [[_COMMUNITY_Swarm Orchestration Skills|Swarm Orchestration Skills]]
- [[_COMMUNITY_Audit Formatting|Audit Formatting]]
- [[_COMMUNITY_Audit Event Building|Audit Event Building]]
- [[_COMMUNITY_AuthZ Factory Bootstrap|AuthZ Factory Bootstrap]]
- [[_COMMUNITY_Cache Bootstrap Error|Cache Bootstrap Error]]
- [[_COMMUNITY_Cache Bootstrap|Cache Bootstrap]]
- [[_COMMUNITY_Disk Snapshot|Disk Snapshot]]
- [[_COMMUNITY_Disk Cache|Disk Cache]]
- [[_COMMUNITY_Event Apply Result|Event Apply Result]]
- [[_COMMUNITY_Apply Role Event|Apply Role Event]]
- [[_COMMUNITY_Parse Role Event|Parse Role Event]]
- [[_COMMUNITY_Kafka Sync Config|Kafka Sync Config]]
- [[_COMMUNITY_Decision Function|Decision Function]]
- [[_COMMUNITY_Audit Permission|Audit Permission]]
- [[_COMMUNITY_Path Splitter|Path Splitter]]
- [[_COMMUNITY_Segment Scorer|Segment Scorer]]
- [[_COMMUNITY_Path Matcher|Path Matcher]]
- [[_COMMUNITY_Specificity Comparator|Specificity Comparator]]
- [[_COMMUNITY_User Principal|User Principal]]
- [[_COMMUNITY_Service Principal|Service Principal]]
- [[_COMMUNITY_Header Sanitizer|Header Sanitizer]]
- [[_COMMUNITY_Request Context Builder|Request Context Builder]]
- [[_COMMUNITY_AuthZ Guard|AuthZ Guard]]
- [[_COMMUNITY_Outbound Interceptor|Outbound Interceptor]]
- [[_COMMUNITY_Run Without Context|Run Without Context]]
- [[_COMMUNITY_Current Context Store|Current Context Store]]
- [[_COMMUNITY_Outbound Headers|Outbound Headers]]
- [[_COMMUNITY_Outbound Propagation|Outbound Propagation]]
- [[_COMMUNITY_Build Outbound Headers|Build Outbound Headers]]
- [[_COMMUNITY_Role Service Config|Role Service Config]]
- [[_COMMUNITY_Rule Compiler|Rule Compiler]]
- [[_COMMUNITY_Config Loader|Config Loader]]
- [[_COMMUNITY_Authorization File Loader|Authorization File Loader]]
- [[_COMMUNITY_Decision Mode|Decision Mode]]
- [[_COMMUNITY_Rule Input Type|Rule Input Type]]
- [[_COMMUNITY_Segment Kind|Segment Kind]]
- [[_COMMUNITY_Segment Type|Segment Type]]
- [[_COMMUNITY_Authorization Request Type|Authorization Request Type]]
- [[_COMMUNITY_Config Error Type|Config Error Type]]
- [[_COMMUNITY_Client Credentials Config|Client Credentials Config]]
- [[_COMMUNITY_Token Claims SPI|Token Claims SPI]]
- [[_COMMUNITY_Role Resolver SPI|Role Resolver SPI]]
- [[_COMMUNITY_Policy Engine SPI|Policy Engine SPI]]
- [[_COMMUNITY_Attribute Provider SPI|Attribute Provider SPI]]
- [[_COMMUNITY_Role Map SPI|Role Map SPI]]
- [[_COMMUNITY_Role Event SPI|Role Event SPI]]
- [[_COMMUNITY_Skill Builder Skill|Skill Builder Skill]]
- [[_COMMUNITY_Stream Chain Skill|Stream Chain Skill]]
- [[_COMMUNITY_Verification Quality Skill|Verification Quality Skill]]

## God Nodes (most connected - your core abstractions)
1. `Authorization Middleware Architecture` - 28 edges
2. `Auth Library` - 9 edges
3. `Authz` - 7 edges
4. `Language-Neutral Test Vectors` - 6 edges
5. `AuthzGuardDeps` - 5 edges
6. `Kafka Event Streams` - 5 edges
7. `CLAUDE.md Project Context` - 4 edges
8. `RequestContext` - 3 edges
9. `Metrics` - 3 edges
10. `PermissionCache` - 3 edges

## Surprising Connections (you probably didn't know these)
- `Language-Neutral Test Vectors` --references--> `SharedVectorsTest (JUnit)`  [EXTRACTED]
  contracts/test-vectors/README.md → libraries/authz-spring-boot/src/test/java/com/example/authz/SharedVectorsTest.java
- `Language-Neutral Test Vectors` --references--> `vectors.spec.ts (Jest)`  [EXTRACTED]
  contracts/test-vectors/README.md → libraries/authz-nestjs/test/vectors.spec.ts
- `Auth Library` --references--> `Authorization Middleware Architecture`  [EXTRACTED]
  README.md → authz-middleware-architecture.md
- `Auth Library` --conceptually_related_to--> `SPARC Methodology Skill`  [INFERRED]
  README.md → .claude/skills/sparc-methodology/SKILL.md
- `Authorization Middleware Architecture` --references--> `authorization.yaml Config`  [EXTRACTED]
  authz-middleware-architecture.md → contracts/config-files.md

## Hyperedges (group relationships)
- **Permission Distribution Channels** — role_service, kafka_events, disk_cache, reconciler [EXTRACTED 1.00]
- **Cross-Language Correctness Spine** — test_vectors, shared_vectors_test_java, vectors_spec_ts, e2e_parity_tests [EXTRACTED 1.00]
- **Startup State Machine** — fail_fast, role_service, disk_cache, seed_mode, kafka_events, reconciler [EXTRACTED 1.00]
- **Authentication and Authorization Decision Pipeline** — token_validator, request_context, decision_engine, permission_cache, decision_matrix, audit_events [EXTRACTED 1.00]

## Communities (59 total, 51 thin omitted)

### Community 0 - "Core Authorization Architecture"
Cohesion: 0.09
Nodes (23): Audit Events, authorization.yaml Config, Authorization Middleware Architecture, cache-sync Module, Context Tampering Prevention, Disk Cache (authorization-cache.json), Fail-Fast Startup Validation, Fail-Open Kafka Resilience (+15 more)

### Community 1 - "NestJS Library Implementation"
Cohesion: 0.14
Nodes (17): LoggingAuditSink, Authz, CreateAuthzOptions, BootstrapResult, CacheBootstrapDeps, CacheMode, AuthorizationEngine, AuthzGuardDeps (+9 more)

### Community 2 - "Project Structure & Skills"
Cohesion: 0.20
Nodes (12): Auth Library, Cross-Language E2E Parity Tests, Hooks Automation Skill, Mock Service (SSO + Auth JWKS + Role Service), nestjs-demo authorization.yaml, Pair Programming Skill, Redpanda (Kafka Broker), SharedVectorsTest (JUnit) (+4 more)

### Community 3 - "Cache & Kafka Event System"
Cohesion: 0.29
Nodes (7): Copy-on-Replace Cache Pattern, DELETE_ROLE Kafka Event, Health Indicator, Kafka Event Streams, Permission Cache, PUBLISH_ROLES Kafka Event (forced refresh), UPSERT_ROLE Kafka Event

### Community 4 - "Cross-Library SPI Interfaces"
Cohesion: 0.50
Nodes (5): authz-nestjs Library, authz-spring-boot Library, Recently Changed Files (architecture fix), CLAUDE.md Project Context, SPI Extension Interfaces

### Community 5 - "Request Context Types"
Cohesion: 0.50
Nodes (4): AuthorizedRequest, RequestContext, OutboundContext, AuthType

### Community 6 - "Decision Engine Types"
Cohesion: 0.50
Nodes (4): DecisionResult, CompiledRule, Decision, AuditEvent

### Community 7 - "Decision Engine & Wildcard Scoring"
Cohesion: 0.67
Nodes (3): Decision Engine, Decision Matrix (USER/SERVICE/USER_AND_SERVICE), Wildcard Path Scoring (literal=2, *=1, **=0)

## Knowledge Gaps
- **96 isolated node(s):** `LoggingAuditSink`, `formatInfoLine`, `buildAuditEvent`, `AuthorizedRequest`, `createAuthz` (+91 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **51 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Authorization Middleware Architecture` connect `Core Authorization Architecture` to `Project Structure & Skills`, `Cache & Kafka Event System`, `Cross-Library SPI Interfaces`, `Decision Engine & Wildcard Scoring`?**
  _High betweenness centrality (0.131) - this node is a cross-community bridge._
- **Why does `Auth Library` connect `Project Structure & Skills` to `Core Authorization Architecture`, `Cross-Library SPI Interfaces`?**
  _High betweenness centrality (0.054) - this node is a cross-community bridge._
- **Why does `Kafka Event Streams` connect `Cache & Kafka Event System` to `Core Authorization Architecture`?**
  _High betweenness centrality (0.020) - this node is a cross-community bridge._
- **What connects `LoggingAuditSink`, `formatInfoLine`, `buildAuditEvent` to the rest of the system?**
  _96 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Core Authorization Architecture` be split into smaller, more focused modules?**
  _Cohesion score 0.09090909090909091 - nodes in this community are weakly interconnected._
- **Should `NestJS Library Implementation` be split into smaller, more focused modules?**
  _Cohesion score 0.13970588235294118 - nodes in this community are weakly interconnected._