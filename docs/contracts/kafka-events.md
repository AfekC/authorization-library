# Kafka Event Contracts

## Ownership split (who owns what)

The **library owns the listener**; the **service owns the connection config**.

- The `authz-*` library ships the message handler — a Spring `@KafkaListener` bean
  (`RoleEventKafkaListener`) and a NestJS `@EventPattern` controller
  (`RoleEventsController`). It also **generates its own consumer group** per instance
  (`authz-cache-sync-<uuid>`) so every replica receives every event (broadcast fan-out).
- The **host service** owns all Kafka connection config — brokers, the Avro deserializer,
  and the Schema Registry URL — via `spring.kafka.consumer.*` (Spring) or the
  `authzKafkaOptions({ brokers, schemaRegistryUrl })` factory the library exports (NestJS).
  The service does **not** set a consumer group; the library does.

## Wire format

**Confluent-framed Avro** (1-byte magic `0x00` + 4-byte schema id + Avro body). Schemas
live in a Confluent-compatible Schema Registry; the deserializer resolves the writer
schema by id at runtime. The **operation is derived from the topic** — each topic carries
exactly one schema and routes to one typed handler method. There is no `operation` field
on the wire, and (unlike the previous JSON protocol) no `operation` cross-check: the topic
*is* the operation.

## Topic: `role-updates` — upsert (`RoleUpsertEvent`)

Insert or fully replace the permission set for one role. Routes to `applyUpsert`.

| Field | Avro type | Description |
|-------|-----------|-------------|
| `roleId` | `string` | Role identifier (blank rejected) |
| `permissions` | `array<string>` | Full replacement set, not a diff (blank entries rejected) |
| `version` | `["null","long"]` | Optional monotonic serial (T24). Absent → always-apply (legacy) |

```jsonc
{ "roleId": "manager", "permissions": ["READ_ORDER", "DELETE_ORDER"], "version": 7 }
```

## Topic: `role-delete` — delete (`RoleDeleteEvent`)

Remove a role entirely. Routes to `applyDelete`.

| Field | Avro type | Description |
|-------|-----------|-------------|
| `roleId` | `string` | Role identifier to remove (blank rejected) |
| `version` | `["null","long"]` | Optional monotonic serial (T24) |

```jsonc
{ "roleId": "manager", "version": 8 }
```

## Topic: `publish-roles` — forced-refresh trigger (`PublishRolesTrigger`)

Signals the library to re-fetch the **full** role map from the Role Service (`GET /roles`),
atomically replace the in-memory cache, and rewrite the disk cache. The **payload is
ignored** — its presence is the signal. It still must be Avro-framed because all three
topics share one deserializer; a trivial schema carries the message.

```jsonc
{ "trigger": 1730000000000 }
```

A forced refresh that cannot reach the Role Service is fail-open: the current cache is
kept and `role_refresh_failures_total` is incremented.

## Processing rules

- **T24 version guard** — an event is applied only if its `version` is strictly greater
  than the highest applied version for that `roleId`; stale/duplicate events are skipped
  (`role_event_skipped_total`). Absent `version` → always-apply + one-time warning.
- **Atomic apply** — copy the in-memory map, apply the change, swap the reference in one
  operation; the disk cache is rewritten after each applied event.
- **Fail-closed authorization** — unknown role → empty permissions → DENY.
- **No batching, no reordering** — each event is applied individually in arrival order
  (the version guard, not arrival order, protects against out-of-order delivery).

## Error handling

| Scenario | Behaviour |
|----------|-----------|
| Kafka unavailable (service already READY) | **Fail open** — serve from last-known-good in-memory cache; the reconciler heals missed events |
| Value fails Avro deserialization | Container logs/skips the message; cache unchanged |
| Blank `roleId` / blank permission entry | Skip event, increment `role_event_skipped_total` |
| Stale `version` | Skip event (idempotent), increment `role_event_skipped_total` |
