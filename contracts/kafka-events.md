# Kafka Event Contracts

## Topic: `role-updates` — upsert events

- **Type:** Change events only (no full snapshots)
- **Format:** JSON, one event per message
- **Derived operation:** `UPSERT_ROLE` (set by the consumer; not on the wire)

Insert or fully replace the permission set for one role.

```jsonc
{
  "roleId": "manager",
  "permissions": ["READ_ORDER", "DELETE_ORDER"]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `roleId` | string | Role identifier |
| `permissions` | string[] | Full replacement set, not a diff |

> `operation` is **not** a wire field. It is absent from the message above. The consumer
> synthesises `"UPSERT_ROLE"` because the message arrived on the `role-updates` topic.

## Topic: `role-delete` — delete events

- **Type:** Deleted ID only
- **Format:** JSON, one event per message
- **Derived operation:** `DELETE_ROLE` (set by the consumer; not on the wire)

Remove a role entirely.

```jsonc
{
  "roleId": "manager"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `roleId` | string | Role identifier to remove |

> `operation` is **not** a wire field. The consumer synthesises `"DELETE_ROLE"` because
> the message arrived on the `role-delete` topic.

## Topic

- **Name:** `publish-roles`
- **Type:** Forced-refresh trigger (no payload semantics)
- **Format:** JSON, one message per trigger

### PUBLISH_ROLES (forced refresh)

Signals the library to re-fetch the **full** role map from the Role Service
(`GET /roles`) and atomically replace the in-memory cache + rewrite the disk
cache. The message **body is ignored** — any message on this topic is a trigger.

```jsonc
{ "trigger": 1730000000000 }
```

| Field | Type | Description |
|-------|------|-------------|
| _(any)_ | _(any)_ | Ignored. Presence of a message is the signal. |

A forced refresh that cannot reach the Role Service is fail-open: the current
cache is kept and `role_refresh_failures_total` is incremented.

## Processing Rules

- Events are applied **atomically**: copy the in-memory map, apply the change, swap the reference in one operation.
- After each applied event the disk cache (`authorization-cache.json`) is written.
- The `operation` is **never on the wire**; the consumer synthesises it from the topic name before passing it to the event handler. The handler receives `UPSERT_ROLE` for messages from `role-updates` (or any non-delete topic) and `DELETE_ROLE` for messages from `role-delete`.
- An unrecognised synthesised `operation` value is **logged as a warning and skipped** (defensive; cannot happen with a correct topic listener).
- **No batching** — each event is applied individually.
- **No reordering** — events are processed in arrival order.

## Error Handling

| Scenario | Behaviour |
|----------|-----------|
| Kafka unavailable (service already READY) | **Fail open** — serve from last-known-good in-memory cache |
| Event fails to parse | Skip event, log warning, cache unchanged |
| Unrecognised `operation` (synthesised from topic) | Log warning, increment `role_event_skipped_total` metric, skip |

## Wire Protocol Clarification

**The `operation` field is NOT present in Kafka messages.** The producer publishes only the
role payload; consumers synthesise the operation from which topic delivered the message:

| Delivered via topic | Synthesised operation |
|---------------------|-----------------------|
| `role-updates` (or any non-delete topic) | `UPSERT_ROLE` |
| `role-delete` | `DELETE_ROLE` |

The consumer injects the `operation` key into the parsed event map **in memory** before
passing it to the event handler — it is never on the wire. Both the Java
(`KafkaCacheEventHandler.java:69`) and NestJS (`kafka.ts:62-64`) implementations
follow this pattern identically.

**Consequence (C9):** An UPSERT message accidentally published to the `role-delete` topic
is treated as a deletion. There is no cross-check against an `operation` field in the
message body because that field does not exist on the wire.
