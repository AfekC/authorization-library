import { PermissionCache } from "../permission-cache/cache.js";
import { RoleEvent } from "../spi/index.js";

export interface ApplyResult {
  applied: boolean;
  reason?: string;
}

/**
 * Apply a single role event to the cache atomically (copy-on-replace happens
 * inside the cache). Unknown operations are skipped, not thrown.
 *
 * The `operation` field is the topic-derived operation set by KafkaCacheEventHandler
 * (not from the wire). When the raw Kafka message body also carries an `operation`
 * field, KafkaCacheEventHandler passes it as `_messageOperation`. If these two
 * values conflict (C9), the event is skipped rather than acted on incorrectly
 * (e.g. an UPSERT message on the delete topic would otherwise silently delete
 * a role).
 */
export async function applyRoleEvent(
  cache: PermissionCache,
  event: unknown,
): Promise<ApplyResult> {
  if (!event || typeof event !== "object") {
    return { applied: false, reason: "not an object" };
  }
  const e = event as Partial<RoleEvent> & {
    operation?: string;
    _messageOperation?: string;
  };

  // C9: Cross-check topic-derived operation vs optional raw-message operation.
  // If the message body carried an `operation` field and it disagrees with the
  // topic that delivered it, skip rather than act on an ambiguous event.
  if (
    typeof e._messageOperation === "string" &&
    e._messageOperation !== e.operation
  ) {
    return {
      applied: false,
      reason: `operation conflict: topic says "${e.operation}" but message body says "${e._messageOperation}"`,
    };
  }
  switch (e.operation) {
    case "UPSERT_ROLE": {
      const rawPerms = (e as any).permissions;
      if (typeof e.roleId !== "string" || !Array.isArray(rawPerms)) {
        return { applied: false, reason: "malformed UPSERT_ROLE" };
      }
      // Q5: reject empty-string roleId — a blank role ID is invalid and must not
      // enter the cache (Java RoleEvents.java alignment: empty roleId is invalid).
      if (e.roleId.trim().length === 0) {
        return { applied: false, reason: "empty roleId in UPSERT_ROLE" };
      }
      // B4/C5: Coerce every element to string so numeric/boolean permissions
      // (e.g. 123, true) stored by Java (which uses String::valueOf) are stored
      // identically here. Ensures Set.has("123") matches a numeric permission 123
      // from a Kafka event — preventing silent decision mismatches.
      const permissions: string[] = rawPerms.map((p: unknown) => String(p));
      // Q5: after stringification, reject any permission that is blank (empty or
      // whitespace-only). A phantom "" permission must never enter the cache.
      const hasEmptyPerm = permissions.some((p) => p.trim().length === 0);
      if (hasEmptyPerm) {
        return { applied: false, reason: "empty permission string in UPSERT_ROLE" };
      }
      await cache.upsertRole(e.roleId, permissions);
      return { applied: true };
    }
    case "DELETE_ROLE":
      if (typeof e.roleId !== "string") {
        return { applied: false, reason: "malformed DELETE_ROLE" };
      }
      // Q5: reject empty-string roleId for DELETE_ROLE as well.
      if (e.roleId.trim().length === 0) {
        return { applied: false, reason: "empty roleId in DELETE_ROLE" };
      }
      await cache.deleteRole(e.roleId);
      return { applied: true };
    default:
      return { applied: false, reason: `unknown operation "${e.operation}"` };
  }
}

/** Parse a raw Kafka message value into a role event (or null if unparseable). */
export function parseRoleEvent(raw: string | Buffer | null): unknown {
  if (raw == null) return null;
  try {
    return JSON.parse(raw.toString());
  } catch {
    return null;
  }
}
