import { PermissionCache } from "../permission-cache/cache.js";
import { RoleUpsertEvent, RoleDeleteEvent } from "../spi/index.js";

export interface ApplyResult {
  applied: boolean;
  reason?: string;
}

/**
 * T24 — Per-entity monotonic version store.
 *
 * Tracks the highest `version` value that has been successfully applied for each
 * entity key (roleId). Kafka events and snapshot entries carry an optional
 * monotonic `version` from the Role Service. An incoming event is applied only if
 * its version is strictly greater than the stored version, preventing out-of-order
 * Kafka messages from regressing the cache.
 *
 * Backward-compatible: if an event omits `version`, the caller falls back to the
 * previous always-apply behaviour and warns once per missing-version source.
 *
 * Version comparison contract (identical to Java implementation):
 *   - incomingVersion > storedVersion → APPLY and update stored version
 *   - incomingVersion <= storedVersion → SKIP (stale or duplicate, idempotent)
 *   - version absent (undefined/null) → APPLY (legacy Role Service) + warn once
 */
export class VersionStore {
  private readonly versions = new Map<string, number>();
  private warnedMissingVersion = false;

  /**
   * Check whether an incoming event for `key` with `version` should be applied.
   * Returns `{ shouldApply: true }` when the event is new, or `{ shouldApply: false,
   * reason }` when it is stale or equal. When `version` is absent the event is
   * allowed through (backward-compat) and a one-time warning callback is invoked.
   */
  check(
    key: string,
    version: number | undefined | null,
    onMissingVersionWarn?: () => void,
  ): { shouldApply: boolean; reason?: string } {
    if (version == null) {
      // Legacy Role Service — no version field. Allow through but warn once.
      if (!this.warnedMissingVersion) {
        this.warnedMissingVersion = true;
        onMissingVersionWarn?.();
      }
      return { shouldApply: true };
    }
    const stored = this.versions.get(key);
    if (stored !== undefined && version <= stored) {
      return {
        shouldApply: false,
        reason: `stale version for "${key}": incoming ${version} <= stored ${stored}`,
      };
    }
    return { shouldApply: true };
  }

  /** Record that version `version` for `key` was successfully applied. */
  record(key: string, version: number | undefined | null): void {
    if (version != null) {
      this.versions.set(key, version);
    }
  }

  /** Remove the stored version for a key (called on DELETE_ROLE so a future
   *  re-add is not blocked by the deleted entry's stale version). */
  delete(key: string): void {
    this.versions.delete(key);
  }
}

/**
 * Apply a typed upsert event to the cache atomically.
 *
 * Q5: rejects empty/whitespace roleId; rejects any empty/whitespace permission
 * after B4/C5 stringify. T24: version guard via versionStore.check/record.
 */
export async function applyUpsert(
  cache: PermissionCache,
  event: RoleUpsertEvent,
  versionStore?: VersionStore,
  onMissingVersionWarn?: () => void,
): Promise<ApplyResult> {
  // Q5: reject empty/whitespace roleId
  if (typeof event.roleId !== "string" || event.roleId.trim().length === 0) {
    return { applied: false, reason: "empty roleId in upsert event" };
  }
  if (!Array.isArray(event.permissions)) {
    return { applied: false, reason: "malformed upsert event: permissions must be an array" };
  }
  // T24: version guard — skip stale/duplicate events.
  if (versionStore) {
    const check = versionStore.check(event.roleId, event.version ?? null, onMissingVersionWarn);
    if (!check.shouldApply) {
      return { applied: false, reason: check.reason };
    }
  }
  // B4/C5: Coerce every element to string so numeric/boolean permissions
  // (e.g. 123, true) stored by Java (which uses String::valueOf) are stored
  // identically here. Ensures Set.has("123") matches a numeric permission 123
  // from a Kafka event — preventing silent decision mismatches.
  const permissions: string[] = event.permissions.map((p: unknown) => String(p));
  // Q5: after stringification, reject any permission that is blank (empty or
  // whitespace-only). A phantom "" permission must never enter the cache.
  const hasEmptyPerm = permissions.some((p) => p.trim().length === 0);
  if (hasEmptyPerm) {
    return { applied: false, reason: "empty permission string in upsert event" };
  }
  await cache.upsertRole(event.roleId, permissions);
  // T24: record the applied version after a successful upsert.
  if (versionStore) versionStore.record(event.roleId, event.version ?? null);
  return { applied: true };
}

/**
 * Apply a typed delete event to the cache atomically.
 *
 * Q5: rejects empty/whitespace roleId. T24: clears stored version on success.
 */
export async function applyDelete(
  cache: PermissionCache,
  event: RoleDeleteEvent,
  versionStore?: VersionStore,
): Promise<ApplyResult> {
  // Q5: reject empty/whitespace roleId
  if (typeof event.roleId !== "string" || event.roleId.trim().length === 0) {
    return { applied: false, reason: "empty roleId in delete event" };
  }
  await cache.deleteRole(event.roleId);
  // T24: clear the stored version on delete so a future re-add is not blocked.
  if (versionStore) versionStore.delete(event.roleId);
  return { applied: true };
}
