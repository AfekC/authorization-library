package com.example.authz.sync;

import com.example.authz.cache.PermissionCache;

import java.util.List;
import java.util.Map;

/**
 * Applies role change events to the cache via typed DTOs.
 *
 * <p><b>T24 — version-aware apply:</b> Events may carry an optional monotonic
 * {@code version} (Long) per entity key.
 * <ul>
 *   <li>If present: apply only if {@code incoming version > stored version}
 *       (prevents out-of-order Kafka events from regressing the cache).
 *       Stale/equal events are silently skipped ({@link ApplyResult#SKIPPED_STALE}).
 *   <li>If absent: fall back to always-apply (backward compatible with older
 *       Role Service deployments that do not emit versions).
 * </ul>
 *
 * <p>Topic-to-method routing by the {@link RoleEventKafkaListener} removes the
 * need for a wire-operation cross-check (C9 / WIRE_OPERATION_KEY): each listener
 * method handles exactly one operation type.
 */
public final class RoleEvents {

    private RoleEvents() {}

    public record ApplyResult(boolean applied, String reason) {
        static ApplyResult ok() { return new ApplyResult(true, null); }
        static ApplyResult skip(String reason) { return new ApplyResult(false, reason); }
        /** Sentinel reason used when a versioned event was skipped as stale (T24). */
        public static final String SKIPPED_STALE = "stale_version";
    }

    /**
     * Apply a role-upsert event (Q5, T24, B4/C5).
     *
     * @return ok() on success, skip(...) on Q5 rejection or T24 stale skip.
     */
    @SuppressWarnings("unchecked")
    public static ApplyResult applyUpsert(PermissionCache cache, RoleUpsertEvent event) {
        if (event == null) return ApplyResult.skip("null event");
        String r = event.roleId();
        // Q5: reject blank roleId
        if (r == null || r.isBlank()) {
            return ApplyResult.skip("UPSERT_ROLE roleId must not be blank");
        }
        List<String> perms = event.permissions();
        if (perms == null) return ApplyResult.skip("malformed UPSERT_ROLE: null permissions");
        // B4/C5: coerce each element via String.valueOf (handles Avro Utf8 etc.)
        List<String> resolved = perms.stream().map(String::valueOf).toList();
        // Q5: reject blank/whitespace permission entries
        for (String perm : resolved) {
            if (perm.isBlank()) {
                return ApplyResult.skip("UPSERT_ROLE contains a blank permission entry");
            }
        }
        Long version = event.version();
        if (version != null) {
            // T24: apply only if strictly newer
            boolean applied = cache.upsertRole(r, resolved, version);
            return applied ? ApplyResult.ok() : ApplyResult.skip(ApplyResult.SKIPPED_STALE);
        } else {
            // T24: no version — always-apply (backward compat)
            cache.upsertRole(r, resolved);
            return ApplyResult.ok();
        }
    }

    /**
     * Apply a role-delete event (Q5, T24).
     *
     * @return ok() on success, skip(...) on Q5 rejection or T24 stale skip.
     */
    public static ApplyResult applyDelete(PermissionCache cache, RoleDeleteEvent event) {
        if (event == null) return ApplyResult.skip("null event");
        String r = event.roleId();
        // Q5: reject blank roleId
        if (r == null || r.isBlank()) {
            return ApplyResult.skip("DELETE_ROLE roleId must not be blank");
        }
        Long version = event.version();
        if (version != null) {
            // T24: apply only if strictly newer
            boolean applied = cache.deleteRole(r, version);
            return applied ? ApplyResult.ok() : ApplyResult.skip(ApplyResult.SKIPPED_STALE);
        } else {
            // T24: no version — always-apply (backward compat)
            cache.deleteRole(r);
            return ApplyResult.ok();
        }
    }

    /**
     * T24: Extract the optional {@code "version"} field from a raw event payload map.
     * Returns {@code null} when the field is absent (backward-compatible path).
     * Accepts Number types (Integer, Long) as well as String for robustness.
     */
    public static Long extractVersion(Map<String, Object> event) {
        Object v = event.get("version");
        if (v == null) return null;
        if (v instanceof Number n) return n.longValue();
        if (v instanceof String s) {
            try { return Long.parseLong(s.trim()); } catch (NumberFormatException ignored) {}
        }
        return null; // unparseable version treated as absent
    }
}
