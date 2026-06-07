package com.example.authz.sync;

import com.example.authz.cache.PermissionCache;

import java.util.List;
import java.util.Map;

/**
 * Applies role change events (Kafka UPSERT/DELETE) to the cache.
 *
 * <p><b>C9 — topic / wire-field cross-check:</b> The Kafka consumer derives the
 * operation from the topic name and stamps it as {@code "operation"} on the
 * event map. If the raw JSON payload already carried its own {@code "operation"}
 * field, the consumer saves it under {@code "__wire_operation"} before
 * overwriting. {@code RoleEvents.apply} checks whether {@code "__wire_operation"}
 * exists and, if so, whether it matches the topic-derived {@code "operation"}.
 * A mismatch (e.g. message body says {@code DELETE_ROLE} but arrived on the
 * upsert topic) is treated as a protocol error: the event is skipped and the
 * metric / log warning is emitted by the caller.
 */
public final class RoleEvents {
    /**
     * Internal key used by {@link KafkaCacheEventHandler} to carry the
     * wire-level {@code operation} field when it conflicts with the
     * topic-derived operation. Not present in normal (correct) messages.
     */
    static final String WIRE_OPERATION_KEY = "__wire_operation";

    private RoleEvents() {}

    public record ApplyResult(boolean applied, String reason) {
        static ApplyResult ok() { return new ApplyResult(true, null); }
        static ApplyResult skip(String reason) { return new ApplyResult(false, reason); }
    }

    @SuppressWarnings("unchecked")
    public static ApplyResult apply(PermissionCache cache, Map<String, Object> event) {
        if (event == null) return ApplyResult.skip("null event");
        Object op = event.get("operation");
        if (!(op instanceof String operation)) return ApplyResult.skip("missing operation");

        // C9: if the wire message carried its own 'operation' field that differs
        // from the topic-derived one, skip rather than act on a misclassified event.
        Object wireOp = event.get(WIRE_OPERATION_KEY);
        if (wireOp instanceof String wireOperation && !wireOperation.equals(operation)) {
            return ApplyResult.skip(
                    "operation field mismatch/conflict: topic-derived=\"" + operation
                    + "\" wire-field=\"" + wireOperation + "\"");
        }

        switch (operation) {
            case "UPSERT_ROLE" -> {
                Object roleId = event.get("roleId");
                Object perms = event.get("permissions");
                if (!(roleId instanceof String r) || !(perms instanceof List<?> p)) {
                    return ApplyResult.skip("malformed UPSERT_ROLE");
                }
                cache.upsertRole(r, ((List<Object>) p).stream().map(String::valueOf).toList());
                return ApplyResult.ok();
            }
            case "DELETE_ROLE" -> {
                Object roleId = event.get("roleId");
                if (!(roleId instanceof String r)) return ApplyResult.skip("malformed DELETE_ROLE");
                cache.deleteRole(r);
                return ApplyResult.ok();
            }
            default -> {
                return ApplyResult.skip("unknown operation \"" + operation + "\"");
            }
        }
    }
}
