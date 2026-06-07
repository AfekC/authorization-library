package com.example.authz.engine;

import com.example.authz.config.CompiledRule;

/**
 * Outcome of a single authorization evaluation: the decision plus the rule that
 * matched (null when no rule matched). The matched rule lets callers report the
 * governing permission in the audit event (architecture §10.1).
 */
public record DecisionResult(Decision decision, CompiledRule matchedRule) {

    /**
     * The permission string for the audit event (architecture §10.1 / A3).
     *
     * <p>When the matched rule requires exactly one permission this returns that
     * single value (e.g. {@code "READ_ORDER"}), matching the architecture's
     * example.  When a rule requires multiple permissions (e.g. {@code ANY} of
     * {@code [WRITE_ORDER, ADMIN]}) the <em>governing set</em> is represented as
     * a comma-separated string (e.g. {@code "WRITE_ORDER,ADMIN"}).  The field
     * name {@code permission} is intentionally kept singular for wire-format
     * stability; the comma-joined representation is the defined contract for
     * multi-permission rules and is consistent between the INFO one-liner and
     * the DEBUG JSON.
     *
     * <p>Returns {@code null} for service-only rules (no permission dimension)
     * or when no rule matched.
     */
    public String auditPermission() {
        if (matchedRule == null || !matchedRule.hasPermissions()) return null;
        return String.join(",", matchedRule.permissions());
    }
}
