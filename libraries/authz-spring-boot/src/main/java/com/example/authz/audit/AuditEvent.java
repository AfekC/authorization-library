package com.example.authz.audit;

import com.example.authz.engine.Decision;

/** Structured audit event emitted per decision (architecture §10.1). */
public record AuditEvent(
        String timestamp,
        String userId,
        String role,
        String serviceName,
        String path,
        String method,
        String permission,
        Decision result,
        String authenticationType,
        String requestId,
        String correlationId,
        long policyVersion) {
}
