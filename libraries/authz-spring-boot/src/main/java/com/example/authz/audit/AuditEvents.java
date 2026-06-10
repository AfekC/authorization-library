package com.example.authz.audit;

import com.example.authz.context.RequestContext;
import com.example.authz.engine.Decision;

import java.time.Instant;

/** Helpers to build + format audit events (parity with the NestJS audit module). */
public final class AuditEvents {
    private AuditEvents() {}

    public static AuditEvent build(RequestContext ctx, String method, String path,
                                   String permission, Decision result) {
        return new AuditEvent(
                Instant.now().toString(),
                ctx.userId(),
                ctx.roleId(),
                ctx.serviceName(),
                path,
                method,
                permission,
                result,
                ctx.authenticationType().name(),
                ctx.requestId(),
                ctx.correlationId());
    }

    /** Short one-line summary for operational monitoring. */
    public static String infoLine(AuditEvent e) {
        String who = e.userId() != null
                ? "userId=" + e.userId() + "  roleId=" + e.roleId()
                : "svc=" + e.serviceName();
        String perm = e.permission() != null ? "  perm=" + e.permission() : "";
        return String.format("AUTHZ %-5s %s %s  %s%s  corr=%s",
                e.result(), e.method(), e.path(), who, perm, e.correlationId());
    }
}
