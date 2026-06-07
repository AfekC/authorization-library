package com.example.authz.context;

import com.example.authz.engine.AuthType;

/** Immutable identity for a request, built only from validated token claims. */
public record RequestContext(
        String userId,
        String role,
        String tenant,
        String serviceName,
        String serviceId,
        String requestId,
        String correlationId,
        AuthType authenticationType,
        String jwtId) {
}
