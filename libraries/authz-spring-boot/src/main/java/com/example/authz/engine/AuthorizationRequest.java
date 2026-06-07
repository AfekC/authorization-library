package com.example.authz.engine;

/** Inputs to an authorization decision (identity comes only from validated claims). */
public record AuthorizationRequest(
        String method,
        String path,
        AuthType authType,
        String role,
        String serviceName) {
}
