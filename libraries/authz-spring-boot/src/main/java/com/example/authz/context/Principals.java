package com.example.authz.context;

/** Validated principal data extracted from token claims. */
public final class Principals {
    private Principals() {}

    public record User(String userId, String role, String tenant, String jwtId) {}

    public record Service(String serviceName, String serviceId) {}
}
