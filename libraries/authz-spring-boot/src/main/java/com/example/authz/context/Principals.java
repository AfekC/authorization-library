package com.example.authz.context;

/** Validated principal data extracted from token claims. */
public final class Principals {
    private Principals() {}

    public record User(String userId, String roleId) {}

    public record Service(String serviceName) {}
}
