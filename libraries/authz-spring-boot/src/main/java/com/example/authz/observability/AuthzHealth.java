package com.example.authz.observability;

import com.example.authz.cache.PermissionCache;
import com.example.authz.sync.CacheBootstrap;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Health snapshot for the authorization library (architecture §10.3). Plain bean
 * (no actuator dependency); apps can expose it however they like.
 */
public class AuthzHealth {
    private final PermissionCache cache;
    private final CacheBootstrap bootstrap;

    public AuthzHealth(PermissionCache cache, CacheBootstrap bootstrap) {
        this.cache = cache;
        this.bootstrap = bootstrap;
    }

    public record Report(String cacheStatus, long currentVersion, long cacheAgeSeconds,
                         String mode, String roleServiceLastSync, boolean kafkaConsumerConnected) {}

    public Report report() {
        boolean empty = cache.snapshot().isEmpty();
        Instant sync = bootstrap.roleServiceLastSync();
        return new Report(
                empty ? "empty" : "initialized",
                cache.version(),
                // B7: FLOOR to whole seconds — explicit integer division truncation (1.999s → 1).
                Math.max(0, (System.currentTimeMillis() - cache.lastUpdatedAt().toEpochMilli()) / 1000),
                bootstrap.mode().name(),
                // B8: truncate to millisecond precision to match NestJS Date.toISOString() output.
                sync != null ? sync.truncatedTo(ChronoUnit.MILLIS).toString() : null,
                bootstrap.isKafkaConnected());
    }
}
