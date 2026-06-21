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

    public record Report(String cacheStatus, long cacheAgeSeconds,
                         String mode, String roleServiceLastSync, boolean kafkaConsumerConnected) {}

    public Report report() {
        boolean empty = cache.snapshot().isEmpty();
        long ageSeconds = Math.max(0,
                // B7: FLOOR to whole seconds — explicit integer division truncation (1.999s → 1).
                (System.currentTimeMillis() - cache.lastUpdatedAt().toEpochMilli()) / 1000);
        // External-source mode (§0.5b): no CacheBootstrap — report cache-only, mirroring
        // the NestJS no-boot health branch (mode "normal", no sync, kafka disconnected).
        if (bootstrap == null) {
            return new Report(empty ? "empty" : "initialized", ageSeconds, CacheBootstrap.Mode.NORMAL.name(), null, false);
        }
        Instant sync = bootstrap.roleServiceLastSync();
        return new Report(
                empty ? "empty" : "initialized",
                ageSeconds,
                bootstrap.mode().name(),
                // B8: truncate to millisecond precision to match NestJS Date.toISOString() output.
                sync != null ? sync.truncatedTo(ChronoUnit.MILLIS).toString() : null,
                bootstrap.isKafkaConnected());
    }
}
