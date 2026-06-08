package com.example.authz.observability;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Simple in-process counters/gauges (architecture §10.2).
 *
 * <p><b>G12 — token-validation failure modes:</b> the aggregate counters
 * {@link #JWT_VALIDATION_FAILURES} and {@link #SERVICE_TOKEN_FAILURES} are
 * supplemented by per-mode counters that encode the failure cause in the
 * metric name suffix: {@code _expired}, {@code _invalid_signature},
 * {@code _malformed}. Call {@link #incTokenFailure(String, TokenFailureMode)}
 * to increment both the aggregate and the mode-specific counter atomically.
 *
 * <p><b>Observability bridge:</b> the in-process maps remain the source of truth
 * for {@link #snapshot()}/health. Optional telemetry sinks can subscribe to
 * updates via {@link #addSink(Sink)}; the Spring auto-configuration uses that
 * hook to mirror values to Micrometer when a registry is present.
 */
public class Metrics {
    public static final String AUTHZ_SUCCESS = "authz_success_total";
    public static final String AUTHZ_FAILURE = "authz_failure_total";
    public static final String PERMISSION_DENIED = "authz_permission_denied_total";
    public static final String JWT_VALIDATION_FAILURES = "jwt_validation_failures_total";
    public static final String SERVICE_TOKEN_FAILURES = "service_token_failures_total";
    public static final String ROLE_EVENT_SKIPPED = "role_event_skipped_total";
    public static final String ROLE_REFRESH_FAILURES = "role_refresh_failures_total";
    public static final String DISK_CACHE_WRITE_FAILURES = "disk_cache_write_failures_total";
    public static final String CACHE_VERSION = "permission_cache_version";
    public static final String CACHE_AGE_SECONDS = "permission_cache_age_seconds";

    // ---- G12: per-mode failure suffixes ----

    /**
     * Token-validation failure modes (G12). Used with
     * {@link #incTokenFailure(String, TokenFailureMode)} to record both the
     * aggregate counter and a mode-specific counter
     * ({@code <base>_expired}, {@code <base>_invalid_signature},
     * {@code <base>_malformed}).
     */
    public enum TokenFailureMode {
        EXPIRED("expired"),
        INVALID_SIGNATURE("invalid_signature"),
        MALFORMED("malformed"),
        OTHER("other");

        private final String suffix;
        TokenFailureMode(String suffix) { this.suffix = suffix; }
        public String suffix() { return suffix; }
    }

    /**
     * Increments the aggregate failure counter {@code base} and the
     * mode-specific counter {@code base + "_" + mode.suffix()}.
     *
     * @param base the aggregate metric name (e.g. {@link #JWT_VALIDATION_FAILURES})
     * @param mode the failure cause
     */
    public void incTokenFailure(String base, TokenFailureMode mode) {
        inc(base);
        inc(base + "_" + mode.suffix());
    }

    /**
     * Classify a token-validation exception into a {@link TokenFailureMode}.
     * Inspects the exception message for well-known Spring Security phrases.
     */
    public static TokenFailureMode classifyTokenFailure(Throwable t) {
        if (t == null) return TokenFailureMode.OTHER;
        String msg = t.getMessage() == null ? "" : t.getMessage().toLowerCase();
        // Check cause chain too
        Throwable cause = t.getCause();
        String causeMsg = (cause != null && cause.getMessage() != null)
                ? cause.getMessage().toLowerCase() : "";
        String combined = msg + " " + causeMsg;
        if (combined.contains("expired") || combined.contains("exp")) {
            // "Jwt expired" / "token is expired"
            if (combined.contains("expir") || combined.contains("jwt expired")) {
                return TokenFailureMode.EXPIRED;
            }
        }
        if (combined.contains("expir")) return TokenFailureMode.EXPIRED;
        if (combined.contains("signature") || combined.contains("verif")) {
            return TokenFailureMode.INVALID_SIGNATURE;
        }
        if (combined.contains("malform") || combined.contains("parse")
                || combined.contains("invalid jwt") || combined.contains("bad jwt")
                || combined.contains("not a valid") || combined.contains("unable to decode")) {
            return TokenFailureMode.MALFORMED;
        }
        return TokenFailureMode.OTHER;
    }

    private final Map<String, AtomicLong> counters = new ConcurrentHashMap<>();
    private final Map<String, Long> gauges = new ConcurrentHashMap<>();

    private final CopyOnWriteArrayList<Sink> sinks = new CopyOnWriteArrayList<>();

    /**
     * Optional metrics mirror. Implementations must be non-throwing: a broken
     * observability backend must never change authorization behavior.
     */
    public interface Sink {
        void incrementCounter(String name);
        void setGauge(String name, long value);
    }

    public void addSink(Sink sink) {
        if (sink != null) {
            sinks.addIfAbsent(sink);
        }
    }

    public void inc(String name) {
        counters.computeIfAbsent(name, k -> new AtomicLong()).incrementAndGet();
        for (Sink sink : sinks) {
            try {
                sink.incrementCounter(name);
            } catch (RuntimeException ignored) {
                // Metrics export is best-effort.
            }
        }
    }

    public void setGauge(String name, long value) {
        gauges.put(name, value);
        for (Sink sink : sinks) {
            try {
                sink.setGauge(name, value);
            } catch (RuntimeException ignored) {
                // Metrics export is best-effort.
            }
        }
    }

    public long get(String name) {
        AtomicLong c = counters.get(name);
        if (c != null) return c.get();
        return gauges.getOrDefault(name, 0L);
    }

    public Map<String, Long> snapshot() {
        Map<String, Long> out = new LinkedHashMap<>();
        counters.forEach((k, v) -> out.put(k, v.get()));
        out.putAll(gauges);
        return out;
    }
}
