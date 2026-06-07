package com.example.authz.audit;

import com.example.authz.spi.Spi;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Default sink: INFO one-liner + DEBUG structured JSON (architecture §10.1).
 *
 * <p><b>C11</b> — Jackson serialization failures are logged at WARN (once per
 * {@value #WARN_INTERVAL_MS} ms) so they are observable without flooding logs.
 * They never propagate to the caller — the request path is never broken by an
 * audit failure.
 */
public class LoggingAuditSink implements Spi.AuditSink {
    private static final Logger LOG = LoggerFactory.getLogger("AUTHZ");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Minimum interval between repeated serialization-failure WARN messages. */
    private static final long WARN_INTERVAL_MS = 60_000L;

    private final AtomicLong lastWarnAt = new AtomicLong(0L);

    @Override
    public void emit(AuditEvent event) {
        LOG.info(AuditEvents.infoLine(event));
        if (LOG.isDebugEnabled()) {
            try {
                LOG.debug(MAPPER.writeValueAsString(event));
            } catch (Exception ex) {
                // C11: never break the request path, but make the failure visible.
                // Rate-limit to one WARN per WARN_INTERVAL_MS to avoid log flooding.
                long now = System.currentTimeMillis();
                long prev = lastWarnAt.get();
                if (now - prev >= WARN_INTERVAL_MS
                        && lastWarnAt.compareAndSet(prev, now)) {
                    LOG.warn("AUTHZ audit: DEBUG JSON serialization failed — "
                            + "check AuditEvent for non-serializable fields: {}", ex.getMessage());
                }
            }
        }
    }
}
