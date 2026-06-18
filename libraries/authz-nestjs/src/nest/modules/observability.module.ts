import { Module } from "@nestjs/common";
import { Metrics } from "../../observability/metrics.js";
import { LoggingAuditSink } from "../../audit/audit.js";
import { OtelAuditSink } from "../../observability/otel-audit-sink.js";
import { initObservability, createAuthzTracer } from "../../observability/otel.js";
import { bridgeMetricsToOtel } from "../../observability/otel-bridge.js";
import { AuditSink } from "../../spi/index.js";
import { CreateAuthzOptions } from "../../bootstrap/create-authz.js";
import { AUTHZ_OPTIONS, AUTHZ_METRICS, AUTHZ_AUDIT } from "../authz-options.js";

@Module({
  providers: [
    {
      provide: AUTHZ_METRICS,
      useFactory: (opts: CreateAuthzOptions) => {
        const metrics = new Metrics();
        if (opts.observability?.enabled) {
          initObservability(opts.observability);
          bridgeMetricsToOtel(metrics);
          createAuthzTracer("authz");
        }
        return metrics;
      },
      inject: [AUTHZ_OPTIONS],
    },
    {
      provide: AUTHZ_AUDIT,
      useFactory: (opts: CreateAuthzOptions): AuditSink =>
        opts.auditSink ?? (opts.observability?.enabled ? new OtelAuditSink() : new LoggingAuditSink()),
      inject: [AUTHZ_OPTIONS],
    },
  ],
  exports: [AUTHZ_METRICS, AUTHZ_AUDIT],
})
export class ObservabilityModule {}
