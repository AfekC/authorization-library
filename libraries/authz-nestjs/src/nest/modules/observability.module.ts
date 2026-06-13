import { Module } from "@nestjs/common";
import { Metrics } from "../../observability/metrics";
import { LoggingAuditSink } from "../../audit/audit";
import { OtelAuditSink } from "../../observability/otel-audit-sink";
import { initObservability, createAuthzTracer } from "../../observability/otel";
import { bridgeMetricsToOtel } from "../../observability/otel-bridge";
import { AuditSink } from "../../spi";
import { CreateAuthzOptions } from "../../bootstrap/create-authz";
import { AUTHZ_OPTIONS, AUTHZ_METRICS, AUTHZ_AUDIT } from "../authz-options";

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
