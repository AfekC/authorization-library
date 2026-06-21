import { Module } from "@nestjs/common";
import { Metrics } from "../../observability/metrics.js";
import { LoggingAuditSink } from "../../audit/audit.js";
import { AuditSink } from "../../spi/index.js";
import { CreateAuthzOptions } from "../../bootstrap/create-authz.js";
import { AUTHZ_OPTIONS, AUTHZ_METRICS, AUTHZ_AUDIT } from "../authz-options.js";

@Module({
  providers: [
    {
      provide: AUTHZ_METRICS,
      useFactory: () => new Metrics(),
    },
    {
      provide: AUTHZ_AUDIT,
      useFactory: (opts: CreateAuthzOptions): AuditSink =>
        opts.auditSink ?? new LoggingAuditSink(),
      inject: [AUTHZ_OPTIONS],
    },
  ],
  exports: [AUTHZ_METRICS, AUTHZ_AUDIT],
})
export class ObservabilityModule {}
