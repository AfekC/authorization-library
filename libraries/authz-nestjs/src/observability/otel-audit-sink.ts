import { AuditEvent, AuditSink } from "../spi";
import { formatInfoLine } from "../audit/audit";

/**
 * Audit sink that emits each decision as a structured JSON log through
 * `@hatraa/otel-ts`'s `otelLogger` (severity INFO for ALLOW, WARN for DENY).
 * The full {@link AuditEvent} fields are spread into the log body alongside a
 * human-readable one-liner, so logs carry both the summary and every field.
 *
 * Selected automatically by `createAuthz` when observability is enabled (unless
 * the caller supplies an explicit `auditSink`). The SDK is loaded lazily so this
 * file is inert until actually constructed.
 */
export class OtelAuditSink implements AuditSink {
  private readonly emitLog: (log: Record<string, unknown> & { message: string; level: string }) => void;

  constructor() {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { otelLogger } = require("@hatraa/otel-ts") as typeof import("@hatraa/otel-ts");
    this.emitLog = otelLogger as unknown as typeof this.emitLog;
  }

  emit(event: AuditEvent): void {
    this.emitLog({
      level: event.result === "ALLOW" ? "INFO" : "WARN",
      message: formatInfoLine(event),
      ...event,
    });
  }
}
