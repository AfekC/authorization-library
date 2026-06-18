import { AuditEvent, AuditSink } from "../spi/index.js";
import { RequestContext } from "../inbound-auth/context.js";
import { Decision } from "../rule-config/types.js";

/** Default sink: INFO one-liner + DEBUG structured event via console. */
export class LoggingAuditSink implements AuditSink {
  constructor(
    private readonly logger: {
      info: (msg: string) => void;
      debug: (msg: string) => void;
    } = { info: (m) => console.log(m), debug: (m) => console.debug(m) },
  ) {}

  emit(event: AuditEvent): void {
    this.logger.info(formatInfoLine(event));
    try {
      this.logger.debug(JSON.stringify(event));
    } catch {
      this.logger.debug("(audit event serialization failed)");
    }
  }
}

/** Short one-line summary for operational monitoring. */
export function formatInfoLine(e: AuditEvent): string {
  const who =
    e.userId != null
      ? `userId=${e.userId}  roleId=${e.roleId}`
      : `svc=${e.serviceName}`;
  const perm = e.permission != null ? `  perm=${e.permission}` : "";
  return `AUTHZ ${e.result.padEnd(5)} ${e.method} ${e.path}  ${who}${perm}  corr=${e.correlationId}`;
}

/** Build an audit event from a decision. */
export function buildAuditEvent(params: {
  ctx: RequestContext;
  method: string;
  path: string;
  permission: string | null;
  result: Decision;
}): AuditEvent {
  const { ctx } = params;
  return {
    timestamp: new Date().toISOString(),
    userId: ctx.userId,
    roleId: ctx.roleId,
    serviceName: ctx.serviceName,
    path: params.path,
    method: params.method,
    permission: params.permission,
    result: params.result,
    authenticationType: ctx.authenticationType,
    requestId: ctx.requestId,
    correlationId: ctx.correlationId,
  };
}
