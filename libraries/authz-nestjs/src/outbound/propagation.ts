import { ServiceIdentityProvider } from "../spi/index.js";
import { RequestContext } from "../inbound-auth/context.js";
import { currentOutboundContext } from "./context-store.js";

export interface OutboundHeaders {
  [name: string]: string;
}

/** Minimal shape of an axios instance's request interceptor registry. */
export interface AxiosLike {
  interceptors: {
    request: {
      use(onFulfilled: (config: any) => any): number;
    };
  };
}

/**
 * Register an axios request interceptor that automatically attaches propagation
 * headers (user JWT, service token, correlation/request ids) for the in-flight
 * inbound request (architecture §9/§12). Headers already set on the outgoing
 * request are preserved. No-op when called outside an authorized request.
 *
 * A5:  serviceIdentity is optional — when absent, X-Service-Token is simply omitted
 *      and user JWT + trace headers are still propagated. This makes attachOutbound
 *      ergonomic to call even before serviceToken is configured.
 * G4:  If service token acquisition fails after retries, the interceptor logs a
 *      warning and omits X-Service-Token — it still propagates the user JWT and trace
 *      headers so the outbound call is not killed by an unrelated SSO failure.
 */
export function attachOutboundPropagation(
  axiosInstance: AxiosLike,
  opts: { serviceIdentity?: ServiceIdentityProvider },
): void {
  axiosInstance.interceptors.request.use(async (config: any) => {
    const current = currentOutboundContext();
    if (!current) return config;
    const headers = await buildOutboundHeaders({
      ctx: current.ctx,
      userJwt: current.userJwt,
      serviceIdentity: opts.serviceIdentity,
    });
    config.headers = config.headers ?? {};
    for (const [name, value] of Object.entries(headers)) {
      if (config.headers[name] == null) config.headers[name] = value;
    }
    return config;
  });
}

/**
 * Build the headers to attach to an outbound call:
 *
 * - B5:   user JWT is propagated only when it is a non-blank string (Java isBlank() parity).
 *         Whitespace-only values ("   ") are treated as absent — no Authorization header added.
 * - F4/G5: X-Service-Token is only attached when serviceIdentity is provided AND the token
 *         is successfully acquired. No unconditional attachment.
 * - G4:   If getServiceToken() rejects after retries, the error is caught and logged;
 *         X-Service-Token is omitted but the rest of the headers (user JWT, trace ids)
 *         are still returned. Never throws — fail-open.
 */
export async function buildOutboundHeaders(params: {
  ctx: RequestContext;
  userJwt?: string | null;
  serviceIdentity?: ServiceIdentityProvider; // F4/G5: optional — no unconditional attachment
  logger?: { warn: (msg: string) => void };
}): Promise<OutboundHeaders> {
  const headers: OutboundHeaders = {};

  // B5: treat whitespace-only JWTs as absent, matching Java's isBlank() check.
  if (params.userJwt && params.userJwt.trim().length > 0) {
    headers["Authorization"] = `Bearer ${params.userJwt}`;
  }

  // F4/G5: only attempt service token acquisition when a provider is configured.
  if (params.serviceIdentity) {
    try {
      const svcToken = await params.serviceIdentity.getServiceToken();
      // Only attach when a non-blank token was actually returned (conditional
      // attachment). A blank/whitespace token is treated as absent so we never
      // emit an empty X-Service-Token header.
      if (typeof svcToken === "string" && svcToken.trim().length > 0) {
        headers["X-Service-Token"] = svcToken;
      }
    } catch (err) {
      // G4: fail-open — log a warning and omit X-Service-Token rather than
      // propagating the error and killing the outbound call.
      const logger = params.logger ?? { warn: (m: string) => console.warn(m) };
      logger.warn(
        `[authz] Service token acquisition failed; omitting X-Service-Token (fail-open): ${String(err)}`,
      );
    }
  }

  headers["X-Correlation-Id"] = params.ctx.correlationId;
  headers["X-Request-Id"] = params.ctx.requestId;
  return headers;
}
