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
 * Resolve the effective target URL from an axios request config, merging
 * `baseURL` and `url` the same way axios does. Returns an empty string when
 * neither field is set (no URL to match against).
 *
 * @internal
 */
export function resolveEffectiveUrl(config: {
  baseURL?: string;
  url?: string;
}): string {
  const base = config.baseURL ?? "";
  const path = config.url ?? "";
  if (!base && !path) return "";
  if (!base) return path;
  if (!path) return base;
  // Combine: strip trailing slash from base, ensure leading slash on path.
  return base.replace(/\/$/, "") + "/" + path.replace(/^\//, "");
}

/**
 * Return true when the string is a well-formed http:// or https:// URL.
 * Used to distinguish full URLs from bare hostnames / host:port entries.
 * @internal
 */
function isHttpUrl(s: string): boolean {
  try {
    const p = new URL(s);
    return p.protocol === "http:" || p.protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Check whether `targetUrl` is on the trusted-host allowlist.
 *
 * Matching rules:
 * - An allowlist entry may be a bare hostname (`api.internal`), a host:port
 *   pair (`api.internal:8080`), or a full base-URL
 *   (`https://api.internal/v1`).  The match is always on **host + port** only —
 *   the path/query/scheme in the entry are ignored after parsing.
 * - The port in `targetUrl` is compared against the explicit port in the entry.
 *   If the entry carries no explicit port (bare hostname), it matches any port
 *   on that host (operator intent: "trust this host").
 * - Comparison is case-insensitive on the hostname (RFC 4343).
 * - An empty allowlist → no host is trusted → returns false (default-deny).
 *
 * Implementation note: `new URL("api.internal:8080")` treats "api.internal"
 * as the URL scheme, yielding an empty hostname.  To avoid this, we detect
 * entries that are NOT http/https URLs and prepend "https://" before parsing,
 * so the URL constructor sees a valid hierarchical URL.
 *
 * @internal exported for unit-testing only.
 */
export function isHostAllowed(targetUrl: string, allowlist: string[]): boolean {
  if (allowlist.length === 0) return false;
  if (!targetUrl) return false;

  // Parse the target URL.
  let parsedTarget: URL;
  try {
    parsedTarget = new URL(targetUrl);
  } catch {
    // targetUrl has no scheme — prepend dummy scheme so URL() can extract the host.
    try {
      parsedTarget = new URL("https://" + targetUrl);
    } catch {
      return false; // unparseable
    }
  }

  const targetHost = parsedTarget.hostname.toLowerCase();
  // port is the explicit port string ("8080", "") — "" means default for scheme.
  const targetPort = parsedTarget.port; // empty string when default

  for (const entry of allowlist) {
    if (!entry || !entry.trim()) continue;

    const trimmed = entry.trim();
    let parsedEntry: URL;
    try {
      // Only use the raw entry when it already has an http/https scheme.
      // For bare "hostname" or "hostname:port" entries we MUST prepend a
      // dummy scheme, because `new URL("host:port")` would interpret "host"
      // as the scheme and return an empty hostname.
      if (isHttpUrl(trimmed)) {
        parsedEntry = new URL(trimmed);
      } else {
        parsedEntry = new URL("https://" + trimmed);
      }
    } catch {
      continue; // skip unparseable entry
    }

    const entryHost = parsedEntry.hostname.toLowerCase();
    const entryPort = parsedEntry.port; // "" means default for the dummy https scheme

    if (entryHost !== targetHost) continue;

    // Port matching:
    // - If the entry carries no explicit port ("") we match any target port
    //   (the operator intent is "trust this host regardless of port").
    // - If the entry carries an explicit port, it must equal the target's
    //   effective port.  When the target's port is "" (default for its scheme),
    //   map it to the numeric default before comparing.
    if (entryPort === "") {
      // Entry has no explicit port → matches any port on this host.
      return true;
    }

    // Entry has an explicit port — compare with target's effective port.
    const effectiveTargetPort =
      targetPort !== ""
        ? targetPort
        : parsedTarget.protocol === "https:"
          ? "443"
          : parsedTarget.protocol === "http:"
            ? "80"
            : "";
    if (entryPort === effectiveTargetPort) return true;
  }

  return false;
}

/**
 * Register an axios request interceptor that automatically attaches propagation
 * headers (user JWT, service token, correlation/request ids) for the in-flight
 * inbound request (architecture §9/§12). Headers already set on the outgoing
 * request are preserved. No-op when called outside an authorized request.
 *
 * SECURITY — trusted-host allowlist (T19):
 * When `allowedHosts` is provided the interceptor resolves the effective
 * request URL (axios `baseURL` + `url`) and only attaches the user JWT and
 * service token when the target host matches the allowlist.  `X-Correlation-Id`
 * and `X-Request-Id` are **always** attached regardless of the allowlist (they
 * are not credentials).  When `allowedHosts` is an empty array (the default)
 * NO credential headers are attached to ANY outbound request — this is the
 * safe default.  Operators MUST populate the allowlist via
 * `AUTHZ_OUTBOUND_ALLOWED_HOSTS` (or the `allowedHosts` option) to enable
 * credential propagation.
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
  opts: {
    serviceIdentity?: ServiceIdentityProvider;
    /**
     * Trusted downstream hosts. Sensitive credential headers (Authorization,
     * X-Service-Token) are ONLY attached when the outbound target's host
     * matches an entry in this list.  Default: [] (attach to nothing).
     */
    allowedHosts?: string[];
  },
): void {
  const allowedHosts = opts.allowedHosts ?? [];
  axiosInstance.interceptors.request.use(async (config: any) => {
    const current = currentOutboundContext();
    if (!current) return config;

    // Resolve the effective target URL from the axios config so we can check
    // the host against the allowlist before attaching any credentials.
    const effectiveUrl = resolveEffectiveUrl({
      baseURL: config.baseURL,
      url: config.url,
    });
    const trusted = isHostAllowed(effectiveUrl, allowedHosts);

    const headers = await buildOutboundHeaders({
      ctx: current.ctx,
      userJwt: current.userJwt,
      serviceIdentity: opts.serviceIdentity,
      trusted,
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
 * - T19:  Credential headers (Authorization, X-Service-Token) are ONLY built when
 *         `trusted` is true.  Trace headers (X-Correlation-Id, X-Request-Id) are
 *         always included — they are not credentials.  Default: trusted=false.
 */
export async function buildOutboundHeaders(params: {
  ctx: RequestContext;
  userJwt?: string | null;
  serviceIdentity?: ServiceIdentityProvider; // F4/G5: optional — no unconditional attachment
  logger?: { warn: (msg: string) => void };
  /**
   * T19: whether the outbound target is on the trusted-host allowlist.
   * When false (the default), credential headers are suppressed even if
   * userJwt and serviceIdentity are present.  This is the safe default —
   * operators must configure AUTHZ_OUTBOUND_ALLOWED_HOSTS to enable
   * credential propagation.
   */
  trusted?: boolean;
}): Promise<OutboundHeaders> {
  const headers: OutboundHeaders = {};
  const trusted = params.trusted ?? false;

  if (trusted) {
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
  }

  // Trace headers are NOT credentials — always attach regardless of allowlist.
  headers["X-Correlation-Id"] = params.ctx.correlationId;
  headers["X-Request-Id"] = params.ctx.requestId;
  return headers;
}
