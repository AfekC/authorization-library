import { randomUUID } from "crypto";
import { AuthType } from "../rule-config/types";

/**
 * Immutable identity for a request, built ONLY from validated token claims.
 * Inbound identity headers are never trusted (see stripUntrustedHeaders).
 */
export interface RequestContext {
  userId: string | null;   // always null in service-only mode
  roleId: string | null;   // always null in service-only mode
  serviceName: string | null;
  requestId: string;
  correlationId: string;
  authenticationType: AuthType;
}

export interface UserPrincipal {
  userId: string | null;
  roleId: string | null;
}

export interface ServicePrincipal {
  serviceName: string | null;
}

/**
 * Identity headers that must never be trusted as authorization input.
 * Correlation/request ids are accepted only as opaque trace values.
 *
 * These are the default sets. Adopters can extend them without forking the
 * library by passing `additionalPrefixes` / `additionalExactNames` to
 * `stripUntrustedHeaders` (B10 / E4).
 */
const DEFAULT_IDENTITY_HEADER_PREFIXES = ["x-user-", "x-role", "x-service-", "x-tenant"];
const DEFAULT_IDENTITY_HEADERS_EXACT = ["x-user", "x-role", "x-tenant", "x-userid"];

/** Options for extending the header deny-list beyond the built-in defaults. */
export interface StripHeadersOptions {
  /** Additional header name prefixes (lower-cased) to treat as untrusted. */
  additionalPrefixes?: string[];
  /** Additional exact header names (lower-cased) to treat as untrusted. */
  additionalExactNames?: string[];
}

/**
 * Returns true when `lowerKey` matches any entry in the identity deny-list.
 *
 * Shared predicate used by both {@link stripUntrustedHeaders} (copy) and
 * {@link sanitizeHeadersInPlace} (in-place) so the rules are never duplicated.
 *
 * The bearer and service-token headers consumed by the validator are
 * explicitly excluded: they are NOT identity-spoofing headers.
 */
function isUntrustedIdentityHeader(
  lowerKey: string,
  prefixes: string[],
  exactNames: string[],
): boolean {
  // Consumed-by-validator headers are allowed through on both paths.
  if (lowerKey === "x-service-token" || lowerKey === "authorization") return false;
  return exactNames.includes(lowerKey) || prefixes.some((p) => lowerKey.startsWith(p));
}

/** Resolve the full prefix and exact-name lists from options (avoids duplication). */
function resolveHeaderLists(options?: StripHeadersOptions): {
  prefixes: string[];
  exactNames: string[];
} {
  return {
    prefixes: options?.additionalPrefixes
      ? [...DEFAULT_IDENTITY_HEADER_PREFIXES, ...options.additionalPrefixes]
      : DEFAULT_IDENTITY_HEADER_PREFIXES,
    exactNames: options?.additionalExactNames
      ? [...DEFAULT_IDENTITY_HEADERS_EXACT, ...options.additionalExactNames]
      : DEFAULT_IDENTITY_HEADERS_EXACT,
  };
}

/** Remove inbound identity-spoofing headers; leave trace ids intact. */
export function stripUntrustedHeaders(
  headers: Record<string, unknown>,
  options?: StripHeadersOptions,
): Record<string, unknown> {
  headers = headers ?? {};
  const { prefixes, exactNames } = resolveHeaderLists(options);

  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(headers)) {
    const lower = key.toLowerCase();
    if (isUntrustedIdentityHeader(lower, prefixes, exactNames)) continue;
    out[key] = value;
  }
  return out;
}

/**
 * Defense-in-depth: sanitize identity-spoofing headers **in place** on the
 * supplied headers object (N4).
 *
 * Unlike {@link stripUntrustedHeaders} — which returns a new filtered copy —
 * this helper **deletes** the offending keys from the object you pass in.
 * Use this as Express/NestJS global middleware so that *all* downstream reads
 * of `req.headers` see the already-sanitized map, mirroring the Java
 * `SanitizingRequestWrapper` approach:
 *
 * ```ts
 * // register as the very first piece of Express middleware:
 * app.use((req, _res, next) => {
 *   sanitizeHeadersInPlace(req.headers as Record<string, unknown>);
 *   next();
 * });
 * ```
 *
 * Both helpers share {@link isUntrustedIdentityHeader} so the deny-list
 * is defined exactly once.
 */
export function sanitizeHeadersInPlace(
  headers: Record<string, unknown>,
  options?: StripHeadersOptions,
): void {
  if (!headers) return;
  const { prefixes, exactNames } = resolveHeaderLists(options);
  for (const key of Object.keys(headers)) {
    const lower = key.toLowerCase();
    if (isUntrustedIdentityHeader(lower, prefixes, exactNames)) {
      delete headers[key];
    }
  }
}

function deriveAuthType(
  user: UserPrincipal | null,
  service: ServicePrincipal | null,
): AuthType {
  if (user && service) return "USER_AND_SERVICE";
  if (service) return "SERVICE";
  return "USER";
}

/** Returns undefined when the value is absent, empty, or whitespace-only
 *  (matches Java's StringUtils.isBlank behaviour for trace-id handling). */
function nonBlank(value: string | null | undefined): string | undefined {
  if (value == null) return undefined;
  return value.trim().length === 0 ? undefined : value;
}

/** Build the RequestContext from validated principals + trace ids. */
export function buildRequestContext(params: {
  user: UserPrincipal | null;
  service: ServicePrincipal | null;
  correlationId?: string | null;
  requestId?: string | null;
}): Readonly<RequestContext> {
  const { user, service } = params;
  return Object.freeze({
    userId: user?.userId ?? null,
    roleId: user?.roleId ?? null,
    serviceName: service?.serviceName ?? null,
    requestId: nonBlank(params.requestId) ?? randomUUID(),
    correlationId: nonBlank(params.correlationId) ?? randomUUID(),
    authenticationType: deriveAuthType(user, service),
  });
}
