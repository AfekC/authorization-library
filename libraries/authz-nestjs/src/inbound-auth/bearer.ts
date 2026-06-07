/**
 * Shared Bearer-token extraction helper.
 *
 * Both the NestJS guard and the Express middleware use this function so that
 * array-header handling and regex parsing are consistent across both entry
 * points (parity gap N3).
 */

/**
 * Extract the token string from an Authorization header value.
 *
 * - Handles duplicate/array headers (Express aggregates them): uses the first.
 * - Case-insensitive "Bearer" prefix match.
 * - Returns undefined (not null) when the header is absent or malformed so
 *   callers can use a uniform undefined-check.
 */
export function extractBearer(header: unknown): string | undefined {
  // Express aggregates duplicate headers into an array; use the first element.
  // Only produce undefined when the header is genuinely absent (not an array).
  const value = Array.isArray(header) ? header[0] : header;
  if (typeof value !== "string") return undefined;
  const m = /^Bearer\s+(.+)$/i.exec(value);
  return m ? m[1] : undefined;
}
