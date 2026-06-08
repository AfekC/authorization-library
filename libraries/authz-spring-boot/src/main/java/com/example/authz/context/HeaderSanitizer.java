package com.example.authz.context;

import java.util.List;

/**
 * Decides whether an inbound header asserts identity and must be ignored
 * (architecture §12.1 / B10 / E4).
 *
 * <p>This is a deny-by-default + explicit-allow boundary against context
 * tampering:
 * <ul>
 *   <li><b>Trusted (never stripped):</b> {@code Authorization} and
 *       {@code X-Service-Token} are consumed by the token validator and pass
 *       through untouched — their authenticity is established by signature
 *       validation, not by trusting the header.</li>
 *   <li><b>Untrusted (stripped/ignored):</b> any identity/context header
 *       matching the configured prefixes/exact names — by default
 *       {@code x-user-*}, {@code x-role}, {@code x-service-*}, {@code x-tenant}
 *       (and exact {@code x-user}, {@code x-role}, {@code x-tenant},
 *       {@code x-userid}). These are never trusted as authorization input,
 *       since a client could forge them.</li>
 * </ul>
 *
 * <p>The untrusted set is injectable via the constructor overloads so that
 * adopters with custom identity-header schemes can extend it without forking
 * the library.
 */
public final class HeaderSanitizer {

    /** Default prefixes that indicate an untrusted identity header. */
    public static final List<String> DEFAULT_IDENTITY_PREFIXES =
            List.of("x-user-", "x-role", "x-service-", "x-tenant");

    /** Default exact names (lower-cased) that indicate an untrusted identity header. */
    public static final List<String> DEFAULT_IDENTITY_EXACT =
            List.of("x-user", "x-role", "x-tenant", "x-userid");

    private final List<String> identityPrefixes;
    private final List<String> identityExact;

    /** Default constructor — uses the built-in untrusted-header set. */
    public HeaderSanitizer() {
        this(DEFAULT_IDENTITY_PREFIXES, DEFAULT_IDENTITY_EXACT);
    }

    /**
     * Injectable constructor for adopters that need a custom untrusted-header set
     * (E4). Both lists are matched case-insensitively.
     *
     * @param identityPrefixes header name prefixes (lower-cased) that are untrusted
     * @param identityExact    exact header names (lower-cased) that are untrusted
     */
    public HeaderSanitizer(List<String> identityPrefixes, List<String> identityExact) {
        this.identityPrefixes = List.copyOf(identityPrefixes);
        this.identityExact    = List.copyOf(identityExact);
    }

    // ------------------------------------------------------------------
    // Instance API (used when the sanitizer is injected into the filter)
    // ------------------------------------------------------------------

    /** True if this header must NOT be trusted as authorization input. */
    public boolean isUntrusted(String name) {
        return isUntrustedWith(name, identityPrefixes, identityExact);
    }

    // ------------------------------------------------------------------
    // Static API — kept for backward-compat with existing callers
    // (uses the default lists)
    // ------------------------------------------------------------------

    /** True if this header must NOT be trusted as authorization input. */
    public static boolean isUntrustedIdentityHeader(String name) {
        return isUntrustedWith(name, DEFAULT_IDENTITY_PREFIXES, DEFAULT_IDENTITY_EXACT);
    }

    // ------------------------------------------------------------------
    // Shared implementation
    // ------------------------------------------------------------------

    private static boolean isUntrustedWith(String name,
                                           List<String> prefixes,
                                           List<String> exact) {
        String lower = name.toLowerCase();
        if (lower.equals("authorization") || lower.equals("x-service-token")) {
            return false; // consumed by the token validator — never strip these
        }
        if (exact.contains(lower)) return true;
        for (String p : prefixes) {
            if (lower.startsWith(p)) return true;
        }
        return false;
    }
}
