package com.example.authz.context;

import java.util.List;

/**
 * Decides whether an inbound header asserts identity and must be ignored
 * (architecture §12.1 / B10 / E4).
 *
 * <p>The default untrusted set covers {@code x-user-*}, {@code x-role},
 * {@code x-service-*}, and {@code x-tenant}. The set is injectable via the
 * constructor overloads so that adopters with custom identity-header schemes
 * can extend it without forking the library.
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
