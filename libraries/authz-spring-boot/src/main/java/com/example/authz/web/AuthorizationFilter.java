package com.example.authz.web;

import com.example.authz.audit.AuditEvents;
import com.example.authz.cache.PermissionCache;
import com.example.authz.context.HeaderSanitizer;
import com.example.authz.context.Principals;
import com.example.authz.context.RequestContext;
import com.example.authz.context.RequestContextBuilder;
import com.example.authz.engine.AuthType;
import com.example.authz.engine.AuthorizationEngine;
import com.example.authz.engine.AuthorizationRequest;
import com.example.authz.config.CompiledRule;
import com.example.authz.engine.Decision;
import com.example.authz.engine.DecisionResult;
import com.example.authz.observability.Metrics;
import com.example.authz.observability.Metrics.TokenFailureMode;
import com.example.authz.spi.Spi;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

/**
 * Global enforcement filter (architecture §12.1). Authenticates inbound tokens,
 * builds the RequestContext from validated claims, applies the local decision.
 * Deny -> 403; bad/absent token -> 401. No per-route opt-in.
 *
 * <p><b>C3</b> — {@link #shouldNotFilterErrorDispatch()} returns {@code true}
 * so the filter does NOT re-run on the container's ERROR dispatch triggered by
 * {@code sendError()}. Without this, a 403/401 sendError causes a second filter
 * pass (no credentials on the error dispatch) which could clobber the status or
 * produce a dispatch loop.
 *
 * <p><b>B9</b> — The path used for rule matching is stripped of the servlet
 * context path so that a deployment under {@code /myapp} sees the same logical
 * path as a root deployment, aligning with NestJS {@code req.path} semantics.
 * Query strings are excluded. Residual: if path-info rewriting by the container
 * (e.g. via a DispatcherServlet forward) changes {@code getRequestURI()}, the
 * matched path may still differ from a fully-qualified Spring MVC route; a future
 * wave can use request-mapping information to cover that case.
 *
 * <p><b>B10</b> — A defense-in-depth sanitization pass strips spoofed identity
 * headers (matching {@link HeaderSanitizer}) from the servlet response wrapper so
 * downstream code and filters cannot accidentally read them. The tokens themselves
 * ({@code Authorization}, {@code X-Service-Token}) are consumed before stripping
 * and are not affected.
 *
 * <p><b>C10</b> — The no-credentials error message is {@code "no credentials"}
 * (aligned with NestJS).
 *
 * <p><b>C12</b> — A non-string {@code role} claim (integer, array, etc.) is
 * treated as absent/invalid: the user principal is built with a {@code null}
 * role, yielding an empty permission set and a DENY decision. No silent
 * {@code String.valueOf()} coercion.
 *
 * <p><b>G12</b> — Token-validation failures increment both the aggregate counter
 * and a mode-specific counter ({@code _expired}, {@code _invalid_signature},
 * {@code _malformed}, {@code _other}) via
 * {@link Metrics#incTokenFailure(String, TokenFailureMode)}.
 */
public class AuthorizationFilter extends OncePerRequestFilter {
    public static final String CONTEXT_ATTR = "authzRequestContext";

    private final AuthorizationEngine engine;
    private final PermissionCache cache;
    private final Spi.TokenValidator validator;
    private final Spi.AuditSink audit;
    private final Metrics metrics;
    private final HeaderSanitizer headerSanitizer;
    private final Spi.PolicyEngine policyEngine;
    private final Spi.AttributeProvider attributeProvider;

    public AuthorizationFilter(AuthorizationEngine engine, PermissionCache cache,
                               Spi.TokenValidator validator, Spi.AuditSink audit) {
        this(engine, cache, validator, audit, new Metrics(), new HeaderSanitizer(),
                null, null);
    }

    public AuthorizationFilter(AuthorizationEngine engine, PermissionCache cache,
                               Spi.TokenValidator validator, Spi.AuditSink audit,
                               Metrics metrics) {
        this(engine, cache, validator, audit, metrics, new HeaderSanitizer(),
                null, null);
    }

    public AuthorizationFilter(AuthorizationEngine engine, PermissionCache cache,
                               Spi.TokenValidator validator, Spi.AuditSink audit,
                               Metrics metrics, HeaderSanitizer headerSanitizer) {
        this(engine, cache, validator, audit, metrics, headerSanitizer, null, null);
    }

    public AuthorizationFilter(AuthorizationEngine engine, PermissionCache cache,
                               Spi.TokenValidator validator, Spi.AuditSink audit,
                               Metrics metrics, HeaderSanitizer headerSanitizer,
                               Spi.PolicyEngine policyEngine, Spi.AttributeProvider attributeProvider) {
        this.engine = engine;
        this.cache = cache;
        this.validator = validator;
        this.audit = audit;
        this.metrics = metrics;
        this.headerSanitizer = headerSanitizer;
        this.policyEngine = policyEngine;
        this.attributeProvider = attributeProvider;
    }

    /**
     * C3 — Do NOT re-run the filter on the container's ERROR dispatch.
     * When {@code sendError()} is called the servlet container performs an ERROR
     * dispatch to the configured error page. Without this override the filter
     * runs a second time (no credentials present on the error dispatch),
     * potentially clobbering the status or causing a dispatch loop.
     */
    @Override
    protected boolean shouldNotFilterErrorDispatch() {
        return true;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        // B10 — Consume the token headers before stripping so they are still readable here.
        String bearer = extractBearer(request.getHeader("Authorization"));
        String serviceToken = request.getHeader("X-Service-Token");

        // B10 — Defense-in-depth: wrap the response to strip untrusted identity
        // headers from downstream visibility. (Inbound headers on HttpServletRequest
        // are read-only after construction; we sanitize by refusing to forward them.)
        // The sanitized request wrapper exposes the original token headers unmodified
        // while dropping spoofed identity headers for any downstream code that reads
        // the request headers directly.
        HttpServletRequest sanitizedRequest = new SanitizingRequestWrapper(request, headerSanitizer);

        if (bearer == null && serviceToken == null) {
            metrics.inc(Metrics.AUTHZ_FAILURE);
            // C10 — aligned with NestJS message
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "no credentials");
            return;
        }

        Principals.User user = null;
        Principals.Service service = null;
        if (bearer != null) {
            try {
                Map<String, Object> c = validator.validateUserToken(bearer);
                // C12 — treat non-string role claim as absent (null role → DENY)
                Object roleClaim = c.get("role");
                String role = (roleClaim instanceof String s) ? s : null;
                user = new Principals.User(
                        str(c.get("sub")), role, str(c.get("tenant")), str(c.get("jti")));
            } catch (RuntimeException e) {
                // G12 — increment aggregate + mode-specific counter
                metrics.incTokenFailure(Metrics.JWT_VALIDATION_FAILURES,
                        Metrics.classifyTokenFailure(e));
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "user token validation failed");
                return;
            }
        }
        if (serviceToken != null) {
            try {
                Map<String, Object> c = validator.validateServiceToken(serviceToken);
                String name = c.get("service_name") != null ? str(c.get("service_name"))
                        : c.get("azp") != null ? str(c.get("azp")) : str(c.get("client_id"));
                service = new Principals.Service(name, str(c.get("client_id")));
            } catch (RuntimeException e) {
                // G12 — increment aggregate + mode-specific counter
                metrics.incTokenFailure(Metrics.SERVICE_TOKEN_FAILURES,
                        Metrics.classifyTokenFailure(e));
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "service token validation failed");
                return;
            }
        }

        // B10 — Read trace headers from sanitized request wrapper (drops spoofed identity headers)
        RequestContext ctx = RequestContextBuilder.build(
                user, service,
                sanitizedRequest.getHeader("X-Correlation-Id"),
                sanitizedRequest.getHeader("X-Request-Id"));
        request.setAttribute(CONTEXT_ATTR, ctx);
        // Retain the user JWT for outbound propagation (§9); kept off the
        // RequestContext record so the §2.4 schema is unchanged.
        if (bearer != null) request.setAttribute(AuthzRequestContext.USER_JWT_ATTR, bearer);

        // B9 — Strip the servlet context path so the matched path is stable across
        // root and non-root deployments, aligning with NestJS req.path semantics.
        String matchPath = effectivePath(request);

        AuthType authType = ctx.authenticationType();
        Decision decision;
        CompiledRule matchedRule = null;

        if (policyEngine != null) {
            decision = policyEngine.authorize(
                new AuthorizationRequest(request.getMethod(), matchPath,
                        authType, ctx.role(), ctx.serviceName()));
        } else {
            DecisionResult result = engine.evaluate(
                new AuthorizationRequest(request.getMethod(), matchPath,
                        authType, ctx.role(), ctx.serviceName()),
                cache);
            decision = result.decision();
            matchedRule = result.matchedRule();
        }

        String auditPermission = matchedRule != null && matchedRule.hasPermissions()
                ? String.join(",", matchedRule.permissions()) : null;
        audit.emit(AuditEvents.build(ctx, request.getMethod(), matchPath,
                auditPermission, decision, cache.version()));

        if (decision == Decision.ALLOW) {
            metrics.inc(Metrics.AUTHZ_SUCCESS);
            chain.doFilter(sanitizedRequest, response);
        } else {
            metrics.inc(Metrics.PERMISSION_DENIED);
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "authorization denied");
        }
    }

    /**
     * B9 — Returns the request path with the servlet context path stripped, and
     * without any query string. For a root deployment the result equals
     * {@code getRequestURI()}.
     */
    public static String effectivePath(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String ctx = request.getContextPath();
        if (ctx != null && !ctx.isEmpty() && uri.startsWith(ctx)) {
            uri = uri.substring(ctx.length());
        }
        if (uri.isEmpty()) uri = "/";
        return uri;
    }

    private static String extractBearer(String header) {
        if (header == null) return null;
        if (header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return header.substring(7).trim();
        }
        return null;
    }

    private static String str(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    // -------------------------------------------------------------------------
    // B10 — Sanitizing request wrapper
    // -------------------------------------------------------------------------

    /**
     * HttpServletRequest wrapper that returns {@code null} for any header that
     * {@link HeaderSanitizer} classifies as an untrusted identity header.
     * This prevents downstream code from accidentally reading spoofed identity
     * headers that were present on the inbound request.
     *
     * <p>The token headers ({@code Authorization}, {@code X-Service-Token})
     * are explicitly allowed through by the sanitizer and remain readable.
     */
    private static final class SanitizingRequestWrapper
            extends jakarta.servlet.http.HttpServletRequestWrapper {

        private final HeaderSanitizer sanitizer;

        SanitizingRequestWrapper(HttpServletRequest request, HeaderSanitizer sanitizer) {
            super(request);
            this.sanitizer = sanitizer;
        }

        @Override
        public String getHeader(String name) {
            if (name != null && sanitizer.isUntrusted(name)) return null;
            return super.getHeader(name);
        }

        @Override
        public java.util.Enumeration<String> getHeaders(String name) {
            if (name != null && sanitizer.isUntrusted(name))
                return java.util.Collections.emptyEnumeration();
            return super.getHeaders(name);
        }
    }
}
