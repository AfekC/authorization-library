package com.example.authz.web;

import com.example.authz.context.RequestContext;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

/**
 * Request-scoped holder exposing the authenticated {@link RequestContext} plus
 * the raw user JWT for the in-flight request (architecture §12.1). App code can
 * inject this bean; the outbound interceptor reads {@link #current()} to attach
 * propagation headers. The user JWT is intentionally kept here, not on the
 * {@link RequestContext} record, so the §2.4 schema is unchanged.
 */
public class AuthzRequestContext {
    public static final String CONTEXT_ATTR = "authzRequestContext";
    public static final String USER_JWT_ATTR = "authzUserJwt";

    private final RequestContext context;
    private final String userJwt;

    public AuthzRequestContext(RequestContext context, String userJwt) {
        this.context = context;
        this.userJwt = userJwt;
    }

    public RequestContext context() { return context; }
    public String userJwt() { return userJwt; }

    /**
     * The holder for the in-flight request, or null when there is no web request
     * bound or the request has not been authenticated yet. Reads the servlet
     * request attributes set by {@link AuthorizationFilter}.
     */
    public static AuthzRequestContext current() {
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        if (attrs == null) return null;
        Object ctx = attrs.getAttribute(CONTEXT_ATTR, RequestAttributes.SCOPE_REQUEST);
        if (!(ctx instanceof RequestContext rc)) return null;
        Object jwt = attrs.getAttribute(USER_JWT_ATTR, RequestAttributes.SCOPE_REQUEST);
        return new AuthzRequestContext(rc, jwt instanceof String s ? s : null);
    }
}
