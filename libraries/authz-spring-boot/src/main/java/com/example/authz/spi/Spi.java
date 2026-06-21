package com.example.authz.spi;

import com.example.authz.engine.AuthorizationRequest;
import com.example.authz.engine.Decision;

import java.util.List;
import java.util.Map;
import java.util.Set;


/** Extension interfaces (architecture §11). Swap implementations without touching auth logic. */
public final class Spi {
    private Spi() {}

    /** Validates user JWTs and service tokens against trusted JWKS. */
    public interface TokenValidator {
        Map<String, Object> validateUserToken(String jwt);
        Map<String, Object> validateServiceToken(String jwt);
    }

    /** Acquires this service's outbound identity token. */
    public interface ServiceIdentityProvider {
        String getServiceToken();
    }

    /** Resolves a role to its permission set. */
    public interface RoleResolver {
        Set<String> permissionsForRole(String role);
    }

    /** Decides ALLOW/DENY for a request. */
    public interface PolicyEngine {
        Decision authorize(AuthorizationRequest request);
    }

    /** Supplies extra attributes for future ABAC policies. */
    public interface AttributeProvider {
        Map<String, Object> attributesFor(com.example.authz.context.RequestContext ctx);
    }

    /**
     * Authoritative full role state: a bare {@code roleId -> permissions} map
     * (`GET /roles`). No envelope, no version — the reconciler re-fetches and
     * replaces the whole map each cycle.
     */
    public interface RoleServiceClient {
        Map<String, List<String>> fetchSnapshot();
    }

    /** Audit sink for per-decision events. */
    public interface AuditSink {
        void emit(com.example.authz.audit.AuditEvent event);
    }
}
