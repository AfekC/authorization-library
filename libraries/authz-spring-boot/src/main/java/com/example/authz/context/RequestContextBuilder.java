package com.example.authz.context;

import com.example.authz.engine.AuthType;

import java.util.UUID;

/** Builds the RequestContext from validated principals + opaque trace ids. */
public final class RequestContextBuilder {
    private RequestContextBuilder() {}

    public static RequestContext build(Principals.User user, Principals.Service service,
                                       String correlationId, String requestId) {
        AuthType authType;
        if (user != null && service != null) authType = AuthType.USER_AND_SERVICE;
        else if (service != null) authType = AuthType.SERVICE;
        else authType = AuthType.USER;

        return new RequestContext(
                user != null ? user.userId() : null,
                user != null ? user.role() : null,
                user != null ? user.tenant() : null,
                service != null ? service.serviceName() : null,
                service != null ? service.serviceId() : null,
                (requestId != null && !requestId.isBlank()) ? requestId : UUID.randomUUID().toString(),
                (correlationId != null && !correlationId.isBlank()) ? correlationId : UUID.randomUUID().toString(),
                authType,
                user != null ? user.jwtId() : null);
    }
}
