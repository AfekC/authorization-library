package com.example.authz.autoconfigure;

import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Matches when user auth is enabled (FULL mode, §0.5). Gates the entire
 * role-permission machinery so it is absent in SERVICE-ONLY mode.
 */
public class OnUserAuthEnabled implements Condition {
    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        AuthzProperties p = Binder.get(context.getEnvironment())
                .bind("authz", AuthzProperties.class)
                .orElseGet(AuthzProperties::new);
        return p.isUserAuthEnabled();
    }
}
