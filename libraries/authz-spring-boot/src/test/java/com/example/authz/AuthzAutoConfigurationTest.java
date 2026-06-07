package com.example.authz;

import com.example.authz.boot.AuthzAutoConfiguration;
import com.example.authz.boot.AuthzProperties;
import com.example.authz.cache.PermissionCache;
import com.example.authz.config.ConfigException;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

class AuthzAutoConfigurationTest {

    private static void validate(AuthzProperties props) {
        try {
            Class<?> clazz = Class.forName("com.example.authz.boot.AuthzAutoConfiguration$ConfigValidator");
            Constructor<?> ctor = clazz.getDeclaredConstructor(AuthzProperties.class);
            ctor.setAccessible(true);
            ctor.newInstance(props);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) throw re;
            throw new RuntimeException(e.getCause());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void configValidator_throwsWhenUserIssuerMissing() {
        AuthzProperties props = new AuthzProperties();
        props.setUserIssuer(null);
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(props));
        assertEquals("authz.user-issuer must be configured", ex.getMessage());
    }

    @Test
    void configValidator_throwsWhenUserIssuerBlank() {
        AuthzProperties props = new AuthzProperties();
        props.setUserIssuer(" ");
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(props));
        assertEquals("authz.user-issuer must be configured", ex.getMessage());
    }

    @Test
    void configValidator_throwsWhenUserJwksUriMissing() {
        AuthzProperties props = new AuthzProperties();
        props.setUserIssuer("https://auth.example.com");
        props.setUserJwksUri(null);
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(props));
        assertEquals("authz.user-jwks-uri must be configured", ex.getMessage());
    }

    @Test
    void configValidator_throwsWhenServiceIssuerMissing() {
        AuthzProperties props = new AuthzProperties();
        props.setUserIssuer("https://auth.example.com");
        props.setUserJwksUri("https://auth.example.com/.well-known/jwks.json");
        props.setServiceIssuer(null);
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(props));
        assertEquals("authz.service-issuer must be configured", ex.getMessage());
    }

    @Test
    void configValidator_throwsWhenServiceJwksUriMissing() {
        AuthzProperties props = new AuthzProperties();
        props.setUserIssuer("https://auth.example.com");
        props.setUserJwksUri("https://auth.example.com/.well-known/jwks.json");
        props.setServiceIssuer("https://sso.example.com");
        props.setServiceJwksUri(null);
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(props));
        assertEquals("authz.service-jwks-uri must be configured", ex.getMessage());
    }

    @Test
    void configValidator_throwsWhenRoleServiceUrlMissing() {
        AuthzProperties props = new AuthzProperties();
        props.setUserIssuer("https://auth.example.com");
        props.setUserJwksUri("https://auth.example.com/.well-known/jwks.json");
        props.setServiceIssuer("https://sso.example.com");
        props.setServiceJwksUri("https://sso.example.com/.well-known/jwks.json");
        props.setRoleServiceUrl(null);
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(props));
        assertEquals("authz.role-service-url must be configured", ex.getMessage());
    }

    @Test
    void configValidator_throwsWhenAudienceMissing() {
        AuthzProperties props = new AuthzProperties();
        props.setUserIssuer("https://auth.example.com");
        props.setUserJwksUri("https://auth.example.com/.well-known/jwks.json");
        props.setServiceIssuer("https://sso.example.com");
        props.setServiceJwksUri("https://sso.example.com/.well-known/jwks.json");
        props.setRoleServiceUrl("http://role-service:8080");
        props.setAudience(null);
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(props));
        assertEquals("authz.audience must be configured", ex.getMessage());
    }

    @Test
    void configValidator_throwsWhenAudienceBlank() {
        AuthzProperties props = new AuthzProperties();
        props.setUserIssuer("https://auth.example.com");
        props.setUserJwksUri("https://auth.example.com/.well-known/jwks.json");
        props.setServiceIssuer("https://sso.example.com");
        props.setServiceJwksUri("https://sso.example.com/.well-known/jwks.json");
        props.setRoleServiceUrl("http://role-service:8080");
        props.setAudience(" ");
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(props));
        assertEquals("authz.audience must be configured", ex.getMessage());
    }

    @Test
    void configValidator_passesWhenAllPropertiesValid() {
        AuthzProperties props = new AuthzProperties();
        props.setUserIssuer("https://auth.example.com");
        props.setUserJwksUri("https://auth.example.com/.well-known/jwks.json");
        props.setServiceIssuer("https://sso.example.com");
        props.setServiceJwksUri("https://sso.example.com/.well-known/jwks.json");
        props.setRoleServiceUrl("http://role-service:8080");
        props.setAudience("my-service");
        assertDoesNotThrow(() -> validate(props));
    }

    @Test
    void metricsBeanHasConditionalOnMissingBean() throws Exception {
        Method method = AuthzAutoConfiguration.class.getDeclaredMethod("authzMetrics");
        assertNotNull(method.getAnnotation(ConditionalOnMissingBean.class));
    }

    @Test
    void permissionCacheBeanHasConditionalOnMissingBean() throws Exception {
        Method method = AuthzAutoConfiguration.class.getDeclaredMethod("permissionCache");
        assertNotNull(method.getAnnotation(ConditionalOnMissingBean.class));
    }

    @Test
    void authorizationEngineBeanHasConditionalOnMissingBean() throws Exception {
        Method method = AuthzAutoConfiguration.class.getDeclaredMethod(
                "authorizationEngine", AuthzProperties.class, ApplicationContext.class);
        assertNotNull(method.getAnnotation(ConditionalOnMissingBean.class));
    }

    @Test
    void permissionCacheBeanIsCreated() {
        PermissionCache cache = new AuthzAutoConfiguration().permissionCache();
        assertNotNull(cache);
    }
}
