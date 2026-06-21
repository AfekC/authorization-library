package com.example.authz;

import com.example.authz.autoconfigure.AuthzCoreAutoConfiguration;
import com.example.authz.autoconfigure.CacheSyncAutoConfiguration;
import com.example.authz.autoconfigure.ObservabilityAutoConfiguration;
import com.example.authz.autoconfigure.AuthzProperties;
import com.example.authz.cache.PermissionCache;
import com.example.authz.config.ConfigException;
import com.example.authz.observability.AuthzHealth;
import com.example.authz.observability.Metrics;
import com.example.authz.sync.CacheBootstrap;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

class AuthzAutoConfigurationTest {

    private static void validate(AuthzProperties props) {
        try {
            Class<?> clazz = Class.forName("com.example.authz.autoconfigure.AuthzCoreAutoConfiguration$ConfigValidator");
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

    /** Service auth (always required) on a fresh props object. */
    private static AuthzProperties serviceAuthValid() {
        AuthzProperties props = new AuthzProperties();
        props.setServiceIssuer("https://sso.example.com");
        props.setServiceJwksUri("https://sso.example.com/.well-known/jwks.json");
        return props;
    }

    /** Add a complete, valid user-auth block (FULL mode). */
    private static void withUserAuth(AuthzProperties props) {
        props.setUserIssuer("https://auth.example.com");
        props.setUserJwksUri("https://auth.example.com/.well-known/jwks.json");
        props.setAudience("my-service");
        props.setRoleServiceUrl("http://role-service:8080");
    }

    // ---- Service auth is always required (both modes) -----------------------

    @Test
    void configValidator_throwsWhenServiceIssuerMissing() {
        AuthzProperties props = new AuthzProperties(); // nothing set
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(props));
        assertEquals("authz.service-issuer must be configured", ex.getMessage());
    }

    @Test
    void configValidator_throwsWhenServiceJwksUriMissing() {
        AuthzProperties props = new AuthzProperties();
        props.setServiceIssuer("https://sso.example.com");
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(props));
        assertEquals("authz.service-jwks-uri must be configured", ex.getMessage());
    }

    // ---- SERVICE-ONLY mode: no user-auth block is valid (§0.5) --------------

    @Test
    void configValidator_passesInServiceOnlyMode() {
        AuthzProperties props = serviceAuthValid(); // no user-auth fields
        assertFalse(props.isUserAuthEnabled());
        assertDoesNotThrow(() -> validate(props));
    }

    // ---- FULL mode: user auth is all-or-nothing (§3.3) ----------------------

    @Test
    void configValidator_throwsWhenUserIssuerMissing() {
        AuthzProperties props = serviceAuthValid();
        // user auth implied by jwks-uri but issuer missing
        props.setUserJwksUri("https://auth.example.com/.well-known/jwks.json");
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(props));
        assertEquals("authz.user.issuer must be configured when user auth is enabled", ex.getMessage());
    }

    @Test
    void configValidator_throwsWhenUserJwksUriMissing() {
        AuthzProperties props = serviceAuthValid();
        props.setUserIssuer("https://auth.example.com");
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(props));
        assertEquals("authz.user.jwks-uri must be configured when user auth is enabled", ex.getMessage());
    }

    @Test
    void configValidator_throwsWhenAudienceMissing() {
        AuthzProperties props = serviceAuthValid();
        props.setUserIssuer("https://auth.example.com");
        props.setUserJwksUri("https://auth.example.com/.well-known/jwks.json");
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(props));
        assertEquals("authz.user.audience must be configured when user auth is enabled", ex.getMessage());
    }

    @Test
    void configValidator_throwsWhenRoleServiceUrlMissing() {
        AuthzProperties props = serviceAuthValid();
        props.setUserIssuer("https://auth.example.com");
        props.setUserJwksUri("https://auth.example.com/.well-known/jwks.json");
        props.setAudience("my-service");
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(props));
        assertEquals("authz.role-service-url must be configured when user auth is enabled", ex.getMessage());
    }

    @Test
    void configValidator_passesWhenAllPropertiesValid() {
        AuthzProperties props = serviceAuthValid();
        withUserAuth(props);
        assertTrue(props.isUserAuthEnabled());
        assertDoesNotThrow(() -> validate(props));
    }

    // ---- Explicit service-only mode (§0.5) ----------------------------------

    @Test
    void serviceOnlyFlag_disablesUserAuth() {
        AuthzProperties props = serviceAuthValid();
        props.setServiceOnly(true);
        assertFalse(props.isUserAuthEnabled());
        assertDoesNotThrow(() -> validate(props));
    }

    @Test
    void configValidator_throwsWhenServiceOnlyCombinedWithUserAuth() {
        AuthzProperties props = serviceAuthValid();
        props.setServiceOnly(true);
        props.setUserIssuer("https://auth.example.com");
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(props));
        assertEquals(
                "authz.service-only cannot be combined with user-auth properties or authz.external-permission-source",
                ex.getMessage());
    }

    @Test
    void configValidator_throwsWhenServiceOnlyCombinedWithExternalSource() {
        AuthzProperties props = serviceAuthValid();
        props.setServiceOnly(true);
        props.setExternalPermissionSource(true);
        assertThrows(ConfigException.class, () -> validate(props));
    }

    // ---- External permission source mode (§0.5b) ----------------------------

    @Test
    void configValidator_passesInExternalModeWithoutRoleServiceUrl() {
        AuthzProperties props = serviceAuthValid();
        props.setUserIssuer("https://auth.example.com");
        props.setUserJwksUri("https://auth.example.com/.well-known/jwks.json");
        props.setAudience("my-service");
        props.setExternalPermissionSource(true); // no role-service-url required
        assertTrue(props.isUserAuthEnabled());
        assertDoesNotThrow(() -> validate(props));
    }

    @Test
    void authzHealth_worksWithoutBootstrap() {
        // External mode: no CacheBootstrap bean — health must report cache-only.
        AuthzHealth.Report report = new AuthzHealth(new PermissionCache(), null).report();
        assertEquals("empty", report.cacheStatus());
        assertEquals(CacheBootstrap.Mode.NORMAL.name(), report.mode());
        assertNull(report.roleServiceLastSync());
        assertFalse(report.kafkaConsumerConnected());
    }

    @Test
    void configValidator_stillRequiresUserAuthFieldsInExternalMode() {
        // External mode disables role distribution but keeps user-JWT validation,
        // so the user-auth block is still all-or-nothing.
        AuthzProperties props = serviceAuthValid();
        props.setUserIssuer("https://auth.example.com");
        props.setUserJwksUri("https://auth.example.com/.well-known/jwks.json");
        props.setExternalPermissionSource(true); // audience still missing
        ConfigException ex = assertThrows(ConfigException.class, () -> validate(props));
        assertEquals("authz.user.audience must be configured when user auth is enabled", ex.getMessage());
    }

    @Test
    void authzHealthFactoryToleratesAbsentBootstrap() {
        // Mirrors external mode, where no CacheBootstrap bean exists.
        ObjectProvider<CacheBootstrap> noBootstrap = new ObjectProvider<>() {
            @Override public CacheBootstrap getObject() { throw new UnsupportedOperationException(); }
            @Override public CacheBootstrap getObject(Object... args) { throw new UnsupportedOperationException(); }
            @Override public CacheBootstrap getIfAvailable() { return null; }
            @Override public CacheBootstrap getIfUnique() { return null; }
        };
        AuthzHealth health = new CacheSyncAutoConfiguration().authzHealth(new PermissionCache(), noBootstrap);
        assertEquals(CacheBootstrap.Mode.NORMAL.name(), health.report().mode());
        assertNull(health.report().roleServiceLastSync());
    }

    @Test
    void cacheBootstrapBeanIsGatedOnExternalPermissionSource() throws Exception {
        Method method = CacheSyncAutoConfiguration.class.getDeclaredMethod(
                "cacheBootstrap", PermissionCache.class, Metrics.class, AuthzProperties.class);
        ConditionalOnProperty cond = method.getAnnotation(ConditionalOnProperty.class);
        assertNotNull(cond);
        assertEquals("false", cond.havingValue());
        assertTrue(cond.matchIfMissing());
    }

    @Test
    void kafkaListenerAndDefaultResolverGatedOnExternalPermissionSource() throws Exception {
        Method listener = CacheSyncAutoConfiguration.class.getDeclaredMethod(
                "roleEventKafkaListener", CacheBootstrap.class);
        assertNotNull(listener.getAnnotation(ConditionalOnProperty.class));
        Method resolver = CacheSyncAutoConfiguration.class.getDeclaredMethod(
                "authzRoleResolver", PermissionCache.class);
        assertNotNull(resolver.getAnnotation(ConditionalOnProperty.class));
    }

    @Test
    void authzHealthBeanInjectsBootstrapViaObjectProvider() throws Exception {
        // Tolerates the absent CacheBootstrap in external mode.
        assertNotNull(CacheSyncAutoConfiguration.class.getDeclaredMethod(
                "authzHealth", PermissionCache.class, ObjectProvider.class));
    }

    @Test
    void metricsBeanHasConditionalOnMissingBean() throws Exception {
        Method method = ObservabilityAutoConfiguration.class.getDeclaredMethod("authzMetrics");
        assertNotNull(method.getAnnotation(ConditionalOnMissingBean.class));
    }

    @Test
    void permissionCacheBeanHasConditionalOnMissingBean() throws Exception {
        Method method = AuthzCoreAutoConfiguration.class.getDeclaredMethod("permissionCache");
        assertNotNull(method.getAnnotation(ConditionalOnMissingBean.class));
    }

    @Test
    void authorizationEngineBeanHasConditionalOnMissingBean() throws Exception {
        Method method = AuthzCoreAutoConfiguration.class.getDeclaredMethod(
                "authorizationEngine", AuthzProperties.class, ApplicationContext.class);
        assertNotNull(method.getAnnotation(ConditionalOnMissingBean.class));
    }

    @Test
    void permissionCacheBeanIsCreated() {
        PermissionCache cache = new AuthzCoreAutoConfiguration().permissionCache();
        assertNotNull(cache);
    }
}
