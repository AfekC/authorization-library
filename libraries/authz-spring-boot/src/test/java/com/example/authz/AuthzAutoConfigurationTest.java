package com.example.authz;

import com.example.authz.boot.AuthzAutoConfiguration;
import com.example.authz.boot.AuthzProperties;
import com.example.authz.cache.PermissionCache;
import com.example.authz.config.ConfigException;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
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

    @Test
    void authzO11yCompatibilityBindingIsConfigured() throws Exception {
        Class<?> bindingClass = Class.forName("com.example.authz.boot.AuthzAutoConfiguration$O11yCompatibilityBinding");
        assertNotNull(bindingClass.getAnnotation(org.springframework.context.annotation.Configuration.class));
        assertNotNull(bindingClass.getAnnotation(org.springframework.boot.autoconfigure.condition.ConditionalOnClass.class));

        Method method = bindingClass.getDeclaredMethod("authzO11yConfigurationUtil");
        assertNotNull(method.getAnnotation(ConditionalOnMissingBean.class));
        assertEquals("idf.hatraa.util.ConfigurationUtil", method.getReturnType().getName());
    }

    /**
     * Mimics o11y-lib's {@code ObservabilityAutoConfiguration}, which field-injects
     * an {@code idf.hatraa.util.ConfigurationUtil}. o11y-lib declares that type as a
     * {@code @Component} outside the consuming app's component-scan path, so it is
     * only available when {@link AuthzAutoConfiguration.O11yCompatibilityBinding}
     * contributes it. This consumer fails to wire if the bean is absent.
     */
    @Configuration(proxyBeanMethods = false)
    static class O11yConsumerConfig {
        @Bean
        String dependsOnConfigurationUtil(idf.hatraa.util.ConfigurationUtil util) {
            return "wired:" + (util != null);
        }
    }

    @Test
    void o11yCompatibilityBinding_suppliesConfigurationUtilForO11yConsumer() throws Exception {
        Class<?> binding = Class.forName(
                "com.example.authz.boot.AuthzAutoConfiguration$O11yCompatibilityBinding");
        new ApplicationContextRunner()
                .withBean(SimpleMeterRegistry.class) // ConfigurationUtil @Autowires a MeterRegistry
                .withUserConfiguration(binding, O11yConsumerConfig.class)
                .run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    assertThat(ctx).hasSingleBean(idf.hatraa.util.ConfigurationUtil.class);
                    assertThat(ctx).hasBean("dependsOnConfigurationUtil");
                });
    }

    @Test
    void withoutBinding_o11yConsumerFails_reproducingStartupError() {
        // Reproduces the original failure: no ConfigurationUtil bean → UnsatisfiedDependency.
        new ApplicationContextRunner()
                .withBean(SimpleMeterRegistry.class)
                .withUserConfiguration(O11yConsumerConfig.class)
                .run(ctx -> assertThat(ctx).hasFailed());
    }
}
