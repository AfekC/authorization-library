package com.example.authz.autoconfigure;

import com.example.authz.cache.PermissionCache;
import com.example.authz.observability.AuthzHealth;
import com.example.authz.observability.Metrics;
import com.example.authz.spi.Spi;
import com.example.authz.sync.CacheBootstrap;
import com.example.authz.sync.DiskCache;
import com.example.authz.sync.HttpRoleServiceClient;
import com.example.authz.sync.KafkaCacheEventHandler;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;

import java.nio.file.Path;

/**
 * Role-permission distribution machinery (FULL mode only, §0.5): Kafka consumer,
 * the startup state machine (snapshot -> seed fallback -> subscribe -> reconcile),
 * the cache health indicator, and the default cache-backed role resolver.
 */
@AutoConfiguration(after = AuthzCoreAutoConfiguration.class)
public class CacheSyncAutoConfiguration {

    @Bean
    @Conditional(OnUserAuthEnabled.class)
    @ConditionalOnMissingBean(Spi.CacheEventHandler.class)
    public Spi.CacheEventHandler authzKafkaEventHandler(AuthzProperties props) {
        if (props.getKafkaBrokers() == null || props.getKafkaBrokers().isEmpty()) {
            return null;
        }
        return new KafkaCacheEventHandler(props.getKafkaBrokers(),
                props.getRoleUpdatesTopic(), props.getRoleDeleteTopic(),
                props.getPublishRolesTopic(), props.getKafkaGroupId(), props.getKafkaClientId());
    }

    @Bean(destroyMethod = "stop")
    @Conditional(OnUserAuthEnabled.class)
    @ConditionalOnMissingBean
    public CacheBootstrap cacheBootstrap(PermissionCache cache, Metrics metrics, AuthzProperties props,
                                         ObjectProvider<Spi.CacheEventHandler> events) {
        CacheBootstrap boot = new CacheBootstrap(
                cache,
                new HttpRoleServiceClient(
                    props.getRoleServiceUrl(),
                    props.getRoleServiceConnectTimeout(),
                    props.getRoleServiceReadTimeout()),
                new DiskCache(Path.of(props.getDiskCachePath())),
                events.getIfAvailable(),
                metrics);
        CacheBootstrap.Mode mode = boot.start();
        boot.startSeedRetry();
        boot.startReconciler(props.getReconcileIntervalMs());
        org.slf4j.LoggerFactory.getLogger(CacheSyncAutoConfiguration.class)
                .info("authz cache started in {} mode", mode);
        return boot;
    }

    @Bean
    @Conditional(OnUserAuthEnabled.class)
    @ConditionalOnMissingBean
    public AuthzHealth authzHealth(PermissionCache cache, CacheBootstrap bootstrap) {
        return new AuthzHealth(cache, bootstrap);
    }

    @Bean
    @Conditional(OnUserAuthEnabled.class)
    @ConditionalOnMissingBean
    public Spi.RoleResolver authzRoleResolver(PermissionCache cache) {
        return cache::permissionsForRole;
    }
}
