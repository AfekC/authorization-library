package com.example.authz.autoconfigure;

import com.example.authz.cache.PermissionCache;
import com.example.authz.observability.AuthzHealth;
import com.example.authz.observability.Metrics;
import com.example.authz.spi.Spi;
import com.example.authz.sync.CacheBootstrap;
import com.example.authz.sync.DiskCache;
import com.example.authz.sync.HttpRoleServiceClient;
import com.example.authz.sync.RoleEventKafkaListener;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.kafka.annotation.KafkaListener;

import java.nio.file.Path;

/**
 * Role-permission distribution machinery (FULL mode only, §0.5):
 * the startup state machine (snapshot -> seed fallback -> reconcile),
 * the cache health indicator, the default cache-backed role resolver,
 * and the {@code @KafkaListener} component that drives incremental cache updates.
 *
 * <p>Kafka connection config (brokers, deserializer, schema-registry) is owned
 * by the host service via {@code spring.kafka.consumer.*} properties.
 */
@AutoConfiguration(after = AuthzCoreAutoConfiguration.class)
public class CacheSyncAutoConfiguration {

    @Bean(destroyMethod = "stop")
    @Conditional(OnUserAuthEnabled.class)
    @ConditionalOnMissingBean
    public CacheBootstrap cacheBootstrap(PermissionCache cache, Metrics metrics, AuthzProperties props) {
        CacheBootstrap boot = new CacheBootstrap(
                cache,
                new HttpRoleServiceClient(
                    props.getRoleServiceUrl(),
                    props.getRoleServiceConnectTimeout(),
                    props.getRoleServiceReadTimeout()),
                new DiskCache(Path.of(props.getDiskCachePath())),
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
    @ConditionalOnClass(KafkaListener.class)
    public RoleEventKafkaListener roleEventKafkaListener(CacheBootstrap cacheBootstrap) {
        return new RoleEventKafkaListener(cacheBootstrap);
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
