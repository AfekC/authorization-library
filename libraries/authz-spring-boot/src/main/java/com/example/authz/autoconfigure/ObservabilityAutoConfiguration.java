package com.example.authz.autoconfigure;

import com.example.authz.audit.LoggingAuditSink;
import com.example.authz.observability.Metrics;
import com.example.authz.spi.Spi;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Observability beans: the in-process Metrics registry, optional Micrometer
 * mirroring, the o11y-lib compatibility util, and the default audit sink.
 * Declared before the in-house ObservabilityAutoConfiguration so the Metrics
 * bean exists when that starter wires its registry.
 */
@AutoConfiguration(after = AuthzCoreAutoConfiguration.class,
        beforeName = "idf.hatraa.ObservabilityAutoConfiguration")
public class ObservabilityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public Metrics authzMetrics() {
        return new Metrics();
    }

    @Bean
    @ConditionalOnMissingBean
    public Spi.AuditSink authzAuditSink() {
        return new LoggingAuditSink();
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(io.micrometer.core.instrument.MeterRegistry.class)
    static class MicrometerMetricsBinding {
        @Bean
        InitializingBean authzMetricsMicrometerBinder(
                Metrics metrics,
                ObjectProvider<io.micrometer.core.instrument.MeterRegistry> registry) {
            return () -> {
                io.micrometer.core.instrument.MeterRegistry reg = registry.getIfAvailable();
                if (reg != null) {
                    java.util.concurrent.ConcurrentHashMap<String, io.micrometer.core.instrument.Counter> counters =
                            new java.util.concurrent.ConcurrentHashMap<>();
                    java.util.concurrent.ConcurrentHashMap<String, java.util.concurrent.atomic.AtomicLong> gauges =
                            new java.util.concurrent.ConcurrentHashMap<>();
                    metrics.addSink(new Metrics.Sink() {
                        @Override
                        public void incrementCounter(String name) {
                            counters.computeIfAbsent(name, reg::counter).increment();
                        }
                        @Override
                        public void setGauge(String name, long value) {
                            java.util.concurrent.atomic.AtomicLong holder = gauges.computeIfAbsent(name, k -> {
                                java.util.concurrent.atomic.AtomicLong a = new java.util.concurrent.atomic.AtomicLong();
                                io.micrometer.core.instrument.Gauge
                                        .builder(name, a, java.util.concurrent.atomic.AtomicLong::doubleValue)
                                        .register(reg);
                                return a;
                            });
                            holder.set(value);
                        }
                    });
                }
            };
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "idf.hatraa.util.ConfigurationUtil")
    static class O11yCompatibilityBinding {
        @Bean
        @ConditionalOnMissingBean
        idf.hatraa.util.ConfigurationUtil authzO11yConfigurationUtil() {
            return new idf.hatraa.util.ConfigurationUtil();
        }
    }
}
