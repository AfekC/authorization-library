package com.example.authz.sync;

import org.apache.avro.generic.GenericRecord;
import org.apache.avro.util.Utf8;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Library-owned {@code @KafkaListener} that receives role change events from Kafka.
 *
 * <p>All Kafka connection config (brokers, schema-registry URL, deserializer) is
 * supplied by the host service via {@code spring.kafka.consumer.*} properties.
 * This component binds Spring Boot's default {@code kafkaListenerContainerFactory}
 * and does NOT configure brokers, deserializer, or schema-registry.
 *
 * <p>Group IDs are generated per-instance (UUID suffix) so every replica receives
 * every event (broadcast fan-out). Topic names are resolved from
 * {@code authz.kafka.*-topic} with library defaults as fallbacks.
 */
@Component
public class RoleEventKafkaListener {
    private static final Logger LOG = LoggerFactory.getLogger(RoleEventKafkaListener.class);

    private final CacheBootstrap cacheBootstrap;

    public RoleEventKafkaListener(CacheBootstrap cacheBootstrap) {
        this.cacheBootstrap = cacheBootstrap;
    }

    @KafkaListener(
            topics = "${authz.kafka.role-updates-topic:role-updates}",
            groupId = "authz-cache-sync-#{T(java.util.UUID).randomUUID()}")
    public void onUpsert(GenericRecord record) {
        if (record == null) {
            LOG.warn("received null GenericRecord on upsert topic; skipping");
            return;
        }
        String roleId = asString(record.get("roleId"));
        List<String> permissions = asStringList(record.get("permissions"));
        Long version = asLong(record.get("version"));
        cacheBootstrap.applyUpsert(new RoleUpsertEvent(roleId, permissions, version));
    }

    @KafkaListener(
            topics = "${authz.kafka.role-delete-topic:role-delete}",
            groupId = "authz-cache-sync-#{T(java.util.UUID).randomUUID()}")
    public void onDelete(GenericRecord record) {
        if (record == null) {
            LOG.warn("received null GenericRecord on delete topic; skipping");
            return;
        }
        String roleId = asString(record.get("roleId"));
        Long version = asLong(record.get("version"));
        cacheBootstrap.applyDelete(new RoleDeleteEvent(roleId, version));
    }

    @KafkaListener(
            topics = "${authz.kafka.publish-roles-topic:publish-roles}",
            groupId = "authz-cache-sync-#{T(java.util.UUID).randomUUID()}")
    public void onForcedRefresh() {
        cacheBootstrap.forcedRefresh();
    }

    // --- mapping helpers ---

    private static String asString(Object value) {
        if (value == null) return null;
        // Avro strings are Utf8; toString() gives the plain Java string.
        return value.toString();
    }

    @SuppressWarnings("unchecked")
    private static List<String> asStringList(Object value) {
        if (value == null) return List.of();
        if (value instanceof Collection<?> col) {
            List<String> result = new ArrayList<>(col.size());
            for (Object item : col) {
                result.add(item == null ? "" : String.valueOf(item));
            }
            return result;
        }
        return List.of();
    }

    private static Long asLong(Object value) {
        if (value == null) return null;
        if (value instanceof Number n) return n.longValue();
        if (value instanceof String s) {
            try { return Long.parseLong(s.trim()); } catch (NumberFormatException ignored) {}
        }
        return null;
    }
}
