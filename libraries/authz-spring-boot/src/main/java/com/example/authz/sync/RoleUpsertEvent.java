package com.example.authz.sync;

import java.util.List;

/**
 * DTO for a role-upsert Kafka event (Avro wire format).
 * Constructed by {@link RoleEventKafkaListener} from a {@code GenericRecord}.
 */
public record RoleUpsertEvent(String roleId, List<String> permissions, Long version) {}
