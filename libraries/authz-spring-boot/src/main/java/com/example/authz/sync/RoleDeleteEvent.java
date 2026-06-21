package com.example.authz.sync;

/**
 * DTO for a role-delete Kafka event (Avro wire format).
 * Constructed by {@link RoleEventKafkaListener} from a {@code GenericRecord}.
 */
public record RoleDeleteEvent(String roleId, Long version) {}
