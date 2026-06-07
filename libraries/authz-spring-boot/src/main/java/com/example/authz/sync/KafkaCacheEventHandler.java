package com.example.authz.sync;

import com.example.authz.spi.Spi;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.listener.ContainerProperties;
import org.springframework.kafka.listener.KafkaMessageListenerContainer;
import org.springframework.kafka.listener.MessageListener;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * Kafka consumer for role change events (architecture §7.2/§8.2), backed by a
 * spring-kafka {@link KafkaMessageListenerContainer}. Three topics: `role-updates`
 * (upserts) and `role-delete` (deletes) for incremental changes, and `publish-roles`
 * as a forced-refresh trigger. The wire message carries only `roleId`
 * (+ `permissions`); the operation is derived from which topic delivered it. The
 * container owns the consumer thread, poll loop, and lifecycle.
 */
public class KafkaCacheEventHandler implements Spi.CacheEventHandler {
    private static final Logger LOG = LoggerFactory.getLogger(KafkaCacheEventHandler.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final List<String> brokers;
    private final String updatesTopic;
    private final String deleteTopic;
    private final String publishTopic;
    private final String groupId;
    private final String clientId;
    private KafkaMessageListenerContainer<String, String> container;

    public KafkaCacheEventHandler(List<String> brokers, String updatesTopic, String deleteTopic,
                                  String publishTopic, String groupId, String clientId) {
        this.brokers = brokers;
        this.updatesTopic = updatesTopic != null ? updatesTopic : "role-updates";
        this.deleteTopic = deleteTopic != null ? deleteTopic : "role-delete";
        this.publishTopic = publishTopic != null ? publishTopic : "publish-roles";
        this.groupId = groupId != null ? groupId : "authz-cache-sync";
        this.clientId = clientId != null ? clientId : "authz-cache-sync";
    }

    @Override
    public void start(Consumer<Map<String, Object>> onEvent, Runnable onRefresh) {
        Map<String, Object> props = new HashMap<>();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, String.join(",", brokers));
        props.put(ConsumerConfig.GROUP_ID_CONFIG, groupId + "-" + UUID.randomUUID());
        props.put(ConsumerConfig.CLIENT_ID_CONFIG, clientId + "-" + UUID.randomUUID());
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "latest");
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, true);

        DefaultKafkaConsumerFactory<String, String> consumerFactory =
                new DefaultKafkaConsumerFactory<>(props);
        ContainerProperties containerProps = new ContainerProperties(updatesTopic, deleteTopic, publishTopic);
        containerProps.setMessageListener((MessageListener<String, String>) record -> {
            if (record.topic().equals(publishTopic)) {
                onRefresh.run();
                return;
            }
            Map<String, Object> event = parse(record.value());
            if (event == null) return;
            // Operation is implied by the source topic, not carried on the wire (E1).
            // C9: if the message payload already carries an 'operation' field, save it
            // under the internal key so RoleEvents.apply can cross-check for conflicts.
            String topicOperation = record.topic().equals(deleteTopic) ? "DELETE_ROLE" : "UPSERT_ROLE";
            Object wireOperation = event.get("operation");
            if (wireOperation instanceof String wireOp) {
                // Preserve the wire value for conflict detection; log a warning now
                // if it already differs from the topic-derived operation.
                event.put(RoleEvents.WIRE_OPERATION_KEY, wireOp);
                if (!wireOp.equals(topicOperation)) {
                    LOG.warn("role event operation field mismatch: topic-derived={} wire-field={}; " +
                             "event will be skipped by RoleEvents.apply", topicOperation, wireOp);
                }
            }
            event.put("operation", topicOperation);
            onEvent.accept(event);
        });

        container = new KafkaMessageListenerContainer<>(consumerFactory, containerProps);
        container.setBeanName("authz-role-events");
        container.start();
        LOG.info("subscribed to Kafka topics '{}','{}','{}' on {}", updatesTopic, deleteTopic, publishTopic, brokers);
    }

    public Map<String, Object> parse(String value) {
        if (value == null) return null;
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> event = MAPPER.readValue(value, Map.class);
            return event;
        } catch (Exception e) {
            LOG.warn("skipping unparseable role event");
            return null;
        }
    }

    @Override
    public void stop() {
        if (container != null) container.stop();
    }
}
