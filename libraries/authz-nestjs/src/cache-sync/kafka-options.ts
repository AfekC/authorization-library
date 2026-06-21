import { randomUUID } from "node:crypto";
import { Transport, type MicroserviceOptions } from "@nestjs/microservices";
import { SchemaRegistry } from "@kafkajs/confluent-schema-registry";

export interface AuthzKafkaOptionsInput {
  /** Kafka broker addresses, e.g. `["localhost:9092"]`. Supplied by the host service. */
  brokers: string[];
  /** Confluent Schema Registry URL, e.g. `"http://schema-registry:8081"`. Supplied by the host service. */
  schemaRegistryUrl: string;
}

/**
 * Build Nest microservice Kafka transport options for the authz role-event consumer.
 *
 * Consumer group is generated INSIDE the library using a random UUID so every
 * replica receives every role event (broadcast fan-out), matching the Java consumer.
 *
 * Wire format: Confluent Avro. The host passes `brokers` and `schemaRegistryUrl`;
 * this factory owns the group, deserializer, and topic subscriptions.
 *
 * Usage in the host service bootstrap:
 * ```ts
 * import { authzKafkaOptions } from "authz-nestjs";
 *
 * const app = await NestFactory.create(AppModule);
 * app.connectMicroservice<MicroserviceOptions>(
 *   authzKafkaOptions({
 *     brokers: process.env.KAFKA_BROKERS?.split(",") ?? [],
 *     schemaRegistryUrl: process.env.SCHEMA_REGISTRY_URL ?? "http://schema-registry:8081",
 *   }),
 * );
 * await app.startAllMicroservices();
 * await app.listen(3000);
 * ```
 */
export function authzKafkaOptions(input: AuthzKafkaOptionsInput): MicroserviceOptions {
  const { brokers, schemaRegistryUrl } = input;

  // Per-instance random consumer group so every replica fans-out (broadcast semantics).
  const groupId = `authz-cache-sync-${randomUUID()}`;

  const registry = new SchemaRegistry({ host: schemaRegistryUrl });

  return {
    transport: Transport.KAFKA,
    options: {
      client: {
        brokers,
      },
      consumer: {
        groupId,
      },
      deserializer: {
        // NestJS ServerKafka calls deserialize(rawMessage, { channel: topic }) and
        // expects back a packet { pattern, data }: `pattern` routes to the @EventPattern
        // handler (it MUST be the topic), `data` is the payload handed to the handler.
        // We Avro-decode the Confluent-framed value buffer into `data`.
        deserialize: async (message: { value?: Buffer | null }, options?: { channel?: string }) => {
          const raw = message?.value;
          let data: unknown = raw;
          if (Buffer.isBuffer(raw)) {
            try {
              data = await registry.decode(raw);
            } catch {
              // Non-Avro or unregistered schema — leave the raw buffer; the handler
              // receives an unexpected type and the event is effectively skipped.
              data = raw;
            }
          }
          return { pattern: options?.channel, data };
        },
      },
    },
  } as MicroserviceOptions;
}
