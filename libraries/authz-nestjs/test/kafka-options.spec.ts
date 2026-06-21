import { jest } from "@jest/globals";
import { Transport } from "@nestjs/microservices";

// Mock the Confluent registry so the deserializer's decode path is deterministic
// (no network to a real Schema Registry).
const decode = jest.fn<(buf: Buffer) => Promise<unknown>>();
jest.unstable_mockModule("@kafkajs/confluent-schema-registry", () => ({
  SchemaRegistry: jest.fn().mockImplementation(() => ({ decode })),
}));

const { authzKafkaOptions } = await import("../src/cache-sync/kafka-options.js");

/** Pull the (typed-as-any) transport options + deserializer out of the factory result. */
function build() {
  const opts = authzKafkaOptions({
    brokers: ["broker-1:9092", "broker-2:9092"],
    schemaRegistryUrl: "http://schema-registry:8081",
  }) as any;
  return { opts, deserialize: opts.options.deserializer.deserialize as (
    message: { value?: Buffer | null },
    options?: { channel?: string },
  ) => Promise<{ pattern: unknown; data: unknown }> };
}

beforeEach(() => decode.mockReset());

describe("authzKafkaOptions", () => {
  it("uses the Kafka transport and passes brokers through", () => {
    const { opts } = build();
    expect(opts.transport).toBe(Transport.KAFKA);
    expect(opts.options.client.brokers).toEqual(["broker-1:9092", "broker-2:9092"]);
  });

  it("generates a per-instance broadcast consumer group (authz-cache-sync-<uuid>)", () => {
    const a = (authzKafkaOptions({ brokers: [], schemaRegistryUrl: "x" }) as any).options.consumer.groupId;
    const b = (authzKafkaOptions({ brokers: [], schemaRegistryUrl: "x" }) as any).options.consumer.groupId;
    expect(a).toMatch(/^authz-cache-sync-/);
    expect(a).not.toBe(b); // random per instance → fan-out, not load-balanced
  });

  // The regression: NestJS ServerKafka calls deserialize(rawMessage, { channel: topic })
  // and routes to the @EventPattern handler by the returned `pattern`. If `pattern` is
  // undefined every role event is dropped ("no matching event handler ... undefined").
  it("returns { pattern: topic, data: decoded } so events route to a handler", async () => {
    const { deserialize } = build();
    const buf = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x01, 0x42]);
    decode.mockResolvedValue({ roleId: "manager", permissions: ["READ"], version: 7 });

    const packet = await deserialize({ value: buf }, { channel: "role-updates" });

    expect(decode).toHaveBeenCalledWith(buf);
    expect(packet.pattern).toBe("role-updates");
    expect(packet.data).toEqual({ roleId: "manager", permissions: ["READ"], version: 7 });
  });

  it("leaves a non-Buffer value untouched (decode not called) but still sets the topic pattern", async () => {
    const { deserialize } = build();
    const packet = await deserialize({ value: null }, { channel: "publish-roles" });
    expect(decode).not.toHaveBeenCalled();
    expect(packet.pattern).toBe("publish-roles");
    expect(packet.data).toBeNull();
  });

  it("fails closed on a non-Avro / unregistered payload: keeps the raw buffer, still routes by topic", async () => {
    const { deserialize } = build();
    const buf = Buffer.from("not-avro");
    decode.mockRejectedValue(new Error("unknown magic byte"));

    const packet = await deserialize({ value: buf }, { channel: "role-delete" });

    expect(packet.pattern).toBe("role-delete");
    expect(packet.data).toBe(buf); // handler gets an unexpected type → event effectively skipped
  });
});
