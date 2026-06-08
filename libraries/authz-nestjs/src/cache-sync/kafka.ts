import { randomUUID } from "crypto";
import { Consumer, Kafka } from "kafkajs";
import { CacheEventHandler, RoleEvent } from "../spi";
import { parseRoleEvent } from "./events";

export interface KafkaSyncConfig {
  brokers: string[];
  /** Topic carrying UPSERT events (default `role-updates`). */
  updatesTopic?: string;
  /** Topic carrying DELETE events (default `role-delete`). */
  deleteTopic?: string;
  /** Topic that triggers a forced full re-fetch (default `publish-roles`). */
  publishTopic?: string;
  groupId?: string;
  clientId?: string;
  /** Logger for skipped/unparseable events (defaults to console.warn). */
  logger?: { warn: (msg: string) => void };
  /** Called when an unparseable event is dropped (e.g. to increment a metric). */
  onSkippedEvent?: () => void;
}

/**
 * Kafka consumer for role change events. Three topics: `role-updates` (upserts)
 * and `role-delete` (deletes) carry incremental changes — the wire message
 * carries only `roleId` (+ `permissions`) and the operation is derived from which
 * topic delivered it; `publish-roles` is a trigger that forces a full re-fetch.
 */
export class KafkaCacheEventHandler implements CacheEventHandler {
  private readonly kafka: Kafka;
  private consumer?: Consumer;
  private readonly updatesTopic: string;
  private readonly deleteTopic: string;
  private readonly publishTopic: string;

  constructor(private readonly cfg: KafkaSyncConfig) {
    this.kafka = new Kafka({
      clientId: cfg.clientId ?? "authz-cache-sync",
      brokers: cfg.brokers,
    });
    this.updatesTopic = cfg.updatesTopic ?? "role-updates";
    this.deleteTopic = cfg.deleteTopic ?? "role-delete";
    this.publishTopic = cfg.publishTopic ?? "publish-roles";
  }

  async start(
    onEvent: (event: RoleEvent) => void,
    onRefresh: () => void,
  ): Promise<void> {
    // Per-instance unique group id so every replica receives every role event
    // (broadcast fan-out), matching the Spring consumer.
    this.consumer = this.kafka.consumer({
      groupId: `${this.cfg.groupId ?? "authz-cache-sync"}-${randomUUID()}`,
    });
    await this.consumer.connect();
    await this.consumer.subscribe({ topic: this.updatesTopic, fromBeginning: false });
    await this.consumer.subscribe({ topic: this.deleteTopic, fromBeginning: false });
    await this.consumer.subscribe({ topic: this.publishTopic, fromBeginning: false });
    await this.consumer.run({
      eachMessage: async ({ topic, message }) => {
        if (topic === this.publishTopic) {
          onRefresh();
          return;
        }
        const parsed = parseRoleEvent(message.value);
        if (!parsed || typeof parsed !== "object") {
          // Unparseable events are dropped here before reaching the bootstrap's
          // apply path, so count + log them through the injected hooks rather
          // than a bare console.warn (fail-open: never throw on a bad event).
          this.cfg.onSkippedEvent?.();
          (this.cfg.logger ?? { warn: (m: string) => console.warn(m) }).warn(
            "skipping unparseable role event",
          );
          return;
        }
        const operation =
          topic === this.deleteTopic ? "DELETE_ROLE" : "UPSERT_ROLE";
        // C9: If the raw message body also carries an `operation` field, pass it
        // as `_messageOperation` so applyRoleEvent can detect conflicts between
        // the topic-derived operation and the message body's claimed operation.
        // An UPSERT payload on the delete topic (or vice-versa) is skipped.
        const rawMessageOperation = (parsed as any).operation as string | undefined;
        const event = {
          ...((parsed as any) as object),
          operation,
          ...(rawMessageOperation !== undefined
            ? { _messageOperation: rawMessageOperation }
            : {}),
        } as RoleEvent & { _messageOperation?: string };
        onEvent(event);
      },
    });
  }

  /**
   * Disconnect the consumer. Idempotent: the consumer reference is cleared
   * first, so a second call (e.g. CacheBootstrap.stop() fire-and-forget plus an
   * explicit await by the host) is a safe no-op rather than a double-disconnect.
   */
  async stop(): Promise<void> {
    const consumer = this.consumer;
    this.consumer = undefined;
    if (consumer) await consumer.disconnect();
  }
}
