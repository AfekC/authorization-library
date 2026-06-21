import { Controller, Inject, Optional } from "@nestjs/common";
import { EventPattern, Payload } from "@nestjs/microservices";
import { CacheBootstrap } from "./bootstrap.js";
import { RoleUpsertEvent, RoleDeleteEvent } from "../spi/index.js";
import { AUTHZ_BOOTSTRAP } from "../nest/authz-options.js";

/**
 * Library-owned Nest microservice controller for role cache events.
 *
 * Consumes three Kafka topics (Avro-decoded by the host's transport config):
 *   - `role-updates`   → upsert a role's permission set
 *   - `role-delete`    → remove a role from the cache
 *   - `publish-roles`  → trigger a forced full re-fetch from the Role Service
 *
 * The host wires transport + Avro deserialisation via `authzKafkaOptions()` and
 * `app.connectMicroservice()`; this controller only processes already-decoded payloads.
 * Enqueues onto CacheBootstrap's serial applyChain to preserve N6/L2 ordering.
 */
@Controller()
export class RoleEventsController {
  constructor(
    @Optional() @Inject(AUTHZ_BOOTSTRAP) private readonly boot: CacheBootstrap | null,
  ) {}

  @EventPattern("role-updates")
  handleUpsert(@Payload() payload: RoleUpsertEvent): void {
    if (!this.boot) return;
    this.boot.applyUpsert(payload);
  }

  @EventPattern("role-delete")
  handleDelete(@Payload() payload: RoleDeleteEvent): void {
    if (!this.boot) return;
    this.boot.applyDelete(payload);
  }

  @EventPattern("publish-roles")
  handlePublishRoles(): void {
    if (!this.boot) return;
    this.boot.forceRefresh();
  }
}
