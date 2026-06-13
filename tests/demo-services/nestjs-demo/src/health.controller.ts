import { Controller, Get, Inject } from "@nestjs/common";
import { AUTHZ_CACHE, AUTHZ_BOOTSTRAP, buildHealth } from "authz-nestjs";

/**
 * Liveness/health endpoint. `/health` is a `public: true` rule, so the global
 * guard lets it through with no credentials. The cache + bootstrap runtime are
 * injected straight from the AuthzModule providers.
 */
@Controller("health")
export class HealthController {
  constructor(
    @Inject(AUTHZ_CACHE) private readonly cache: any,
    @Inject(AUTHZ_BOOTSTRAP) private readonly boot: any,
  ) {}

  @Get()
  health() {
    const h = this.boot
      ? buildHealth(this.cache, this.boot.mode_(), {
          roleServiceLastSync: this.boot.roleServiceLastSync(),
          kafkaConsumerConnected: this.boot.isKafkaConnected(),
        })
      : buildHealth(this.cache, "normal", {
          roleServiceLastSync: null,
          kafkaConsumerConnected: false,
        });
    return { ok: true, ...h };
  }
}
