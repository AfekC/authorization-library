import { Module } from "@nestjs/common";
import { AuthzModule } from "authz-nestjs";
import * as path from "path";
import { HealthController } from "./health.controller.js";
import { OrdersController } from "./orders.controller.js";
import { InternalController } from "./internal.controller.js";
import { FallbackController } from "./fallback.controller.js";

const MOCK = process.env.MOCK_URL || "http://localhost:4000";

/**
 * The demo's root module. Adopting the library is a single import:
 * `AuthzModule.forRoot(options)` wires the global guard + outbound interceptor,
 * compiles authorization.yaml (fail-fast), runs the startup state machine, and
 * exposes the runtime providers (cache, bootstrap, service identity) for DI.
 * Business controllers below carry NO authorization code.
 */
@Module({
  imports: [
    AuthzModule.forRoot({
      serviceIssuer: `${MOCK}/sso`,
      serviceJwksUri: `${MOCK}/sso/jwks`,
      userIssuer: `${MOCK}/auth`,
      userJwksUri: `${MOCK}/auth/jwks`,
      audience: process.env.API_AUDIENCE || "orders-api",
      roleServiceUrl: MOCK,
      authorizationYamlPath: path.join(__dirname, "..", "authorization.yaml"),
      diskCachePath: process.env.AUTHZ_DISK_CACHE_PATH || "/tmp/authorization-cache.json",
      serviceToken: {
        tokenUrl: `${MOCK}/sso/token`,
        clientId: process.env.CLIENT_ID || "nestjs-demo-id",
        clientSecret: process.env.CLIENT_SECRET || "nestjs-demo-secret",
      },
    }),
  ],
  // FallbackController must be last so real routes take precedence.
  controllers: [HealthController, OrdersController, InternalController, FallbackController],
})
export class AppModule {}
