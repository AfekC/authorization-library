import { DynamicModule, Global, Module, OnModuleDestroy } from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import { createAuthzFromOptions, CreateAuthzOptions, Authz } from "../bootstrap/create-authz";
import { AuthzGuard, AuthzGuardDeps } from "./authz.guard";

/**
 * Injection token for the full `Authz` runtime object returned by createAuthz().
 * Consumers can inject it to access engine, cache, metrics, health, stop, etc.
 *
 * @example
 * constructor(@Inject(AUTHZ) private readonly authz: Authz) {}
 */
export const AUTHZ = "AUTHZ";

/**
 * NestJS auto-wiring module for the authorization library.
 *
 * Usage:
 * ```ts
 * @Module({
 *   imports: [AuthzModule.forRoot({ ...urls, authorizationYaml: yaml })],
 * })
 * export class AppModule {}
 * ```
 *
 * This registers `AuthzGuard` as a global `APP_GUARD` so every route is
 * covered without per-route opt-in — mirroring the Java global filter
 * and the architecture doc's "global enforcement" requirement.
 *
 * Exports:
 *  - `AUTHZ` token → the full `Authz` object (engine, cache, metrics, health…)
 *  - `AuthzGuard` directly (resolvable by class reference)
 */
@Global()
@Module({})
export class AuthzModule implements OnModuleDestroy {
  private authz: Authz | undefined;

  // Called by the DynamicModule factory; kept here so onModuleDestroy can reach it.
  static setAuthz(instance: AuthzModule, authz: Authz): void {
    instance.authz = authz;
  }

  async onModuleDestroy(): Promise<void> {
    if (this.authz) {
      await this.authz.stop();
    }
  }

  /**
   * Create a dynamic module that bootstraps the full authorization runtime once
   * and wires it into the NestJS DI container.
   */
  static forRoot(options: CreateAuthzOptions): DynamicModule {
    // We need a shared Authz reference across the factory providers.
    // We use a lazy-initialised Promise so the async bootstrap runs once.
    let authzPromise: Promise<Authz> | undefined;
    const getAuthz = (): Promise<Authz> => {
      if (!authzPromise) {
        authzPromise = createAuthzFromOptions(options);
      }
      return authzPromise;
    };

    return {
      module: AuthzModule,
      providers: [
        // ----------------------------------------------------------------
        // 1. The full Authz runtime — async factory, injected via AUTHZ token.
        // ----------------------------------------------------------------
        {
          provide: AUTHZ,
          useFactory: async (module: AuthzModule): Promise<Authz> => {
            const authz = await getAuthz();
            AuthzModule.setAuthz(module, authz);
            return authz;
          },
          inject: [AuthzModule],
        },

        // ----------------------------------------------------------------
        // 2. AuthzGuard — constructed from Authz pieces.
        // ----------------------------------------------------------------
        {
          provide: AuthzGuard,
          useFactory: async (): Promise<AuthzGuard> => {
            const authz = await getAuthz();
            const deps: AuthzGuardDeps = {
              engine: authz.engine,
              cache: authz.cache,
              metrics: authz.metrics,
              validator: authz.validator,
              audit: authz.audit,
              policyEngine: options.policyEngine,
              roleResolver: options.roleResolver,
            };
            return new AuthzGuard(deps);
          },
        },

        // ----------------------------------------------------------------
        // 3. Register as global guard via APP_GUARD so every route is covered.
        // ----------------------------------------------------------------
        {
          provide: APP_GUARD,
          useFactory: async (): Promise<AuthzGuard> => {
            const authz = await getAuthz();
            const deps: AuthzGuardDeps = {
              engine: authz.engine,
              cache: authz.cache,
              metrics: authz.metrics,
              validator: authz.validator,
              audit: authz.audit,
              policyEngine: options.policyEngine,
              roleResolver: options.roleResolver,
            };
            return new AuthzGuard(deps);
          },
        },
      ],
      exports: [AUTHZ, AuthzGuard],
    };
  }
}
