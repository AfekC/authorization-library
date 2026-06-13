import { DynamicModule, Global, Module, OnModuleDestroy, Provider } from "@nestjs/common";
import { APP_GUARD, APP_INTERCEPTOR } from "@nestjs/core";
import { createAuthzFromOptions, CreateAuthzOptions, Authz } from "../bootstrap/create-authz";
import { AuthzGuard, AuthzGuardDeps } from "./authz.guard";
import { AuthzOutboundInterceptor } from "./outbound.interceptor";
import {
  AUTHZ_OPTIONS, AUTHZ_ENGINE, AUTHZ_CACHE, AUTHZ_METRICS, AUTHZ_AUDIT,
  AUTHZ_VALIDATOR, AUTHZ_USER_AUTH_ENABLED, AuthzModuleAsyncOptions,
} from "./authz-options";
import { ObservabilityModule } from "./modules/observability.module";
import { DecisionEngineModule } from "./modules/decision-engine.module";
import { PermissionCacheModule } from "./modules/permission-cache.module";
import { InboundAuthModule } from "./modules/inbound-auth.module";
import { CacheSyncModule } from "./modules/cache-sync.module";
import { OutboundModule } from "./modules/outbound.module";

/**
 * Injection token for the full `Authz` runtime object returned by createAuthz().
 * Consumers can inject it to access engine, cache, metrics, health, stop, etc.
 *
 * @example
 * constructor(@Inject(AUTHZ) private readonly authz: Authz) {}
 */
export const AUTHZ = "AUTHZ";

const FEATURE_MODULES = [
  ObservabilityModule, PermissionCacheModule, DecisionEngineModule,
  InboundAuthModule, CacheSyncModule, OutboundModule,
];

/** Provider building the AuthzGuard from the feature-module providers. */
const guardProvider: Provider = {
  provide: AuthzGuard,
  useFactory: (engine: any, cache: any, metrics: any, validator: any, audit: any, userAuthEnabled: boolean, opts: CreateAuthzOptions): AuthzGuard => {
    const deps: AuthzGuardDeps = {
      engine, cache, metrics, validator, audit,
      policyEngine: opts.policyEngine, roleResolver: opts.roleResolver, userAuthEnabled,
    };
    return new AuthzGuard(deps);
  },
  inject: [AUTHZ_ENGINE, AUTHZ_CACHE, AUTHZ_METRICS, AUTHZ_VALIDATOR, AUTHZ_AUDIT, AUTHZ_USER_AUTH_ENABLED, AUTHZ_OPTIONS],
};

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

  // Called by the DynamicModule AUTHZ factory; kept here so onModuleDestroy can reach it.
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
    return AuthzModule.build({ provide: AUTHZ_OPTIONS, useValue: options }, []);
  }

  static forRootAsync(asyncOpts: AuthzModuleAsyncOptions): DynamicModule {
    return AuthzModule.build(
      { provide: AUTHZ_OPTIONS, useFactory: asyncOpts.useFactory, inject: asyncOpts.inject ?? [] },
      asyncOpts.imports ?? [],
    );
  }

  private static build(optionsProvider: Provider, extraImports: any[]): DynamicModule {
    // Backward-compat AUTHZ token: build the full Authz runtime via createAuthzFromOptions
    // so existing consumers of AUTHZ.engine / AUTHZ.health / AUTHZ.stop still work.
    const authzProvider: Provider = {
      provide: AUTHZ,
      useFactory: async (module: AuthzModule, opts: CreateAuthzOptions): Promise<Authz> => {
        const authz = await createAuthzFromOptions(opts);
        AuthzModule.setAuthz(module, authz);
        return authz;
      },
      inject: [AuthzModule, AUTHZ_OPTIONS],
    };

    return {
      module: AuthzModule,
      imports: [...extraImports, ...FEATURE_MODULES],
      providers: [
        optionsProvider,
        authzProvider,
        guardProvider,
        { provide: APP_GUARD, useExisting: AuthzGuard },
        { provide: APP_INTERCEPTOR, useClass: AuthzOutboundInterceptor },
      ],
      exports: [
        AUTHZ_OPTIONS, AuthzGuard, AUTHZ,
        // Re-export feature modules so their providers are accessible to consumers
        ...FEATURE_MODULES,
      ],
    };
  }
}
