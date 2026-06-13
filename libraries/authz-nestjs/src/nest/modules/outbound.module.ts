import { Module, Injectable, OnModuleDestroy } from "@nestjs/common";
import { ClientCredentialsProvider } from "../../service-token/provider";
import { Metrics, METRIC } from "../../observability/metrics";
import { ServiceIdentityProvider } from "../../spi";
import { AuthzOutboundInterceptor } from "../outbound.interceptor";
import { CreateAuthzOptions } from "../../bootstrap/create-authz";
import { AUTHZ_OPTIONS, AUTHZ_METRICS, AUTHZ_SERVICE_IDENTITY } from "../authz-options";

@Injectable()
export class OutboundLifecycle implements OnModuleDestroy {
  private id: ServiceIdentityProvider | null = null;

  static wire(instance: OutboundLifecycle, id: ServiceIdentityProvider | null): void {
    instance.id = id;
  }

  async onModuleDestroy(): Promise<void> {
    const closable = this.id as { close?: () => void } | null;
    if (closable && typeof closable.close === "function") closable.close();
  }
}

@Module({
  providers: [
    {
      provide: AUTHZ_SERVICE_IDENTITY,
      useFactory: async (opts: CreateAuthzOptions, metrics: Metrics): Promise<ServiceIdentityProvider | null> => {
        if (!opts.serviceToken) return null;
        const provider = new ClientCredentialsProvider({
          tokenUrl: opts.serviceToken.tokenUrl, clientId: opts.serviceToken.clientId,
          clientSecret: opts.serviceToken.clientSecret,
          onError: () => metrics.inc(METRIC.serviceTokenFailures), metrics,
        });
        await provider.checkTokenEndpoint();
        return provider;
      },
      inject: [AUTHZ_OPTIONS, AUTHZ_METRICS],
    },
    {
      provide: OutboundLifecycle,
      useFactory: (id: ServiceIdentityProvider | null): OutboundLifecycle => {
        const lifecycle = new OutboundLifecycle();
        OutboundLifecycle.wire(lifecycle, id);
        return lifecycle;
      },
      inject: [AUTHZ_SERVICE_IDENTITY],
    },
    AuthzOutboundInterceptor,
  ],
  exports: [AUTHZ_SERVICE_IDENTITY, AuthzOutboundInterceptor, OutboundLifecycle],
})
export class OutboundModule {}
