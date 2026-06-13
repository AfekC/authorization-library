import { Module } from "@nestjs/common";
import { JwksTokenValidator } from "../../inbound-auth/token-validator";
import { TokenValidator } from "../../spi";
import { CreateAuthzOptions } from "../../bootstrap/create-authz";
import { AUTHZ_OPTIONS, AUTHZ_VALIDATOR, AUTHZ_USER_AUTH_ENABLED } from "../authz-options";

function userAuthEnabled(opts: CreateAuthzOptions): boolean {
  return Boolean(opts.userIssuer || opts.userJwksUri || opts.audience || opts.roleServiceUrl);
}

@Module({
  providers: [
    {
      provide: AUTHZ_USER_AUTH_ENABLED,
      useFactory: (opts: CreateAuthzOptions) => userAuthEnabled(opts),
      inject: [AUTHZ_OPTIONS],
    },
    {
      provide: AUTHZ_VALIDATOR,
      useFactory: (opts: CreateAuthzOptions): TokenValidator =>
        opts.validator ?? new JwksTokenValidator({
          userIssuer: opts.userIssuer, userJwksUri: opts.userJwksUri,
          serviceIssuer: opts.serviceIssuer, serviceJwksUri: opts.serviceJwksUri,
          serviceTokenUseClaim: opts.serviceTokenUseClaim,
          serviceTokenUseValue: opts.serviceTokenUseValue,
          audience: opts.audience, clockSkewSeconds: opts.clockSkewSeconds ?? 5,
        }),
      inject: [AUTHZ_OPTIONS],
    },
  ],
  exports: [AUTHZ_VALIDATOR, AUTHZ_USER_AUTH_ENABLED],
})
export class InboundAuthModule {}
