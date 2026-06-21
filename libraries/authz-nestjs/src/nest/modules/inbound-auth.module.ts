import { Module } from "@nestjs/common";
import { JwksTokenValidator } from "../../inbound-auth/token-validator.js";
import { TokenValidator } from "../../spi/index.js";
import { CreateAuthzOptions } from "../../bootstrap/create-authz.js";
import { AUTHZ_OPTIONS, AUTHZ_VALIDATOR, AUTHZ_USER_AUTH_ENABLED } from "../authz-options.js";

function userAuthEnabled(opts: CreateAuthzOptions): boolean {
  if (opts.serviceOnly) return false; // explicit SERVICE-ONLY mode (§0.5)
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
