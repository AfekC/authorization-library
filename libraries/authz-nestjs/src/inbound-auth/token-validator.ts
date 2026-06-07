import {
  createRemoteJWKSet,
  jwtVerify,
  JWTVerifyGetKey,
  JWTPayload,
} from "jose";
import { TokenClaims, TokenValidator } from "../spi";
import { ServicePrincipal, UserPrincipal } from "./context";

/** Attach the original error as `.cause` on a new Error (G12 — preserve cause).
 *  Uses property assignment for ES2021 compat (Error({ cause }) is ES2022+). */
function withCause(message: string, cause: unknown): Error {
  const err = new Error(message);
  (err as any).cause = cause;
  return err;
}

export interface JwksValidatorConfig {
  /** Auth Service issuer + JWKS for user JWTs. */
  userIssuer: string;
  userJwksUri: string;
  /** SSO issuer + JWKS for service tokens. */
  serviceIssuer: string;
  serviceJwksUri: string;
  audience: string;
  clockSkewSeconds?: number;
  /** Pinned algorithms (alg:none is always rejected). */
  algorithms?: string[];
  /** Claim that marks a service token. */
  serviceTokenUseClaim?: string;
  serviceTokenUseValue?: string;
}

/** Validates JWTs against remote JWKS for the Auth Service and SSO provider. */
export class JwksTokenValidator implements TokenValidator {
  private readonly userJwks: JWTVerifyGetKey;
  private readonly serviceJwks: JWTVerifyGetKey;
  private readonly algorithms: string[];

  constructor(private readonly cfg: JwksValidatorConfig) {
    this.userJwks = createRemoteJWKSet(new URL(cfg.userJwksUri));
    this.serviceJwks = createRemoteJWKSet(new URL(cfg.serviceJwksUri));
    this.algorithms = cfg.algorithms ?? ["RS256", "ES256"];
  }

  async validateUserToken(jwt: string): Promise<TokenClaims> {
    try {
      const { payload } = await jwtVerify(jwt, this.userJwks, {
        issuer: this.cfg.userIssuer,
        audience: this.cfg.audience,
        algorithms: this.algorithms,
        clockTolerance: this.cfg.clockSkewSeconds ?? 5,
      });
      return payload as TokenClaims;
    } catch (cause) {
      throw withCause(
        `user token validation failed: ${(cause as Error).message}`,
        cause,
      );
    }
  }

  async validateServiceToken(jwt: string): Promise<TokenClaims> {
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(jwt, this.serviceJwks, {
        issuer: this.cfg.serviceIssuer,
        algorithms: this.algorithms,
        clockTolerance: this.cfg.clockSkewSeconds ?? 5,
      }));
    } catch (cause) {
      throw withCause(
        `service token validation failed: ${(cause as Error).message}`,
        cause,
      );
    }
    // Distinguish a service token from a user token by a configurable claim
    // (default token_use == "service"); reject if it does not match (§2.3).
    // An empty/blank serviceTokenUseClaim falls back to the default claim name
    // "token_use", matching Java's isBlank() behaviour (parity gap B3/G3).
    const rawClaimName = this.cfg.serviceTokenUseClaim;
    const claimName =
      rawClaimName == null || rawClaimName.trim().length === 0
        ? "token_use"
        : rawClaimName;
    const expected = this.cfg.serviceTokenUseValue ?? "service";
    if (payload[claimName] !== expected) {
      throw withCause(
        `service token rejected: ${claimName} != "${expected}"`,
        new Error(
          `claim "${claimName}" value "${String(payload[claimName])}" != expected "${expected}"`,
        ),
      );
    }
    return payload as TokenClaims;
  }
}

/** Map validated user claims to a principal (identity only from claims). */
export function userPrincipalFromClaims(claims: JWTPayload): UserPrincipal {
  return {
    userId: (claims.sub as string) ?? null,
    role: typeof claims.role === "string" ? (claims.role as string) : null,
    tenant: (claims.tenant as string) ?? null,
    jwtId: (claims.jti as string) ?? null,
  };
}

/** Map validated service claims to a principal. */
export function servicePrincipalFromClaims(
  claims: JWTPayload,
): ServicePrincipal {
  const name =
    (claims.service_name as string) ??
    (claims.azp as string) ??
    (claims.client_id as string) ??
    null;
  return {
    serviceName: name,
    serviceId: (claims.client_id as string) ?? null,
  };
}
