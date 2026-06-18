import {
  createRemoteJWKSet,
  jwtVerify,
  JWTVerifyGetKey,
  JWTPayload,
} from "jose";
import { TokenClaims, TokenValidator } from "../spi/index.js";
import { ServicePrincipal, UserPrincipal } from "./context.js";

/** Attach the original error as `.cause` on a new Error (G12 — preserve cause).
 *  Uses property assignment for ES2021 compat (Error({ cause }) is ES2022+). */
function withCause(message: string, cause: unknown): Error {
  const err = new Error(message);
  (err as any).cause = cause;
  return err;
}

/**
 * Default timeout for JWKS HTTP fetches (ms). Matches Java Nimbus's 5-second
 * default and is passed as `timeoutDuration` to createRemoteJWKSet so that a
 * slow/hung JWKS endpoint does not block jwtVerify indefinitely.
 */
export const DEFAULT_JWKS_TIMEOUT_MS = 5000;

export interface JwksValidatorConfig {
  /**
   * Auth Service issuer + JWKS + audience for user JWTs. Optional: omit all
   * three to run in SERVICE-ONLY mode (§0.5), where user JWTs are never
   * validated and {@link JwksTokenValidator.validateUserToken} throws.
   */
  userIssuer?: string;
  userJwksUri?: string;
  audience?: string;
  /** SSO issuer + JWKS for service tokens. */
  serviceIssuer: string;
  serviceJwksUri: string;
  clockSkewSeconds?: number;
  /** Pinned algorithms (alg:none is always rejected). */
  algorithms?: string[];
  /** Claim that marks a service token. */
  serviceTokenUseClaim?: string;
  serviceTokenUseValue?: string;
  /**
   * Timeout (ms) for JWKS HTTP fetches. Defaults to {@link DEFAULT_JWKS_TIMEOUT_MS}
   * (5000 ms). Passed as `timeoutDuration` to createRemoteJWKSet.
   */
  jwksTimeoutMs?: number;
}

/** Validates JWTs against remote JWKS for the Auth Service and SSO provider. */
export class JwksTokenValidator implements TokenValidator {
  /** Undefined in SERVICE-ONLY mode (no user-JWT validation). */
  private readonly userJwks?: JWTVerifyGetKey;
  private readonly serviceJwks: JWTVerifyGetKey;
  private readonly algorithms: string[];

  constructor(private readonly cfg: JwksValidatorConfig) {
    const timeoutDuration = cfg.jwksTimeoutMs ?? DEFAULT_JWKS_TIMEOUT_MS;
    // SERVICE-ONLY mode (§0.5): no user JWKS when user auth is not configured.
    this.userJwks = cfg.userJwksUri
      ? createRemoteJWKSet(new URL(cfg.userJwksUri), { timeoutDuration })
      : undefined;
    this.serviceJwks = createRemoteJWKSet(new URL(cfg.serviceJwksUri), { timeoutDuration });
    this.algorithms = cfg.algorithms ?? ["RS256", "ES256"];
  }

  async validateUserToken(jwt: string): Promise<TokenClaims> {
    if (!this.userJwks) {
      throw new Error("user auth is disabled (service-only mode)");
    }
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
    userId: (claims.userId as string) ?? null,
    // Non-string roleId (number, array, …) is treated as absent → empty perms → DENY.
    roleId: typeof claims.roleId === "string" ? (claims.roleId as string) : null,
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
  };
}
