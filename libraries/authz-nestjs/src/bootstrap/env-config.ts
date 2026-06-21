import type { CreateAuthzOptions } from "./create-authz.js";
import { ConfigError } from "../rule-config/types.js";

/**
 * Environment-variable-driven configuration for the authorization library.
 *
 * This brings the NestJS library to parity with the Spring Boot library, where
 * `@ConfigurationProperties(prefix = "authz")` binds configuration from the
 * environment automatically. Here, {@link optionsFromEnv} maps `AUTHZ_*`
 * environment variables onto {@link CreateAuthzOptions}.
 *
 * The variable names mirror Spring's relaxed binding 1:1 — e.g. Spring's
 * `authz.user-issuer` property is overridable by the `AUTHZ_USER_ISSUER`
 * environment variable, which is exactly the name read here.
 *
 * | Env var | Option | Notes |
 * |---|---|---|
 * | `AUTHZ_SERVICE_ISSUER` | `serviceIssuer` | required (both modes) |
 * | `AUTHZ_SERVICE_JWKS_URI` | `serviceJwksUri` | required (both modes) |
 * | `AUTHZ_USER_ISSUER` | `userIssuer` | required only when user auth enabled |
 * | `AUTHZ_USER_JWKS_URI` | `userJwksUri` | required only when user auth enabled |
 * | `AUTHZ_USER_AUDIENCE` | `audience` | required only when user auth enabled |
 * | `AUTHZ_ROLE_SERVICE_URL` | `roleServiceUrl` | required only when user auth enabled |
 * | `AUTHZ_SERVICE_ONLY` | `serviceOnly` | `true`/`1` → explicit SERVICE-ONLY mode (§0.5); rejects user-auth fields |
 * | `AUTHZ_AUTHORIZATION_YAML` | `authorizationYaml` | one-of (rules as text) |
 * | `AUTHZ_AUTHORIZATION_YAML_PATH` | `authorizationYamlPath` | one-of (rules file path) |
 * | `AUTHZ_CLOCK_SKEW_SECONDS` | `clockSkewSeconds` | number |
 * | `AUTHZ_RECONCILE_INTERVAL_MS` | `reconcileIntervalMs` | number |
 * | `AUTHZ_ROLE_SERVICE_CONNECT_TIMEOUT` | `roleServiceConnectTimeout` | number |
 * | `AUTHZ_ROLE_SERVICE_READ_TIMEOUT` | `roleServiceReadTimeout` | number |
 * | `AUTHZ_DISK_CACHE_PATH` | `diskCachePath` | |
 * | `AUTHZ_SERVICE_TOKEN_USE_CLAIM` | `serviceTokenUseClaim` | |
 * | `AUTHZ_SERVICE_TOKEN_USE_VALUE` | `serviceTokenUseValue` | |
 * | `AUTHZ_TOKEN_URL` | `serviceToken.tokenUrl` | outbound identity |
 * | `AUTHZ_CLIENT_ID` | `serviceToken.clientId` | presence enables outbound identity |
 * | `AUTHZ_CLIENT_SECRET` | `serviceToken.clientSecret` | inject from a secret store |
 * | `AUTHZ_OUTBOUND_ALLOWED_HOSTS` | `outboundAllowedHosts` | comma-separated trusted downstream hosts; default empty → attach credentials to nothing (T19) |
 */
export type EnvSource = Record<string, string | undefined>;

/** Parse a numeric env var; throw a ConfigError naming the variable on a bad value. */
function numberFromEnv(env: EnvSource, name: string): number | undefined {
  const raw = env[name];
  if (raw === undefined || raw.trim().length === 0) return undefined;
  const n = Number(raw);
  if (!Number.isFinite(n)) {
    throw new ConfigError(`Invalid ${name}: "${raw}" is not a valid number`);
  }
  return n;
}

/** Read a string env var, treating absent/blank as undefined (so defaults apply). */
function stringFromEnv(env: EnvSource, name: string): string | undefined {
  const raw = env[name];
  return raw === undefined || raw.length === 0 ? undefined : raw;
}

/** Parse a boolean env var ("true"/"1" → true). Absent/blank → undefined. */
function booleanFromEnv(env: EnvSource, name: string): boolean | undefined {
  const raw = env[name];
  if (raw === undefined || raw.trim().length === 0) return undefined;
  const v = raw.trim().toLowerCase();
  return v === "true" || v === "1";
}

/**
 * Map `AUTHZ_*` environment variables onto a {@link CreateAuthzOptions} object.
 *
 * Absent variables are omitted (so library defaults apply); only variables that
 * are actually present are mapped. Required-field and URL validation is left to
 * {@link createAuthz}, so the rules live in exactly one place.
 *
 * Outbound identity (`serviceToken`) is assembled only when `AUTHZ_CLIENT_ID` is
 * set — mirroring Spring's `@ConditionalOnProperty(name = "authz.client-id")`.
 * When it is set, `AUTHZ_TOKEN_URL` and `AUTHZ_CLIENT_SECRET` are required too.
 *
 * @param env  the environment to read (defaults to `process.env`).
 */
export function optionsFromEnv(env: EnvSource = process.env): Partial<CreateAuthzOptions> {
  const opts: Partial<CreateAuthzOptions> = {};

  // --- trust roots (required; validated by createAuthz) ---
  const userIssuer = stringFromEnv(env, "AUTHZ_USER_ISSUER");
  if (userIssuer !== undefined) opts.userIssuer = userIssuer;
  const userJwksUri = stringFromEnv(env, "AUTHZ_USER_JWKS_URI");
  if (userJwksUri !== undefined) opts.userJwksUri = userJwksUri;
  const serviceIssuer = stringFromEnv(env, "AUTHZ_SERVICE_ISSUER");
  if (serviceIssuer !== undefined) opts.serviceIssuer = serviceIssuer;
  const serviceJwksUri = stringFromEnv(env, "AUTHZ_SERVICE_JWKS_URI");
  if (serviceJwksUri !== undefined) opts.serviceJwksUri = serviceJwksUri;
  const audience = stringFromEnv(env, "AUTHZ_USER_AUDIENCE");
  if (audience !== undefined) opts.audience = audience;
  const roleServiceUrl = stringFromEnv(env, "AUTHZ_ROLE_SERVICE_URL");
  if (roleServiceUrl !== undefined) opts.roleServiceUrl = roleServiceUrl;
  const serviceOnly = booleanFromEnv(env, "AUTHZ_SERVICE_ONLY");
  if (serviceOnly !== undefined) opts.serviceOnly = serviceOnly;

  // --- rules source (one of) ---
  const yaml = stringFromEnv(env, "AUTHZ_AUTHORIZATION_YAML");
  if (yaml !== undefined) opts.authorizationYaml = yaml;
  const yamlPath = stringFromEnv(env, "AUTHZ_AUTHORIZATION_YAML_PATH");
  if (yamlPath !== undefined) opts.authorizationYamlPath = yamlPath;

  // --- optional numbers ---
  const clockSkew = numberFromEnv(env, "AUTHZ_CLOCK_SKEW_SECONDS");
  if (clockSkew !== undefined) opts.clockSkewSeconds = clockSkew;
  const reconcile = numberFromEnv(env, "AUTHZ_RECONCILE_INTERVAL_MS");
  if (reconcile !== undefined) opts.reconcileIntervalMs = reconcile;
  const connectTimeout = numberFromEnv(env, "AUTHZ_ROLE_SERVICE_CONNECT_TIMEOUT");
  if (connectTimeout !== undefined) opts.roleServiceConnectTimeout = connectTimeout;
  const readTimeout = numberFromEnv(env, "AUTHZ_ROLE_SERVICE_READ_TIMEOUT");
  if (readTimeout !== undefined) opts.roleServiceReadTimeout = readTimeout;

  // --- optional strings ---
  const diskCachePath = stringFromEnv(env, "AUTHZ_DISK_CACHE_PATH");
  if (diskCachePath !== undefined) opts.diskCachePath = diskCachePath;
  const useClaim = stringFromEnv(env, "AUTHZ_SERVICE_TOKEN_USE_CLAIM");
  if (useClaim !== undefined) opts.serviceTokenUseClaim = useClaim;
  const useValue = stringFromEnv(env, "AUTHZ_SERVICE_TOKEN_USE_VALUE");
  if (useValue !== undefined) opts.serviceTokenUseValue = useValue;
  // --- outbound identity (serviceToken): only when AUTHZ_CLIENT_ID is set ---
  const svcClientId = stringFromEnv(env, "AUTHZ_CLIENT_ID");
  if (svcClientId !== undefined) {
    const tokenUrl = stringFromEnv(env, "AUTHZ_TOKEN_URL");
    const clientSecret = stringFromEnv(env, "AUTHZ_CLIENT_SECRET");
    if (tokenUrl === undefined) {
      throw new ConfigError(
        "AUTHZ_CLIENT_ID is set but AUTHZ_TOKEN_URL is missing (required for outbound identity)",
      );
    }
    if (clientSecret === undefined) {
      throw new ConfigError(
        "AUTHZ_CLIENT_ID is set but AUTHZ_CLIENT_SECRET is missing (required for outbound identity)",
      );
    }
    opts.serviceToken = { tokenUrl, clientId: svcClientId, clientSecret };
  }

  // --- outbound trusted-host allowlist (T19): comma-separated hosts ---
  // Present-but-empty → [] (credentials attached to nothing — the safe default).
  // Absent → field omitted entirely (library default applies, which is also []).
  const allowedHostsRaw = env["AUTHZ_OUTBOUND_ALLOWED_HOSTS"];
  if (allowedHostsRaw !== undefined) {
    opts.outboundAllowedHosts = allowedHostsRaw
      .split(",")
      .map((h) => h.trim())
      .filter((h) => h.length > 0);
  }

  return opts;
}

