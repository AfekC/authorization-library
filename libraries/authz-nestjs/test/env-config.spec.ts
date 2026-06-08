/**
 * Env-driven configuration: optionsFromEnv.
 *
 * Brings the NestJS library to parity with Spring's @ConfigurationProperties,
 * which binds `authz.*` config from the environment. `AUTHZ_*` env vars map onto
 * CreateAuthzOptions.
 */

import { optionsFromEnv } from "../src/bootstrap/env-config";
import { ConfigError } from "../src/rule-config/types";

describe("optionsFromEnv — required trust roots", () => {
  it("maps the six required fields", () => {
    const opts = optionsFromEnv({
      AUTHZ_USER_ISSUER: "https://auth.example.com",
      AUTHZ_USER_JWKS_URI: "https://auth.example.com/jwks",
      AUTHZ_SERVICE_ISSUER: "https://sso.example.com",
      AUTHZ_SERVICE_JWKS_URI: "https://sso.example.com/jwks",
      AUTHZ_AUDIENCE: "orders-api",
      AUTHZ_ROLE_SERVICE_URL: "http://role-service:8080",
    });
    expect(opts).toMatchObject({
      userIssuer: "https://auth.example.com",
      userJwksUri: "https://auth.example.com/jwks",
      serviceIssuer: "https://sso.example.com",
      serviceJwksUri: "https://sso.example.com/jwks",
      audience: "orders-api",
      roleServiceUrl: "http://role-service:8080",
    });
  });

  it("omits absent fields so library defaults apply", () => {
    const opts = optionsFromEnv({ AUTHZ_AUDIENCE: "orders-api" });
    expect(opts).toEqual({ audience: "orders-api" });
    expect("userIssuer" in opts).toBe(false);
  });

  it("treats blank strings as absent", () => {
    const opts = optionsFromEnv({ AUTHZ_USER_ISSUER: "" });
    expect("userIssuer" in opts).toBe(false);
  });
});

describe("optionsFromEnv — rules source", () => {
  it("maps inline YAML and a YAML path", () => {
    expect(optionsFromEnv({ AUTHZ_AUTHORIZATION_YAML: "rules: []" })).toEqual({
      authorizationYaml: "rules: []",
    });
    expect(optionsFromEnv({ AUTHZ_AUTHORIZATION_YAML_PATH: "/etc/authz.yaml" })).toEqual({
      authorizationYamlPath: "/etc/authz.yaml",
    });
  });
});

describe("optionsFromEnv — numbers", () => {
  it("parses numeric settings", () => {
    const opts = optionsFromEnv({
      AUTHZ_CLOCK_SKEW_SECONDS: "10",
      AUTHZ_RECONCILE_INTERVAL_MS: "7000",
      AUTHZ_ROLE_SERVICE_CONNECT_TIMEOUT: "1500",
      AUTHZ_ROLE_SERVICE_READ_TIMEOUT: "2500",
    });
    expect(opts).toMatchObject({
      clockSkewSeconds: 10,
      reconcileIntervalMs: 7000,
      roleServiceConnectTimeout: 1500,
      roleServiceReadTimeout: 2500,
    });
  });

  it("throws ConfigError naming the variable on a non-numeric value", () => {
    expect(() => optionsFromEnv({ AUTHZ_CLOCK_SKEW_SECONDS: "soon" })).toThrow(ConfigError);
    expect(() => optionsFromEnv({ AUTHZ_CLOCK_SKEW_SECONDS: "soon" })).toThrow(
      /AUTHZ_CLOCK_SKEW_SECONDS/,
    );
  });
});

describe("optionsFromEnv — Kafka brokers", () => {
  it("splits a comma-separated list and trims entries", () => {
    expect(optionsFromEnv({ AUTHZ_KAFKA_BROKERS: "a:9092, b:9092 ,c:9092" })).toEqual({
      kafkaBrokers: ["a:9092", "b:9092", "c:9092"],
    });
  });

  it("maps a present-but-empty value to [] (Kafka disabled)", () => {
    expect(optionsFromEnv({ AUTHZ_KAFKA_BROKERS: "" })).toEqual({ kafkaBrokers: [] });
  });

  it("omits kafkaBrokers entirely when the var is absent", () => {
    expect("kafkaBrokers" in optionsFromEnv({})).toBe(false);
  });
});

describe("optionsFromEnv — outbound identity (serviceToken)", () => {
  it("assembles serviceToken when AUTHZ_CLIENT_ID is set", () => {
    const opts = optionsFromEnv({
      AUTHZ_CLIENT_ID: "svc-id",
      AUTHZ_TOKEN_URL: "https://sso.example.com/token",
      AUTHZ_CLIENT_SECRET: "shh",
    });
    expect(opts.serviceToken).toEqual({
      tokenUrl: "https://sso.example.com/token",
      clientId: "svc-id",
      clientSecret: "shh",
    });
  });

  it("does not assemble serviceToken when AUTHZ_CLIENT_ID is absent", () => {
    const opts = optionsFromEnv({ AUTHZ_TOKEN_URL: "https://sso.example.com/token" });
    expect(opts.serviceToken).toBeUndefined();
  });

  it("throws when client id is set without token url", () => {
    expect(() =>
      optionsFromEnv({ AUTHZ_CLIENT_ID: "svc-id", AUTHZ_CLIENT_SECRET: "shh" }),
    ).toThrow(/AUTHZ_TOKEN_URL/);
  });

  it("throws when client id is set without client secret", () => {
    expect(() =>
      optionsFromEnv({ AUTHZ_CLIENT_ID: "svc-id", AUTHZ_TOKEN_URL: "https://sso/token" }),
    ).toThrow(/AUTHZ_CLIENT_SECRET/);
  });
});


