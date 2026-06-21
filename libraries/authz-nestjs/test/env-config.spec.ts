/**
 * Env-driven configuration: optionsFromEnv.
 *
 * Brings the NestJS library to parity with Spring's @ConfigurationProperties,
 * which binds `authz.*` config from the environment. `AUTHZ_*` env vars map onto
 * CreateAuthzOptions.
 */

import { optionsFromEnv } from "../src/bootstrap/env-config.js";
import { ConfigError } from "../src/rule-config/types.js";

describe("optionsFromEnv — required trust roots", () => {
  it("maps the six required fields", () => {
    const opts = optionsFromEnv({
      AUTHZ_USER_ISSUER: "https://auth.example.com",
      AUTHZ_USER_JWKS_URI: "https://auth.example.com/jwks",
      AUTHZ_SERVICE_ISSUER: "https://sso.example.com",
      AUTHZ_SERVICE_JWKS_URI: "https://sso.example.com/jwks",
      AUTHZ_USER_AUDIENCE: "orders-api",
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
    const opts = optionsFromEnv({ AUTHZ_USER_AUDIENCE: "orders-api" });
    expect(opts).toEqual({ audience: "orders-api" });
    expect("userIssuer" in opts).toBe(false);
  });

  it("treats blank strings as absent", () => {
    const opts = optionsFromEnv({ AUTHZ_USER_ISSUER: "" });
    expect("userIssuer" in opts).toBe(false);
  });
});

describe("optionsFromEnv — service-only flag (AUTHZ_SERVICE_ONLY)", () => {
  it.each(["true", "TRUE", "True", "1"])("maps %p to serviceOnly=true", (v) => {
    expect(optionsFromEnv({ AUTHZ_SERVICE_ONLY: v }).serviceOnly).toBe(true);
  });

  it.each(["false", "0", "no", "off", "anything-else"])("maps %p to serviceOnly=false", (v) => {
    expect(optionsFromEnv({ AUTHZ_SERVICE_ONLY: v }).serviceOnly).toBe(false);
  });

  it("omits serviceOnly entirely when absent or blank (library default applies)", () => {
    expect("serviceOnly" in optionsFromEnv({})).toBe(false);
    expect("serviceOnly" in optionsFromEnv({ AUTHZ_SERVICE_ONLY: "" })).toBe(false);
    expect("serviceOnly" in optionsFromEnv({ AUTHZ_SERVICE_ONLY: "   " })).toBe(false);
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

describe("optionsFromEnv — outbound trusted-host allowlist (T19)", () => {
  it("parses a comma-separated list of hosts into outboundAllowedHosts", () => {
    const opts = optionsFromEnv({
      AUTHZ_OUTBOUND_ALLOWED_HOSTS: "api.internal, payments.internal:8443 , reports.internal",
    });
    expect(opts.outboundAllowedHosts).toEqual([
      "api.internal",
      "payments.internal:8443",
      "reports.internal",
    ]);
  });

  it("maps a single host to a one-element array", () => {
    const opts = optionsFromEnv({ AUTHZ_OUTBOUND_ALLOWED_HOSTS: "api.internal" });
    expect(opts.outboundAllowedHosts).toEqual(["api.internal"]);
  });

  it("maps a present-but-empty value to [] (attach credentials to nothing)", () => {
    const opts = optionsFromEnv({ AUTHZ_OUTBOUND_ALLOWED_HOSTS: "" });
    expect(opts.outboundAllowedHosts).toEqual([]);
  });

  it("omits outboundAllowedHosts entirely when the var is absent", () => {
    const opts = optionsFromEnv({});
    expect("outboundAllowedHosts" in opts).toBe(false);
  });

  it("trims whitespace around each entry", () => {
    const opts = optionsFromEnv({ AUTHZ_OUTBOUND_ALLOWED_HOSTS: "  a.internal  ,  b.internal  " });
    expect(opts.outboundAllowedHosts).toEqual(["a.internal", "b.internal"]);
  });

  it("skips blank-only comma entries (e.g. trailing comma)", () => {
    const opts = optionsFromEnv({ AUTHZ_OUTBOUND_ALLOWED_HOSTS: "a.internal,,b.internal," });
    expect(opts.outboundAllowedHosts).toEqual(["a.internal", "b.internal"]);
  });
});

