import * as fs from "fs";
import axios from "axios";
import { AuthorizationEngine } from "../decision-engine/engine.js";
import { loadAuthorizationConfig } from "../rule-config/loader.js";
import { PermissionCache } from "../permission-cache/cache.js";
import {
  JwksTokenValidator,
} from "../inbound-auth/token-validator.js";
import {
  RequestContext,
} from "../inbound-auth/context.js";
import { HttpRoleServiceClient } from "../role-service-client/client.js";
import { DiskCache } from "../cache-sync/disk.js";
import { KafkaCacheEventHandler } from "../cache-sync/kafka.js";
import { CacheBootstrap, CacheMode } from "../cache-sync/bootstrap.js";
import { Metrics, METRIC, buildHealth } from "../observability/metrics.js";
import { ObservabilityConfig, initObservability, createAuthzTracer, AuthzTracer, AuthzSpan } from "../observability/otel.js";
import { bridgeMetricsToOtel } from "../observability/otel-bridge.js";
import { OtelAuditSink } from "../observability/otel-audit-sink.js";
import { LoggingAuditSink } from "../audit/audit.js";
import { AuditSink, ServiceIdentityProvider, TokenValidator, RoleResolver, PolicyEngine, AttributeProvider } from "../spi/index.js";
import { ClientCredentialsProvider } from "../service-token/provider.js";
import { runWithOutboundContext } from "../outbound/context-store.js";
import { attachOutboundPropagation, AxiosLike } from "../outbound/propagation.js";
import { ConfigError } from "../rule-config/types.js";
import { optionsFromEnv } from "./env-config.js";
import { decideRequest } from "../decision-engine/decide.js";

/**
 * Everything needed to stand up authorization in one call. Most fields have
 * sensible defaults; only the issuer/JWKS/role-service URLs are required.
 */
export interface CreateAuthzOptions {
  /** authorization.yaml as text, OR a path to it (one is required). */
  authorizationYaml?: string;
  authorizationYamlPath?: string;

  /** Service trust roots (always required). */
  serviceIssuer: string;
  serviceJwksUri: string;
  clockSkewSeconds?: number;

  /**
   * User trust roots (optional, all-or-nothing). Omit all three to run in
   * SERVICE-ONLY mode (§0.5): user JWTs are ignored and the role-permission
   * machinery (Role Service, cache sync, Kafka) is disabled.
   */
  userIssuer?: string;
  userJwksUri?: string;
  audience?: string;

  /** Permission distribution (required only when user auth is enabled). */
  roleServiceUrl?: string;
  kafkaBrokers?: string[];
  /** Kafka topic carrying UPSERT events (default `role-updates`). */
  roleUpdatesTopic?: string;
  /** Kafka topic carrying DELETE events (default `role-delete`). */
  roleDeleteTopic?: string;
  /** Kafka topic that triggers a forced full re-fetch (default `publish-roles`). */
  publishRolesTopic?: string;
  /** Kafka consumer group prefix (default "authz-cache-sync"). A UUID is appended per instance. */
  kafkaGroupId?: string;
  /** Kafka consumer client ID (default "authz-cache-sync"). */
  kafkaClientId?: string;
  diskCachePath?: string;
  /** Claim that marks a service token (default "token_use"). */
  serviceTokenUseClaim?: string;
  /** Expected value of the service-token-use claim (default "service"). */
  serviceTokenUseValue?: string;
  /** Periodic reconciler interval (ms). Default 300000 (5 minutes). */
  reconcileIntervalMs?: number;
  /** Role Service HTTP connect timeout (ms). Default 5000. */
  roleServiceConnectTimeout?: number;
  /** Role Service HTTP read timeout (ms). Default 5000. */
  roleServiceReadTimeout?: number;

  /** Outbound identity (optional): enables this.serviceIdentity for forwarding. */
  serviceToken?: {
    tokenUrl: string;
    clientId: string;
    clientSecret: string;
  };

  /**
   * Opt-in observability via `@hatraa/otel-ts` (OTLP traces, Prometheus metrics,
   * JSON logs). Off by default. When `enabled`, the in-process metrics are
   * mirrored to an OTel meter, the decision path is wrapped in a span, and the
   * default audit sink emits through `otelLogger`. For full request
   * auto-instrumentation, call {@link initObservability} at the very top of your
   * entrypoint before importing NestJS/HTTP.
   */
  observability?: ObservabilityConfig;

  /** Overrides for advanced use. */
  validator?: TokenValidator;
  auditSink?: AuditSink;
  roleResolver?: RoleResolver;
  policyEngine?: PolicyEngine;
  attributeProvider?: AttributeProvider;
}

/** Express request augmented with authorization context. Set only on ALLOW. */
export interface AuthorizedRequest {
  authz: RequestContext;
  authzUserJwt?: string;
}

/** A ready-to-use authorization runtime. */
export interface Authz {
  engine: AuthorizationEngine;
  cache: PermissionCache;
  metrics: Metrics;
  mode: CacheMode;
  /** False in SERVICE-ONLY mode (§0.5) — user JWTs are ignored. */
  userAuthEnabled: boolean;
  /** The TokenValidator instance wired at startup — exposed for NestJS guard wiring (M2). */
  validator: TokenValidator;
  /** The AuditSink instance wired at startup — exposed for NestJS guard wiring (M2). */
  audit: AuditSink;
  /** Outbound identity provider (present only if `serviceToken` was configured). */
  serviceIdentity?: ServiceIdentityProvider;
  /** Express-style global middleware: authenticate -> decide -> allow/deny. */
  middleware: (req: any, res: any, next: () => void) => Promise<void>;
  /**
   * Register auto-propagation on an axios instance: outbound calls made while
   * handling an authorized request get the user JWT, service token (when
   * configured), and correlation/request ids attached automatically (§9/§12).
   * A5: ergonomic — safe to call even if `serviceToken` was not configured;
   * X-Service-Token is simply omitted in that case (fail-open, G4).
   */
  attachOutbound: (axiosInstance: AxiosLike) => void;
  /**
   * Create an HTTP client with outbound propagation already registered.
   * Accepts the same config options as axios.create().
   * Recommended over manual attachOutbound() calls for consistency.
   */
  createClient: (config?: Record<string, unknown>) => AxiosLike;
  /** Health snapshot (cache status/version/age/mode/sync/kafka). */
  health: () => ReturnType<typeof buildHealth>;
  /** Stop background loops (reconciler, Kafka). */
  stop: () => Promise<void>;
}

/** Validate that a string is a well-formed http/https URL. Throws ConfigError on failure. */
function requireHttpUrl(value: string, fieldName: string): void {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new ConfigError(
      `Invalid ${fieldName}: "${value}" is not a valid URL`,
    );
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new ConfigError(
      `Invalid ${fieldName}: "${value}" must use http or https (got "${parsed.protocol.replace(":", "")}")`,
    );
  }
}

/**
 * Compile config, wire JWKS validation, run the startup state machine (Role
 * Service snapshot -> disk seed fallback -> Kafka subscribe), and return a
 * global Express middleware plus the engine/cache/metrics.
 *
 * Internal options-based bootstrap (used by env wrappers and tests).
 */
export async function createAuthzFromOptions(opts: CreateAuthzOptions): Promise<Authz> {
  // Service auth is ALWAYS required (both modes).
  if (!opts.serviceIssuer) throw new ConfigError("Missing required option: serviceIssuer");
  if (!opts.serviceJwksUri) throw new ConfigError("Missing required option: serviceJwksUri");
  requireHttpUrl(opts.serviceIssuer, "serviceIssuer");
  requireHttpUrl(opts.serviceJwksUri, "serviceJwksUri");

  // User auth is OPTIONAL and all-or-nothing (§0.5, §3.3). Enabled when any
  // user-auth field is present; then every required field must be present.
  const userAuthEnabled = Boolean(
    opts.userIssuer || opts.userJwksUri || opts.audience || opts.roleServiceUrl,
  );
  if (userAuthEnabled) {
    if (!opts.userIssuer)
      throw new ConfigError("Missing required option when user auth is enabled: userIssuer");
    if (!opts.userJwksUri)
      throw new ConfigError("Missing required option when user auth is enabled: userJwksUri");
    if (!opts.audience || opts.audience.trim().length === 0)
      throw new ConfigError("Missing required option when user auth is enabled: audience");
    if (!opts.roleServiceUrl)
      throw new ConfigError("Missing required option when user auth is enabled: roleServiceUrl");
    requireHttpUrl(opts.userIssuer, "userIssuer");
    requireHttpUrl(opts.userJwksUri, "userJwksUri");
    requireHttpUrl(opts.roleServiceUrl, "roleServiceUrl");
  }
  if (opts.serviceToken?.tokenUrl) {
    requireHttpUrl(opts.serviceToken.tokenUrl, "serviceToken.tokenUrl");
  }

  const yamlText =
    opts.authorizationYaml ??
    (opts.authorizationYamlPath
      ? fs.readFileSync(opts.authorizationYamlPath, "utf8")
      : (() => {
          throw new Error(
            "createAuthz requires authorizationYaml or authorizationYamlPath",
          );
        })());

  const engine = loadAuthorizationConfig(yamlText); // fail-fast on config error
  const cache = new PermissionCache();
  const metrics = new Metrics();

  // Opt-in observability (@hatraa/otel-ts): mirror the in-process metrics to an
  // OTel meter (→ Prometheus), trace the decision path, and emit audit via
  // otelLogger. Everything is lazy — nothing from the OTel/pprof stack is loaded
  // unless `observability.enabled` is set, so the default path is unchanged.
  let tracer: AuthzTracer | undefined;
  if (opts.observability?.enabled) {
    initObservability(opts.observability); // idempotent; safe if the app already called it
    bridgeMetricsToOtel(metrics);
    tracer = createAuthzTracer("authz");
  }

  const audit =
    opts.auditSink ??
    (opts.observability?.enabled ? new OtelAuditSink() : new LoggingAuditSink());

  const validator: TokenValidator =
    opts.validator ??
    new JwksTokenValidator({
      userIssuer: opts.userIssuer,
      userJwksUri: opts.userJwksUri,
      serviceIssuer: opts.serviceIssuer,
      serviceJwksUri: opts.serviceJwksUri,
      serviceTokenUseClaim: opts.serviceTokenUseClaim,
      serviceTokenUseValue: opts.serviceTokenUseValue,
      audience: opts.audience,
      clockSkewSeconds: opts.clockSkewSeconds ?? 5,
    });

  // Kafka role events are part of the role-permission machinery — FULL mode only.
  const events =
    userAuthEnabled && opts.kafkaBrokers?.length
      ? new KafkaCacheEventHandler({
          brokers: opts.kafkaBrokers,
          updatesTopic: opts.roleUpdatesTopic,
          deleteTopic: opts.roleDeleteTopic,
          publishTopic: opts.publishRolesTopic,
          groupId: opts.kafkaGroupId,
          clientId: opts.kafkaClientId,
          logger: { warn: (m) => console.warn(m) },
          onSkippedEvent: () => metrics.inc(METRIC.roleEventSkipped),
        })
      : undefined;

  const serviceIdentity = opts.serviceToken
    ? new ClientCredentialsProvider({
        tokenUrl: opts.serviceToken.tokenUrl,
        clientId: opts.serviceToken.clientId,
        clientSecret: opts.serviceToken.clientSecret,
        onError: () => metrics.inc(METRIC.serviceTokenFailures),
        metrics,
      })
    : undefined;

  // G11: best-effort startup reachability check for the token endpoint
  if (serviceIdentity) {
    await serviceIdentity.checkTokenEndpoint();
  }

  // Role-permission machinery (Role Service snapshot, disk seed, Kafka,
  // reconciler) — FULL mode only (§0.5). Absent in SERVICE-ONLY mode.
  let boot: CacheBootstrap | undefined;
  let mode: CacheMode = "normal";
  if (userAuthEnabled) {
    boot = new CacheBootstrap(
      cache,
      new HttpRoleServiceClient({
        baseUrl: opts.roleServiceUrl!,
        connectTimeoutMs: opts.roleServiceConnectTimeout ?? 5000,
        readTimeoutMs: opts.roleServiceReadTimeout ?? 5000,
      }),
      new DiskCache(opts.diskCachePath ?? "authorization-cache.json"),
      events,
      { metrics, logger: { warn: (m) => console.warn(m) } },
    );
    ({ mode } = await boot.start());
    boot.startSeedRetry(); // 2s/4s/8s backoff until seed→normal
    boot.startReconciler(opts.reconcileIntervalMs ?? 300000);
  }

  const runAuthz = async (req: any, res: any, next: () => void, span?: AuthzSpan) => {
    const out = await decideRequest(
      { method: req.method, rawPath: req.path ?? req.url ?? "", headers: req.headers ?? {} },
      { engine, cache, validator, audit, metrics,
        policyEngine: opts.policyEngine, roleResolver: opts.roleResolver, userAuthEnabled },
    );
    if (span && out.kind === "allow") {
      span.setAttribute("authz.path", (req.path ?? req.url ?? "").split("?")[0]);
      span.setAttribute("authz.method", req.method);
      span.setAttribute("authz.authType", out.ctx.authenticationType);
      if (out.ctx.roleId) span.setAttribute("authz.role", out.ctx.roleId);
      if (out.ctx.serviceName) span.setAttribute("authz.service", out.ctx.serviceName);
    }
    if (out.kind === "deny") {
      res.status(out.status).json({ error: out.error });
      return;
    }
    req.authz = out.ctx;
    if (out.bearer) (req as AuthorizedRequest).authzUserJwt = out.bearer;
    runWithOutboundContext(out.ctx, out.bearer, next);
  };

  // When tracing is on, wrap each decision in an "authz.decision" span; otherwise
  // the middleware is exactly the bare decision path (no behavioral change).
  const middleware = tracer
    ? (req: any, res: any, next: () => void): Promise<void> =>
        tracer!.startActiveSpan("authz.request", async (requestSpan: AuthzSpan) => {
          const stopTimer = metrics.startTimer(METRIC.authzRequestDuration);
          try {
            return tracer!.startActiveSpan("authz.decision", async (span: AuthzSpan) => {
              try {
                await runAuthz(req, res, next, span);
              } catch (err) {
                span.recordException(err);
                throw err;
              } finally {
                span.end();
              }
            });
          } finally {
            try {
              stopTimer();
            } catch (e) {
              /* ignore timer errors */
            }
            requestSpan.end();
          }
        })
    : runAuthz;

  return {
    engine,
    cache,
    metrics,
    mode,
    userAuthEnabled,
    validator,
    audit,
    serviceIdentity,
    middleware,
    attachOutbound: (axiosInstance: AxiosLike) => {
      // A5: robust and ergonomic — works even without a serviceToken configured.
      // When serviceIdentity is absent, buildOutboundHeaders omits X-Service-Token
      // (F4/G5) and still propagates user JWT + trace headers (G4 fail-open).
      attachOutboundPropagation(axiosInstance, { serviceIdentity });
    },
    createClient: (config?: Record<string, unknown>) => {
      const instance = axios.create(config ?? {}) as AxiosLike;
      attachOutboundPropagation(instance, { serviceIdentity });
      return instance;
    },
    health: () =>
      // SERVICE-ONLY mode (§0.5): no cache machinery — report an empty cache in
      // normal mode (cache-related fields are not meaningful without user auth).
      boot
        ? buildHealth(cache, boot.mode_(), {
            roleServiceLastSync: boot.roleServiceLastSync(),
            kafkaConsumerConnected: boot.isKafkaConnected(),
          })
        : buildHealth(cache, "normal", {
            roleServiceLastSync: null,
            kafkaConsumerConnected: false,
          }),
    stop: async () => {
      boot?.stop();
      if (events) await events.stop();
      // Cancel the outbound provider's proactive-refresh timer so the process
      // can exit cleanly (graceful shutdown — clear timers/intervals).
      if (serviceIdentity && typeof (serviceIdentity as { close?: () => void }).close === "function") {
        (serviceIdentity as { close: () => void }).close();
      }
    },
  };
}

/**
 * Bootstrap authorization from AUTHZ_* environment variables only.
 *
 * This is the default public entrypoint and does not accept injected options.
 */
export async function createAuthz(): Promise<Authz> {
  return createAuthzFromOptions(optionsFromEnv(process.env) as CreateAuthzOptions);
}
