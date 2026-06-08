import * as fs from "fs";
import { AuthorizationEngine, auditPermission } from "../decision-engine/engine";
import { Decision, CompiledRule } from "../rule-config/types";
import { loadAuthorizationConfig } from "../rule-config/loader";
import { PermissionCache } from "../permission-cache/cache";
import {
  JwksTokenValidator,
  servicePrincipalFromClaims,
  userPrincipalFromClaims,
} from "../inbound-auth/token-validator";
import {
  buildRequestContext,
  stripUntrustedHeaders,
  RequestContext,
} from "../inbound-auth/context";
import { HttpRoleServiceClient } from "../role-service-client/client";
import { DiskCache } from "../cache-sync/disk";
import { KafkaCacheEventHandler } from "../cache-sync/kafka";
import { CacheBootstrap, CacheMode } from "../cache-sync/bootstrap";
import { LoggingAuditSink, buildAuditEvent } from "../audit/audit";
import { Metrics, METRIC, buildHealth, TokenFailureMode, classifyTokenFailure } from "../observability/metrics";
import { AuditSink, ServiceIdentityProvider, TokenValidator, RoleResolver, PolicyEngine, AttributeProvider } from "../spi";
import { extractBearer } from "../inbound-auth/bearer";
import { ClientCredentialsProvider } from "../service-token/provider";
import { runWithOutboundContext } from "../outbound/context-store";
import { attachOutboundPropagation, AxiosLike } from "../outbound/propagation";
import { ConfigError } from "../rule-config/types";

/**
 * Everything needed to stand up authorization in one call. Most fields have
 * sensible defaults; only the issuer/JWKS/role-service URLs are required.
 */
export interface CreateAuthzOptions {
  /** authorization.yaml as text, OR a path to it (one is required). */
  authorizationYaml?: string;
  authorizationYamlPath?: string;

  /** Trust roots. */
  userIssuer: string;
  userJwksUri: string;
  serviceIssuer: string;
  serviceJwksUri: string;
  audience: string;
  clockSkewSeconds?: number;

  /** Permission distribution. */
  roleServiceUrl: string;
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
  /** Periodic reconciler interval (ms). Default 5000. */
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
 * Usage:
 * ```ts
 * const authz = await createAuthz({ ...urls });
 * app.use(authz.middleware);   // global enforcement, no per-route opt-in
 * ```
 */
export async function createAuthz(opts: CreateAuthzOptions): Promise<Authz> {
  // P4: validation order matches Java's ConfigValidator order
  // userIssuer → userJwksUri → serviceIssuer → serviceJwksUri → roleServiceUrl → audience
  if (!opts.userIssuer) throw new ConfigError("Missing required option: userIssuer");
  if (!opts.userJwksUri) throw new ConfigError("Missing required option: userJwksUri");
  if (!opts.serviceIssuer) throw new ConfigError("Missing required option: serviceIssuer");
  if (!opts.serviceJwksUri) throw new ConfigError("Missing required option: serviceJwksUri");
  if (!opts.roleServiceUrl) throw new ConfigError("Missing required option: roleServiceUrl");
  if (!opts.audience || opts.audience.trim().length === 0)
    throw new ConfigError("Missing required option: audience");

  // Q4: URL well-formedness validation (http/https required)
  requireHttpUrl(opts.userIssuer, "userIssuer");
  requireHttpUrl(opts.userJwksUri, "userJwksUri");
  requireHttpUrl(opts.serviceIssuer, "serviceIssuer");
  requireHttpUrl(opts.serviceJwksUri, "serviceJwksUri");
  requireHttpUrl(opts.roleServiceUrl, "roleServiceUrl");
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
  const audit = opts.auditSink ?? new LoggingAuditSink();

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

  const events = opts.kafkaBrokers?.length
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
      })
    : undefined;

  // G11: best-effort startup reachability check for the token endpoint
  if (serviceIdentity) {
    await serviceIdentity.checkTokenEndpoint();
  }

  const boot = new CacheBootstrap(
    cache,
    new HttpRoleServiceClient({
      baseUrl: opts.roleServiceUrl,
      connectTimeoutMs: opts.roleServiceConnectTimeout ?? 5000,
      readTimeoutMs: opts.roleServiceReadTimeout ?? 5000,
    }),
    new DiskCache(opts.diskCachePath ?? "authorization-cache.json"),
    events,
    { metrics, logger: { warn: (m) => console.warn(m) } },
  );
  const { mode } = await boot.start();
  boot.startReconciler(opts.reconcileIntervalMs ?? 5000);

  const middleware = async (req: any, res: any, next: () => void) => {
    const headers = stripUntrustedHeaders(req.headers ?? {});
    const bearer = extractBearer(headers["authorization"]) ?? null;
    const serviceToken = (headers["x-service-token"] as string) ?? null;

    if (!bearer && !serviceToken) {
      metrics.inc(METRIC.authzFailure);
      res.status(401).json({ error: "no credentials" });
      return;
    }

    let user = null;
    let service = null;
    if (bearer) {
      try {
        user = userPrincipalFromClaims(await validator.validateUserToken(bearer));
      } catch (err) {
        metrics.incTokenFailure(METRIC.jwtValidationFailures, classifyTokenFailure(err));
        res.status(401).json({ error: "user token validation failed" });
        return;
      }
    }
    if (serviceToken) {
      try {
        service = servicePrincipalFromClaims(
          await validator.validateServiceToken(serviceToken),
        );
      } catch (err) {
        metrics.incTokenFailure(METRIC.serviceTokenFailures, classifyTokenFailure(err));
        res.status(401).json({ error: "service token validation failed" });
        return;
      }
    }

    const ctx = buildRequestContext({
      user,
      service,
      correlationId: headers["x-correlation-id"] as string,
      requestId: headers["x-request-id"] as string,
    });
    req.authz = ctx;

    // B9: strip any query string from the fallback req.url so the path used
    // for rule matching and audit is always the bare path component (stable,
    // consistent with Java's HttpServletRequest.getRequestURI() semantics).
    const rawPath: string = req.path ?? req.url ?? "";
    const requestPath = rawPath.split("?")[0];

    let decision: Decision;
    let matchedRule: CompiledRule | null = null;

    if (opts.policyEngine) {
      decision = opts.policyEngine.authorize({
        method: req.method,
        path: requestPath,
        authType: ctx.authenticationType,
        role: ctx.role,
        serviceName: ctx.serviceName,
      });
    } else if (opts.roleResolver) {
      decision = engine.authorizeWithResolver(
        { method: req.method, path: requestPath,
          authType: ctx.authenticationType,
          role: ctx.role, serviceName: ctx.serviceName },
        opts.roleResolver,
      );
      const rule = engine.matchRule(req.method, requestPath);
      if (rule) matchedRule = rule;
    } else {
      const result = engine.evaluate(
        { method: req.method, path: requestPath,
          authType: ctx.authenticationType,
          role: ctx.role, serviceName: ctx.serviceName },
        cache,
      );
      decision = result.decision;
      matchedRule = result.matchedRule;
    }
    audit.emit(
      buildAuditEvent({
        ctx,
        method: req.method,
        path: requestPath,
        permission: auditPermission(matchedRule),
        result: decision,
        policyVersion: cache.version(),
      }),
    );

    if (decision === "ALLOW") {
      metrics.inc(METRIC.authzSuccess);
      if (bearer) (req as AuthorizedRequest).authzUserJwt = bearer; // expose for outbound propagation
      runWithOutboundContext(ctx, bearer ?? null, next);
      return;
    }
    metrics.inc(METRIC.permissionDenied);
    res.status(403).json({ error: "authorization denied" });
  };

  return {
    engine,
    cache,
    metrics,
    mode,
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
      const axiosLib = require("axios");
      const instance = axiosLib.create(config ?? {}) as AxiosLike;
      attachOutboundPropagation(instance, { serviceIdentity });
      return instance;
    },
    health: () =>
      buildHealth(cache, boot.mode_(), {
        roleServiceLastSync: boot.roleServiceLastSync(),
        kafkaConsumerConnected: boot.isKafkaConnected(),
      }),
    stop: async () => {
      boot.stop();
      if (events) await events.stop();
      // Cancel the outbound provider's proactive-refresh timer so the process
      // can exit cleanly (graceful shutdown — clear timers/intervals).
      if (serviceIdentity && typeof (serviceIdentity as { close?: () => void }).close === "function") {
        (serviceIdentity as { close: () => void }).close();
      }
    },
  };
}
