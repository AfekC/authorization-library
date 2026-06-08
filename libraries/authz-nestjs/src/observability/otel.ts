import type { Environment } from "@hatraa/otel-ts";

/**
 * Opt-in observability via the in-house `@hatraa/otel-ts` SDK (OTLP/gRPC traces,
 * Prometheus metrics on :9464, structured JSON logs, HTTP + NestJS
 * auto-instrumentation). Disabled by default.
 *
 * The SDK is loaded with a lazy `require()` (see {@link loadO11y}) so that — when
 * observability is off — neither the heavy OpenTelemetry tree nor the native
 * `@datadog/pprof` addon that `@hatraa/otel-ts` pulls in at import are touched.
 */
export interface ObservabilityConfig {
  enabled: boolean;
  /** OTel `service.name` resource attribute (default "authz"). */
  serviceName?: string;
  /** `system` resource attribute (default "authz"). */
  systemName?: string;
  /** Deployment environment (default "live"). */
  envName?: Environment;
  /** OTLP/gRPC collector endpoint (e.g. http://localhost:4317). */
  otelExporterOtlpEndpoint?: string;
}

let initialized = false;

/** Lazily resolve the o11y SDK so it only loads when observability is enabled. */
function loadO11y(): typeof import("@hatraa/otel-ts") {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  return require("@hatraa/otel-ts") as typeof import("@hatraa/otel-ts");
}

/**
 * Initialize the global OpenTelemetry providers via `otelConfig()`.
 *
 * For full auto-instrumentation this MUST run before any instrumented module
 * (NestJS/HTTP) is imported — call it as the very first statement of your
 * application entrypoint. It is idempotent and a no-op when `enabled === false`.
 * `createAuthz` also calls it as a fallback so the metrics/trace/log bridges work
 * even if the app forgot (auto-instrumentation of already-loaded modules is then
 * the only thing missed).
 *
 * @returns whether observability is now active.
 */
export function initObservability(config: ObservabilityConfig): boolean {
  if (!config.enabled || initialized) return initialized;
  const { otelConfig } = loadO11y();
  otelConfig({
    serviceName: config.serviceName ?? "authz",
    systemName: config.systemName ?? "authz",
    envName: config.envName ?? "live",
    otelExporterOtlpEndpoint: config.otelExporterOtlpEndpoint,
  });
  initialized = true;
  return true;
}

/** True once {@link initObservability} has successfully run. */
export function isObservabilityEnabled(): boolean {
  return initialized;
}

/** Minimal structural view of the OTel tracer we use (avoids a hard @opentelemetry/api import). */
export interface AuthzTracer {
  startActiveSpan<T>(name: string, fn: (span: AuthzSpan) => T): T;
}
export interface AuthzSpan {
  setAttribute(key: string, value: string | number | boolean): void;
  recordException(error: unknown): void;
  end(): void;
}

/** Create a tracer for authorization spans, or `undefined` if observability is off. */
export function createAuthzTracer(name = "authz"): AuthzTracer | undefined {
  if (!initialized) return undefined;
  const { createTracer } = loadO11y();
  return createTracer(name) as unknown as AuthzTracer;
}
