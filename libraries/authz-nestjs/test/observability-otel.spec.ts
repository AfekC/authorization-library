/**
 * Tests for the opt-in @hatraa/otel-ts integration (observability wiring).
 *
 * The SDK is mocked so no real OpenTelemetry providers, Prometheus server, or
 * native @datadog/pprof addon are loaded. We assert that:
 *   - initObservability maps config onto otelConfig and is idempotent
 *   - bridgeMetricsToOtel registers an observable instrument per metric/gauge,
 *     whose callback reports the live in-process value
 *   - OtelAuditSink.emit routes through otelLogger (INFO for ALLOW, WARN for DENY)
 *   - createAuthz({observability:{enabled}}) inits the SDK, selects OtelAuditSink,
 *     and wraps the decision path in a span
 */

jest.mock("@hatraa/otel-ts", () => {
  const observables: Array<{ _cb?: (res: { observe: (v: number) => void }) => void }> = [];
  const makeObservable = () => {
    const inst: any = {};
    inst.addCallback = jest.fn((cb: any) => {
      inst._cb = cb;
    });
    observables.push(inst);
    return inst;
  };
  const meter = {
    createObservableCounter: jest.fn(() => makeObservable()),
    createObservableGauge: jest.fn(() => makeObservable()),
  };
  const span = {
    setAttribute: jest.fn(),
    recordException: jest.fn(),
    end: jest.fn(),
  };
  const tracer = {
    startActiveSpan: jest.fn((_name: string, fn: any) => fn(span)),
  };
  return {
    __esModule: true,
    otelConfig: jest.fn(),
    createMeter: jest.fn(() => meter),
    createTracer: jest.fn(() => tracer),
    otelLogger: jest.fn(),
    __mock: { meter, tracer, span, observables },
  };
});

import nock from "nock";
import * as o11y from "@hatraa/otel-ts";
import {
  initObservability,
  isObservabilityEnabled,
} from "../src/observability/otel";
import { bridgeMetricsToOtel } from "../src/observability/otel-bridge";
import { OtelAuditSink } from "../src/observability/otel-audit-sink";
import { Metrics, METRIC, GAUGE } from "../src/observability/metrics";
import { AuditEvent } from "../src/spi";
import { createAuthzFromOptions } from "../src/bootstrap/create-authz";

const mock = (o11y as any).__mock;

const ROLE_SERVICE_URL = "http://localhost:18170";
const VALID_YAML = `
rules:
  - path: "/api/test"
    methods: ["GET"]
    permissions: ["read"]
`;

function baseEvent(result: "ALLOW" | "DENY"): AuditEvent {
  return {
    timestamp: new Date().toISOString(),
    userId: "u1",
    roleId: "viewer",
    serviceName: null,
    path: "/api/test",
    method: "GET",
    permission: "read",
    result,
    authenticationType: "USER",
    requestId: "req-1",
    correlationId: "corr-1",
  };
}

afterEach(() => {
  jest.clearAllMocks();
  nock.cleanAll();
});

describe("initObservability", () => {
  it("maps config onto otelConfig and is idempotent", () => {
    const active = initObservability({
      enabled: true,
      serviceName: "svc",
      systemName: "sys",
      envName: "drill",
      otelExporterOtlpEndpoint: "http://collector:4317",
    });
    expect(active).toBe(true);
    expect(isObservabilityEnabled()).toBe(true);
    expect(o11y.otelConfig).toHaveBeenCalledWith({
      serviceName: "svc",
      systemName: "sys",
      envName: "drill",
      otelExporterOtlpEndpoint: "http://collector:4317",
    });

    // Second call is a no-op (already initialized).
    initObservability({ enabled: true, serviceName: "other" });
    expect(o11y.otelConfig).toHaveBeenCalledTimes(1);
  });
});

describe("bridgeMetricsToOtel", () => {
  it("registers an observable instrument per metric/gauge that reports live values", () => {
    const metrics = new Metrics();
    metrics.inc(METRIC.authzSuccess);
    metrics.inc(METRIC.authzSuccess);
    metrics.setGauge(GAUGE.cacheAgeSeconds, 7);

    bridgeMetricsToOtel(metrics);

    expect(mock.meter.createObservableCounter).toHaveBeenCalledTimes(
      Object.keys(METRIC).length,
    );
    expect(mock.meter.createObservableGauge).toHaveBeenCalledTimes(
      Object.keys(GAUGE).length,
    );

    // Every instrument's callback observes the current in-process value.
    let observed = -1;
    const successInst = mock.observables.find((i: any) => i.addCallback.mock.calls.length);
    // Drive all callbacks; assert at least one reports the success counter (2).
    const seen: number[] = [];
    for (const inst of mock.observables) {
      inst._cb?.({ observe: (v: number) => seen.push(v) });
    }
    observed = Math.max(...seen);
    expect(successInst).toBeDefined();
    expect(seen).toContain(2); // authz_success_total
    expect(seen).toContain(7); // permission_cache_version
    expect(observed).toBeGreaterThanOrEqual(7);
  });
});

describe("OtelAuditSink", () => {
  it("emits ALLOW at INFO and DENY at WARN through otelLogger", () => {
    const sink = new OtelAuditSink();
    sink.emit(baseEvent("ALLOW"));
    sink.emit(baseEvent("DENY"));

    expect(o11y.otelLogger).toHaveBeenCalledTimes(2);
    const first = (o11y.otelLogger as jest.Mock).mock.calls[0][0];
    const second = (o11y.otelLogger as jest.Mock).mock.calls[1][0];
    expect(first.level).toBe("INFO");
    expect(first.message).toContain("ALLOW");
    expect(first.path).toBe("/api/test");
    expect(second.level).toBe("WARN");
  });
});

describe("createAuthz with observability enabled", () => {
  it("inits the SDK, selects OtelAuditSink, and wraps the decision in a span", async () => {
    nock(ROLE_SERVICE_URL).get("/roles").reply(200, { viewer: ["read"] });

    const authz = await createAuthzFromOptions({
      userIssuer: "https://issuer",
      userJwksUri: "https://jwks",
      serviceIssuer: "https://sso",
      serviceJwksUri: "https://sso-jwks",
      audience: "my-app",
      roleServiceUrl: ROLE_SERVICE_URL,
      authorizationYaml: VALID_YAML,
      reconcileIntervalMs: 999999,
      observability: { enabled: true, serviceName: "authz-test" },
    });

    try {
      expect(o11y.createMeter).toHaveBeenCalled();
      expect(o11y.createTracer).toHaveBeenCalledWith("authz");
      expect(authz.audit).toBeInstanceOf(OtelAuditSink);

      // Drive the middleware (no creds → 401) and confirm it ran inside a span.
      const res = {
        statusCode: 0,
        body: undefined as unknown,
        status(code: number) {
          this.statusCode = code;
          return this;
        },
        json(b: unknown) {
          this.body = b;
          return this;
        },
      };
      await authz.middleware({ headers: {}, method: "GET", url: "/api/test" }, res, () => {});
      expect(mock.tracer.startActiveSpan).toHaveBeenCalledWith("authz.decision", expect.any(Function));
      expect(mock.span.end).toHaveBeenCalled();
      expect(res.statusCode).toBe(401);
    } finally {
      await authz.stop();
    }
  });
});
