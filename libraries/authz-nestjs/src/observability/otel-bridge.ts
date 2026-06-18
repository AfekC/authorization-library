import { createRequire } from "module";
import { Metrics, METRIC, GAUGE } from "./metrics.js";
import { isObservabilityEnabled } from "./otel.js";

/**
 * Mirror the in-process {@link Metrics} counters/gauges onto an OpenTelemetry
 * meter as observable instruments, so they are scraped by the Prometheus
 * exporter that `@hatraa/otel-ts` stands up (default :9464/metrics).
 *
 * Cumulative counters → observable counters; gauges → observable gauges. Each
 * instrument's callback reads the live value from `metrics.get(name)` on every
 * collection, so this is a one-time registration with no polling.
 *
 * No-op when observability is disabled. Only the well-known base series
 * (8 counters + 2 gauges) are registered; per-mode token-failure suffixes remain
 * available via the in-process snapshot/health API.
 */
export function bridgeMetricsToOtel(metrics: Metrics, meterName = "authz"): void {
  if (!isObservabilityEnabled()) return;
  const require = createRequire(import.meta.url);
  const { createMeter } = require("@hatraa/otel-ts") as typeof import("@hatraa/otel-ts");
  const meter = createMeter(meterName);

  for (const name of Object.values(METRIC)) {
    const counter = meter.createObservableCounter(name);
    counter.addCallback((res) => res.observe(metrics.get(name)));
  }
  for (const name of Object.values(GAUGE)) {
    const gauge = meter.createObservableGauge(name);
    gauge.addCallback((res) => res.observe(metrics.get(name)));
  }
}
