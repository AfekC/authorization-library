import { PermissionCache } from "../permission-cache/cache";
import { CacheMode } from "../cache-sync/bootstrap";

/** Simple in-process counters/gauges (architecture §10.2). */
export class Metrics {
  private counters = new Map<string, number>();
  private gauges = new Map<string, number>();
  /** simple duration aggregates: we record _count and _sum for each base name */
  private durations = new Map<string, { count: number; sum: number }>();

  inc(name: string, by = 1): void {
    this.counters.set(name, (this.counters.get(name) ?? 0) + by);
  }

  incTokenFailure(base: string, mode: TokenFailureMode): void {
    this.inc(base);
    this.inc(`${base}_${mode}`);
  }

  setGauge(name: string, value: number): void {
    this.gauges.set(name, value);
  }

  /** Start a simple timer. Returns a stop() function that records the elapsed seconds. */
  startTimer(baseName: string): () => void {
    const start = Date.now();
    let stopped = false;
    return () => {
      if (stopped) return;
      stopped = true;
      const elapsed = (Date.now() - start) / 1000;
      this.recordDuration(baseName, elapsed);
    };
  }

  /** Record a duration (seconds) into `<base>_count` and `<base>_sum`. */
  recordDuration(baseName: string, seconds: number): void {
    const current = this.durations.get(baseName) ?? { count: 0, sum: 0 };
    current.count += 1;
    current.sum += seconds;
    this.durations.set(baseName, current);
    // expose as counters so bridge/snapshot picks them up
    this.counters.set(`${baseName}_count`, current.count);
    this.counters.set(`${baseName}_sum`, Math.round(current.sum * 1000) / 1000);
  }

  get(name: string): number {
    return this.counters.get(name) ?? this.gauges.get(name) ?? 0;
  }

  snapshot(): Record<string, number> {
    return {
      ...Object.fromEntries(this.counters),
      ...Object.fromEntries(this.gauges),
      // durations already mirrored into counters (base_count/base_sum)
    };
  }
}

export type TokenFailureMode = "expired" | "invalid_signature" | "malformed" | "other";

export function classifyTokenFailure(error: unknown): TokenFailureMode {
  const msg = error instanceof Error ? error.message.toLowerCase() : "";
  if (msg.includes("expired")) return "expired";
  if (msg.includes("signature") || msg.includes("verif")) return "invalid_signature";
  if (msg.includes("malform") || msg.includes("parse") || msg.includes("invalid jwt")) return "malformed";
  return "other";
}

export const METRIC = {
  authzSuccess: "authz_success_total",
  authzFailure: "authz_failure_total",
  permissionDenied: "authz_permission_denied_total",
  jwtValidationFailures: "jwt_validation_failures_total",
  serviceTokenFailures: "service_token_failures_total",
  serviceTokenFetchSuccess: "service_token_fetch_success_total",
  serviceTokenFetchDuration: "service_token_fetch_duration_seconds",
  roleEventSkipped: "role_event_skipped_total",
  roleRefreshFailures: "role_refresh_failures_total",
  roleRefreshSuccess: "role_refresh_success_total",
  roleEventsProcessed: "role_events_processed_total",
  roleEventProcessingDuration: "role_event_processing_duration_seconds",
  diskCacheWriteFailures: "disk_cache_write_failures_total",
  authzRequestDuration: "authz_request_duration_seconds",
} as const;

export const GAUGE = {
  cacheAgeSeconds: "permission_cache_age_seconds",
} as const;

export interface HealthReport {
  cacheStatus: "initialized" | "empty";
  cacheAgeSeconds: number;
  mode: CacheMode;
  roleServiceLastSync: string | null;
  kafkaConsumerConnected: boolean;
}

/** Build the health indicator (architecture §10.3). */
export function buildHealth(
  cache: PermissionCache,
  mode: CacheMode,
  extra?: { roleServiceLastSync?: Date | null; kafkaConsumerConnected?: boolean },
): HealthReport {
  const empty = Object.keys(cache.toSnapshot()).length === 0;
  return {
    cacheStatus: empty ? "empty" : "initialized",
    cacheAgeSeconds: Math.max(
      0,
      Math.floor((Date.now() - cache.lastUpdatedAt().getTime()) / 1000),
    ),
    mode,
    roleServiceLastSync: extra?.roleServiceLastSync
      ? extra.roleServiceLastSync.toISOString()
      : null,
    kafkaConsumerConnected: extra?.kafkaConsumerConnected ?? false,
  };
}
