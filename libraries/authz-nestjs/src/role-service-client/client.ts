import axios, { AxiosInstance } from "axios";
import { RoleMap, RoleServiceClient, VersionedRoleEntry, VersionedSnapshot } from "../spi/index.js";

/**
 * Default connect + read timeout for the Role Service HTTP client (ms).
 * Override via {@link RoleServiceConfig.timeoutMs} or — once wired — via
 * the `createAuthz` option `roleServiceTimeoutMs` (E7: deferred).
 */
export const DEFAULT_ROLE_SERVICE_TIMEOUT_MS = 5000;

export interface RoleServiceConfig {
  baseUrl: string;
  timeoutMs?: number;
  /** Connect timeout in ms (default 5000). Takes precedence over timeoutMs when set. */
  connectTimeoutMs?: number;
  /** Read timeout in ms (default 5000). Takes precedence over timeoutMs when set. */
  readTimeoutMs?: number;
}

/**
 * T24 — Normalised snapshot: the Role Service may return either legacy
 * `{ roleId: string[] }` or versioned `{ roleId: { permissions, version } }` per
 * entry. This type always carries both the plain role map and per-role version data.
 */
export interface NormalisedSnapshot {
  /** Plain permissions map for cache application (backward-compatible with RoleMap). */
  roles: RoleMap;
  /**
   * Per-role version numbers extracted from versioned entries. Absent (undefined) for
   * a roleId means the Role Service sent a legacy unversioned entry for that role.
   */
  versions: Map<string, number>;
}

/** HTTP client for the authoritative Role Service. */
export class HttpRoleServiceClient implements RoleServiceClient {
  private readonly http: AxiosInstance;

  constructor(cfg: RoleServiceConfig) {
    const connectTimeout = cfg.connectTimeoutMs ?? cfg.timeoutMs ?? DEFAULT_ROLE_SERVICE_TIMEOUT_MS;
    const readTimeout = cfg.readTimeoutMs ?? cfg.timeoutMs ?? DEFAULT_ROLE_SERVICE_TIMEOUT_MS;
    // Use the larger of the two timeouts for the axios-level timeout (which
    // covers both connect and read). For frameworks (nock) that intercept at
    // the http.request layer, custom agents are not used, so a separate connect
    // timeout is not meaningful; the single axios timeout covers both cases.
    const timeout = readTimeout > connectTimeout ? readTimeout : connectTimeout;
    this.http = axios.create({
      baseURL: cfg.baseUrl,
      timeout,
    });
  }

  /**
   * `GET /roles` returns either a bare `roleId -> string[]` map (legacy) or a
   * `roleId -> { permissions, version }` map (T24 versioned format). Both shapes
   * are accepted; fetchSnapshot() strips version info and returns a plain RoleMap
   * for compatibility with the RoleServiceClient SPI.
   *
   * Use fetchNormalisedSnapshot() to obtain both the permissions and the per-role
   * version numbers from a single fetch.
   */
  async fetchSnapshot(): Promise<RoleMap> {
    const { roles } = await this.fetchNormalisedSnapshot();
    return roles;
  }

  /**
   * T24 — Fetch the authoritative snapshot and return both the plain role map and
   * any per-role version numbers the Role Service included. Callers that need version
   * data (e.g. CacheBootstrap) should prefer this method.
   */
  async fetchNormalisedSnapshot(): Promise<NormalisedSnapshot> {
    const { data } = await this.http.get<VersionedSnapshot>("/roles");
    if (typeof data !== "object" || data === null || Array.isArray(data)) {
      throw new Error("Role Service returned a malformed snapshot");
    }

    const roles: RoleMap = {};
    const versions = new Map<string, number>();

    for (const [roleId, value] of Object.entries(data)) {
      // Reject blank role ids: an empty-string key would create a phantom role
      // that silently never matches (parity with the Java client's validation).
      if (typeof roleId !== "string" || roleId.trim().length === 0) {
        throw new Error(
          "Role Service returned a malformed snapshot: role id must be a non-empty string",
        );
      }

      let permissions: unknown[];
      let version: number | undefined;

      if (Array.isArray(value)) {
        // Legacy format: bare string[]
        permissions = value;
      } else if (
        value !== null &&
        typeof value === "object" &&
        Array.isArray((value as VersionedRoleEntry).permissions) &&
        typeof (value as VersionedRoleEntry).version === "number"
      ) {
        // T24 versioned format: { permissions: string[], version: number }
        permissions = (value as VersionedRoleEntry).permissions;
        version = (value as VersionedRoleEntry).version;
      } else {
        throw new Error(
          `Role Service returned a malformed snapshot: role "${roleId}" has an unexpected value shape`,
        );
      }

      // Q2: validate every permission is a string.
      for (const perm of permissions) {
        if (typeof perm !== "string") {
          throw new Error(
            `Role Service returned a malformed snapshot: role "${roleId}" contains a non-string permission`,
          );
        }
      }

      roles[roleId] = permissions as string[];
      if (version !== undefined) {
        versions.set(roleId, version);
      }
    }

    return { roles, versions };
  }
}
