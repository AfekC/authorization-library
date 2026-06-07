import axios, { AxiosInstance } from "axios";
import { RoleMap, RoleServiceClient } from "../spi";

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

  /** `GET /roles` returns a bare `roleId -> permissions` map. */
  async fetchSnapshot(): Promise<RoleMap> {
    const { data } = await this.http.get<RoleMap>("/roles");
    if (typeof data !== "object" || data === null || Array.isArray(data)) {
      throw new Error("Role Service returned a malformed snapshot");
    }
    return data;
  }
}
