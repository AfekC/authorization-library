import { ModuleMetadata } from "@nestjs/common";
import { CreateAuthzOptions } from "../bootstrap/create-authz";

/** Injection token carrying the resolved CreateAuthzOptions to every feature module. */
export const AUTHZ_OPTIONS = "AUTHZ_OPTIONS";

/** Async configuration for AuthzModule.forRootAsync (idiomatic Nest dynamic module). */
export interface AuthzModuleAsyncOptions extends Pick<ModuleMetadata, "imports"> {
  useFactory: (...args: any[]) => Promise<CreateAuthzOptions> | CreateAuthzOptions;
  inject?: any[];
}

export const AUTHZ_ENGINE = "AUTHZ_ENGINE";
export const AUTHZ_CACHE = "AUTHZ_CACHE";
export const AUTHZ_METRICS = "AUTHZ_METRICS";
export const AUTHZ_AUDIT = "AUTHZ_AUDIT";
export const AUTHZ_VALIDATOR = "AUTHZ_VALIDATOR";
export const AUTHZ_BOOTSTRAP = "AUTHZ_BOOTSTRAP";
export const AUTHZ_SERVICE_IDENTITY = "AUTHZ_SERVICE_IDENTITY";
export const AUTHZ_USER_AUTH_ENABLED = "AUTHZ_USER_AUTH_ENABLED";
