import { Module } from "@nestjs/common";
import { PermissionCache } from "../../permission-cache/cache.js";
import { AUTHZ_CACHE } from "../authz-options.js";

@Module({
  providers: [{ provide: AUTHZ_CACHE, useFactory: () => new PermissionCache() }],
  exports: [AUTHZ_CACHE],
})
export class PermissionCacheModule {}
