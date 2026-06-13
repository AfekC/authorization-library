import { Module } from "@nestjs/common";
import { PermissionCache } from "../../permission-cache/cache";
import { AUTHZ_CACHE } from "../authz-options";

@Module({
  providers: [{ provide: AUTHZ_CACHE, useFactory: () => new PermissionCache() }],
  exports: [AUTHZ_CACHE],
})
export class PermissionCacheModule {}
