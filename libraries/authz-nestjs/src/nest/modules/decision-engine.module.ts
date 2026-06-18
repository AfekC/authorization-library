import * as fs from "fs";
import { Module } from "@nestjs/common";
import { loadAuthorizationConfig } from "../../rule-config/loader.js";
import { CreateAuthzOptions } from "../../bootstrap/create-authz.js";
import { AUTHZ_OPTIONS, AUTHZ_ENGINE } from "../authz-options.js";

@Module({
  providers: [
    {
      provide: AUTHZ_ENGINE,
      useFactory: (opts: CreateAuthzOptions) => {
        const yaml = opts.authorizationYaml
          ?? (opts.authorizationYamlPath
            ? fs.readFileSync(opts.authorizationYamlPath, "utf8")
            : (() => { throw new Error("AuthzModule requires authorizationYaml or authorizationYamlPath"); })());
        return loadAuthorizationConfig(yaml); // fail-fast on config error
      },
      inject: [AUTHZ_OPTIONS],
    },
  ],
  exports: [AUTHZ_ENGINE],
})
export class DecisionEngineModule {}
