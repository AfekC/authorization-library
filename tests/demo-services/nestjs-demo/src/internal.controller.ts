import { Controller, Post } from "@nestjs/common";
import { AuthzContext } from "authz-nestjs";
import type { RequestContext } from "authz-nestjs";

/**
 * Service-only endpoint: `POST /internal/reconcile` is a SERVICE rule (allow-list
 * [scheduler, batch]). A user JWT alone is denied by the global guard before this
 * handler runs.
 */
@Controller("internal")
export class InternalController {
  @Post("reconcile")
  reconcile(@AuthzContext() ctx: RequestContext) {
    return { reconciled: true, by: ctx?.serviceName };
  }
}
