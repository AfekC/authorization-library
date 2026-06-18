import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import { RequestContext } from "../inbound-auth/context.js";

export const REQUEST_CONTEXT_KEY = "authzRequestContext";

/** Parameter decorator exposing the validated RequestContext to handlers. */
export const AuthzContext = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): RequestContext | undefined => {
    const req = ctx.switchToHttp().getRequest();
    return req[REQUEST_CONTEXT_KEY];
  },
);
