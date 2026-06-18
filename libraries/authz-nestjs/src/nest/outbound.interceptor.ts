import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from "@nestjs/common";
import { Observable } from "rxjs";
import { runWithOutboundContext } from "../outbound/context-store.js";
import { REQUEST_CONTEXT_KEY } from "./request-context.decorator.js";

/**
 * Binds the inbound RequestContext (built by AuthzGuard) into the outbound
 * AsyncLocalStorage for the duration of the route handler, so an axios
 * interceptor registered via attachOutboundPropagation auto-attaches propagation
 * headers (§9/§12). Register globally via APP_INTERCEPTOR, after the guard.
 */
@Injectable()
export class AuthzOutboundInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const req = context.switchToHttp().getRequest();
    const ctx = req?.[REQUEST_CONTEXT_KEY];
    if (!ctx) return next.handle();
    const userJwt = req.authzUserJwt ?? null;
    return new Observable((subscriber) => {
      runWithOutboundContext(ctx, userJwt, () => {
        next.handle().subscribe(subscriber);
      });
    });
  }
}
