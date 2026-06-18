import { AsyncLocalStorage } from "async_hooks";
import { RequestContext } from "../inbound-auth/context.js";

/** What an outbound call needs to propagate the inbound identity downstream. */
export interface OutboundContext {
  ctx: RequestContext;
  userJwt: string | null;
}

/**
 * Carries the inbound RequestContext (+ user JWT) across the async call chain so
 * an axios/HttpService interceptor can attach propagation headers automatically
 * (architecture §9/§12), without the handler threading them through by hand.
 */
const storage = new AsyncLocalStorage<OutboundContext>();

/** Run `fn` with the given outbound context bound for the duration of the call. */
export function runWithOutboundContext(
  ctx: RequestContext,
  userJwt: string | null,
  fn: () => void,
): void {
  storage.run({ ctx, userJwt }, fn);
}

/** The outbound context for the in-flight request, or undefined outside one. */
export function currentOutboundContext(): OutboundContext | undefined {
  return storage.getStore();
}
