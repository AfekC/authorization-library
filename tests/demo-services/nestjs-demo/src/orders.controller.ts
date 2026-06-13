import { Body, Controller, Get, Inject, Param, Post } from "@nestjs/common";
import {
  AuthzContext,
  AUTHZ_SERVICE_IDENTITY,
  attachOutboundPropagation,
} from "authz-nestjs";
import type { RequestContext } from "authz-nestjs";
import axios, { AxiosInstance } from "axios";

const DOWNSTREAM = process.env.DOWNSTREAM_URL || "http://localhost:5002";

/**
 * Business routes — no authorization annotations. `@AuthzContext()` exposes the
 * validated RequestContext built by the global guard. Outbound forwarding uses an
 * axios instance with the library's propagation interceptor: it auto-attaches the
 * user JWT, this service's token, and the correlation/request ids for any call
 * made inside an authorized request (the inbound context flows via AsyncLocalStorage).
 */
@Controller("orders")
export class OrdersController {
  private readonly downstream: AxiosInstance;

  constructor(@Inject(AUTHZ_SERVICE_IDENTITY) serviceIdentity: any) {
    this.downstream = axios.create({ timeout: 5000 });
    attachOutboundPropagation(this.downstream, { serviceIdentity: serviceIdentity ?? undefined });
  }

  @Get(":id")
  get(@Param("id") id: string, @AuthzContext() ctx: RequestContext) {
    return { id, by: ctx.userId };
  }

  @Get(":id/audit")
  audit(@Param("id") id: string) {
    return { id, audit: true };
  }

  @Post()
  create() {
    return { created: true };
  }

  @Post(":id")
  update(@Param("id") id: string, @AuthzContext() ctx: RequestContext) {
    return {
      id,
      updated: true,
      seenServiceName: ctx?.serviceName || "none",
      seenAuthType: ctx?.authenticationType || "none",
      seenCorrelationId: ctx?.correlationId || "none",
      seenUserId: ctx?.userId || "none",
    };
  }

  @Post(":id/forward")
  async forward(@Param("id") id: string, @Body() body: any) {
    try {
      const r = await this.downstream.post(`${DOWNSTREAM}/orders/${id}`, body ?? {});
      return {
        forwarded: true,
        downstreamStatus: r.status,
        sentHeaders: {
          hasServiceToken: !!(
            r.config?.headers?.["X-Service-Token"] || r.config?.headers?.["x-service-token"]
          ),
          hasAuthorization: !!(
            r.config?.headers?.["Authorization"] || r.config?.headers?.["authorization"]
          ),
          correlationId:
            r.config?.headers?.["X-Correlation-Id"] || r.config?.headers?.["x-correlation-id"],
          requestId: r.config?.headers?.["X-Request-Id"] || r.config?.headers?.["x-request-id"],
        },
        downstream: r.data,
      };
    } catch (e: any) {
      if (e.response) {
        return {
          forwarded: false,
          downstreamStatus: e.response.status,
          downstream: e.response.data,
        };
      }
      throw e;
    }
  }
}
