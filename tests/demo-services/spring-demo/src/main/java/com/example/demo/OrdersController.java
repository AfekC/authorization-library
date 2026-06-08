package com.example.demo;

import com.example.authz.context.RequestContext;
import com.example.authz.web.AuthorizationFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

/** Business routes — no authorization annotations; enforcement is global. */
@RestController
public class OrdersController {

    private final RestTemplate restTemplate;
    private final String downstreamUrl;

    public OrdersController(RestTemplateBuilder builder,
                            @Value("${DOWNSTREAM_URL:http://localhost:5001}") String downstreamUrl) {
        // RestTemplateBuilder applies the auto-configured OutboundPropagationInterceptor.
        this.restTemplate = builder.build();
        this.downstreamUrl = downstreamUrl;
    }

    @GetMapping("/orders/{id}")
    public Map<String, Object> getOrder(@PathVariable String id, HttpServletRequest req) {
        RequestContext ctx = (RequestContext) req.getAttribute(AuthorizationFilter.CONTEXT_ATTR);
        return Map.of("id", id, "by", ctx != null && ctx.userId() != null ? ctx.userId() : "unknown");
    }

    @GetMapping("/orders/{id}/audit")
    public Map<String, Object> auditOrder(@PathVariable String id) {
        return Map.of("id", id, "audit", true);
    }

    @PostMapping("/orders")
    public Map<String, Object> createOrder() {
        return Map.of("created", true);
    }

    @PostMapping("/orders/{id}")
    public Map<String, Object> updateOrder(@PathVariable String id, HttpServletRequest req) {
        RequestContext ctx = (RequestContext) req.getAttribute(AuthorizationFilter.CONTEXT_ATTR);
        // Echo what this downstream service saw, so callers can verify propagation.
        return Map.of(
                "id", id,
                "updated", true,
                "seenServiceName", ctx != null && ctx.serviceName() != null ? ctx.serviceName() : "none",
                "seenAuthType", ctx != null ? ctx.authenticationType().name() : "none",
                "seenCorrelationId", ctx != null ? ctx.correlationId() : "none",
                "seenUserId", ctx != null && ctx.userId() != null ? ctx.userId() : "none");
    }

    @PostMapping("/internal/reconcile")
    public Map<String, Object> reconcile(HttpServletRequest req) {
        RequestContext ctx = (RequestContext) req.getAttribute(AuthorizationFilter.CONTEXT_ATTR);
        return Map.of("reconciled", true, "by", ctx != null ? ctx.serviceName() : "unknown");
    }

    @PostMapping("/orders/{id}/forward")
    public Map<String, Object> forwardOrder(@PathVariable String id, HttpServletRequest req) {
        // The RestTemplate has the OutboundPropagationInterceptor auto-configured,
        // so it attaches the user JWT, service token, and correlation/request ids.
        try {
            var response = restTemplate.postForEntity(
                    downstreamUrl + "/orders/" + id,
                    null,
                    Map.class);
            return Map.of(
                    "forwarded", true,
                    "downstreamStatus", response.getStatusCode().value(),
                    "downstream", response.getBody());
        } catch (org.springframework.web.client.HttpClientErrorException e) {
            return Map.of(
                    "forwarded", false,
                    "downstreamStatus", e.getStatusCode().value(),
                    "downstream", e.getResponseBodyAs(Map.class));
        } catch (Exception e) {
            return Map.of(
                    "forwarded", false,
                    "error", "downstream service unavailable");
        }
    }
}
