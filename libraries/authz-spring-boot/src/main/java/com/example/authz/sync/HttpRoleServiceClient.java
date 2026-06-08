package com.example.authz.sync;

import com.example.authz.spi.Spi;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

/** HTTP client for the authoritative Role Service, backed by Spring {@link RestClient}. */
public class HttpRoleServiceClient implements Spi.RoleServiceClient {
    private static final ParameterizedTypeReference<Map<String, List<String>>> ROLE_MAP =
            new ParameterizedTypeReference<>() {};

    /** Default connect timeout in milliseconds (overridable via authz.role-service-connect-timeout-ms). */
    public static final int DEFAULT_CONNECT_TIMEOUT_MS = 5000;

    /** Default read timeout in milliseconds (overridable via authz.role-service-read-timeout-ms). */
    public static final int DEFAULT_READ_TIMEOUT_MS = 5000;

    private final RestClient http;

    /**
     * Creates a client with the default 5 s connect + 5 s read timeouts.
     *
     * @param baseUrl base URL of the Role Service (trailing slashes are stripped)
     */
    public HttpRoleServiceClient(String baseUrl) {
        this(baseUrl, DEFAULT_CONNECT_TIMEOUT_MS, DEFAULT_READ_TIMEOUT_MS);
    }

    /**
     * Overridable-timeout constructor. Allows tests and config-property
     * wiring to supply custom timeouts without needing new Maven dependencies.
     *
     * @param baseUrl          base URL of the Role Service
     * @param connectTimeoutMs TCP connect timeout in milliseconds
     * @param readTimeoutMs    socket read timeout in milliseconds
     */
    public HttpRoleServiceClient(String baseUrl, int connectTimeoutMs, int readTimeoutMs) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(connectTimeoutMs);
        factory.setReadTimeout(readTimeoutMs);
        this.http = RestClient.builder()
                .baseUrl(baseUrl.replaceAll("/+$", ""))
                .requestFactory(factory)
                .build();
    }

    /** {@code GET /roles} returns a bare {@code roleId -> permissions} map. */
    @Override
    public Map<String, List<String>> fetchSnapshot() {
        // retrieve() raises RestClientException (a RuntimeException) on non-2xx or I/O
        // failure, which CacheBootstrap treats as "Role Service unreachable" -> seed mode.
        Map<String, List<String>> roles = http.get()
                .uri("/roles")
                .retrieve()
                .body(ROLE_MAP);
        if (roles == null) {
            throw new RuntimeException("Role Service returned a malformed snapshot");
        }
        validateSnapshot(roles);
        return roles;
    }

    /**
     * Reject a malformed snapshot so {@link CacheBootstrap} treats it as a fetch
     * failure (seed/retry) rather than letting bad data corrupt the cache:
     * blank role ids, null permission lists, and blank permission entries are
     * all rejected. Mirrors the NestJS client's snapshot validation.
     */
    private static void validateSnapshot(Map<String, List<String>> roles) {
        for (Map.Entry<String, List<String>> e : roles.entrySet()) {
            String roleId = e.getKey();
            if (roleId == null || roleId.isBlank()) {
                throw new RuntimeException(
                        "Role Service returned a malformed snapshot: role id must be a non-blank string");
            }
            List<String> permissions = e.getValue();
            if (permissions == null) {
                throw new RuntimeException(
                        "Role Service returned a malformed snapshot: role \"" + roleId
                                + "\" permissions is null");
            }
            for (String perm : permissions) {
                if (perm == null || perm.isBlank()) {
                    throw new RuntimeException(
                            "Role Service returned a malformed snapshot: role \"" + roleId
                                    + "\" has a blank permission");
                }
            }
        }
    }
}
