package com.example.authz;

import com.example.authz.cache.PermissionCache;
import com.example.authz.engine.AuthType;
import com.example.authz.engine.AuthorizationEngine;
import com.example.authz.engine.AuthorizationRequest;
import com.example.authz.engine.Decision;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

/**
 * Loads the language-neutral vectors in docs/contracts/test-vectors and asserts the
 * Java engine produces the same decisions as the NestJS engine.
 */
class SharedVectorsTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static Path vectorDir() {
        // Resolved relative to the module working directory (repo/libraries/authz-spring-boot).
        Path here = Path.of(System.getProperty("user.dir"));
        Path candidate = here.resolve("../../docs/contracts/test-vectors").normalize();
        if (Files.isDirectory(candidate)) return candidate;
        // Fallback: repo root mounted at user.dir
        return here.resolve("docs/contracts/test-vectors").normalize();
    }

    @TestFactory
    Stream<DynamicTest> sharedVectors() throws IOException {
        Path dir = vectorDir();
        List<DynamicTest> tests = new ArrayList<>();
        try (Stream<Path> files = Files.list(dir)) {
            List<Path> vectorFiles = files
                    .filter(p -> p.getFileName().toString().endsWith(".vectors.json"))
                    .sorted()
                    .toList();
            for (Path file : vectorFiles) {
                JsonNode arr = MAPPER.readTree(Files.readString(file));
                for (JsonNode v : arr) {
                    String name = file.getFileName() + " :: " + v.get("name").asText();
                    tests.add(dynamicTest(name, () -> runVector(v)));
                }
            }
        }
        return tests.stream();
    }

    @SuppressWarnings("unchecked")
    private void runVector(JsonNode v) throws IOException {
        List<Map<String, Object>> rules =
                MAPPER.convertValue(v.get("rules"), List.class);

        if (v.has("expectCompileError") && v.get("expectCompileError").asBoolean()) {
            assertThrows(RuntimeException.class, () -> AuthorizationEngine.compile(rules));
            return;
        }

        AuthorizationEngine engine = AuthorizationEngine.compile(rules);

        Map<String, List<String>> roleCache = new HashMap<>();
        if (v.has("roleCache")) {
            roleCache = MAPPER.convertValue(v.get("roleCache"), Map.class);
        }
        PermissionCache cache = new PermissionCache((Map) roleCache);

        JsonNode req = v.get("request");
        AuthorizationRequest request = new AuthorizationRequest(
                req.get("method").asText(),
                req.get("path").asText(),
                AuthType.valueOf(req.get("authType").asText()),
                req.has("role") ? req.get("role").asText() : null,
                req.has("serviceName") ? req.get("serviceName").asText() : null);

        Decision expected = Decision.valueOf(v.get("expected").asText());
        assertEquals(expected, engine.authorize(request, cache),
                "vector: " + v.get("name").asText());
    }
}
