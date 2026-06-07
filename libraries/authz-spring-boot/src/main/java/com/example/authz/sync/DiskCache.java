package com.example.authz.sync;

import com.example.authz.cache.PermissionCache;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Persists / loads the fallback cache file (authorization-cache.json). */
public final class DiskCache {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final Path path;

    public DiskCache(Path path) {
        this.path = path;
    }

    public record Snapshot(String timestamp, Map<String, List<String>> roles) {}

    public void write(PermissionCache cache) {
        Map<String, List<String>> roles = new LinkedHashMap<>();
        for (Map.Entry<String, Set<String>> e : cache.snapshot().entrySet()) {
            roles.put(e.getKey(), List.copyOf(e.getValue()));
        }
        try {
            MAPPER.writerWithDefaultPrettyPrinter()
                    .writeValue(path.toFile(), new Snapshot(Instant.now().toString(), roles));
        } catch (IOException e) {
            throw new RuntimeException("failed to write disk cache: " + e.getMessage(), e);
        }
    }

    public boolean exists() {
        return Files.exists(path);
    }

    /** Read the seed snapshot, or null if absent/unreadable. */
    public Snapshot read() {
        if (!exists()) return null;
        try {
            return MAPPER.readValue(path.toFile(), Snapshot.class);
        } catch (IOException e) {
            return null;
        }
    }
}
