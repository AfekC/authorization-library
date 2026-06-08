package com.example.authz.sync;

import com.example.authz.cache.PermissionCache;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
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
        // Atomic write: serialize to a sibling temp file, then move it onto the
        // target. The move is atomic on the same filesystem, so a crash mid-write
        // can never leave a half-written authorization-cache.json — the previous
        // file stays intact until the complete new one replaces it in one step.
        Path dir = path.toAbsolutePath().getParent();
        Path tmp;
        try {
            tmp = Files.createTempFile(dir, ".authz-cache", ".tmp");
        } catch (IOException e) {
            throw new RuntimeException("failed to create temp file for disk cache: " + e.getMessage(), e);
        }
        try {
            MAPPER.writerWithDefaultPrettyPrinter()
                    .writeValue(tmp.toFile(), new Snapshot(Instant.now().toString(), roles));
            try {
                Files.move(tmp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException unsupported) {
                // Some filesystems don't support atomic moves; fall back to a plain replace.
                Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            try {
                Files.deleteIfExists(tmp);
            } catch (IOException ignore) {
                // best-effort cleanup of the temp file
            }
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
