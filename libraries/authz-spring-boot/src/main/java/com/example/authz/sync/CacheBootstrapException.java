package com.example.authz.sync;

/**
 * Thrown at startup when there is no usable role state to serve: the Role
 * Service is unreachable AND the disk cache is missing, unreadable, or empty.
 * Propagates out of {@code CacheBootstrap.start()} so the application refuses to
 * start instead of silently serving an empty cache.
 */
public class CacheBootstrapException extends RuntimeException {
    public CacheBootstrapException(String message) {
        super(message);
    }
}
