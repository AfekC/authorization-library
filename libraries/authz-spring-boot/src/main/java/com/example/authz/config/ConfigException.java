package com.example.authz.config;

/** Thrown when authorization configuration is invalid (fail-fast at startup). */
public class ConfigException extends RuntimeException {
    public ConfigException(String message) {
        super(message);
    }
}
