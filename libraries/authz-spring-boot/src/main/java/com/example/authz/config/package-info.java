/**
 * Authorization configuration loading, rule compilation, and validation
 * (architecture §5). Processes {@code authorization.yaml} into type-safe
 * {@link com.example.authz.config.CompiledRule} instances with precomputed
 * matching metadata. Fails fast on config errors at startup.
 */
package com.example.authz.config;
