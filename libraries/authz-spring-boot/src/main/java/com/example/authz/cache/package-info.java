/**
 * In-memory role-to-permissions cache. Copy-on-replace with atomic snapshot
 * semantics; single-writer lock serialises concurrent Kafka events and
 * reconciler full-replaces (architecture §4, C2/C6).
 */
package com.example.authz.cache;
