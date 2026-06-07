/**
 * Service Provider Interfaces (architecture §11). All extension points:
 * {@code TokenValidator}, {@code ServiceIdentityProvider}, {@code RoleResolver},
 * {@code PolicyEngine}, {@code AttributeProvider}, {@code RoleServiceClient},
 * {@code CacheEventHandler}, {@code AuditSink}. Swap implementations without
 * touching auth logic.
 */
package com.example.authz.spi;
