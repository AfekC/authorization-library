/**
 * Outbound identity propagation (architecture §9/§12): service token acquisition
 * via OAuth2 client-credentials, auto-propagation headers (user JWT, service
 * token, trace IDs) for RestClient/RestTemplate, and fail-open handling.
 */
package com.example.authz.outbound;
