import { PermissionCache } from "../permission-cache/cache.js";
import {
  AuthorizationRequest,
  CompiledRule,
  Decision,
} from "../rule-config/types.js";
import { RoleResolver } from "../spi/index.js";

/** Anything with a permissionsForRole method — both PermissionCache and RoleResolver. */
type PermissionSource = {
  permissionsForRole(role: string | null | undefined): ReadonlySet<string>;
};

function permissionCheckPasses(
  rule: CompiledRule,
  role: string | null | undefined,
  source: PermissionSource,
): boolean {
  const required = rule.permissions ?? [];
  if (required.length === 0) return false;
  const held = source.permissionsForRole(role);
  if (rule.decision === "ALL") {
    return required.every((p) => held.has(p));
  }
  return required.some((p) => held.has(p));
}

function serviceCheckPasses(
  rule: CompiledRule,
  serviceName: string | null | undefined,
): boolean {
  const allowed = rule.allowedServices ?? [];
  if (allowed.length === 0) return false;
  if (allowed.includes("*")) return true;
  return serviceName != null && allowed.includes(serviceName);
}

/**
 * Apply the decision matrix for a single matched rule.
 * USER -> permission check; SERVICE -> allow-list check;
 * USER_AND_SERVICE -> both must pass. Any missing dimension -> DENY.
 */
export function decide(
  rule: CompiledRule,
  request: AuthorizationRequest,
  cache: PermissionCache,
): Decision {
  // public:true routes require no validation and are always allowed (§3.1, §5.1).
  if (rule.isPublic) return "ALLOW";

  const ruleHasPermissions = (rule.permissions?.length ?? 0) > 0;
  const ruleHasServices = (rule.allowedServices?.length ?? 0) > 0;

  switch (request.authType) {
    case "USER":
      if (!ruleHasPermissions) return "DENY";
      return permissionCheckPasses(rule, request.role, cache)
        ? "ALLOW"
        : "DENY";

    case "SERVICE":
      if (!ruleHasServices) return "DENY";
      return serviceCheckPasses(rule, request.serviceName) ? "ALLOW" : "DENY";

    case "USER_AND_SERVICE":
      if (!ruleHasPermissions || !ruleHasServices) return "DENY";
      return permissionCheckPasses(rule, request.role, cache) &&
        serviceCheckPasses(rule, request.serviceName)
        ? "ALLOW"
        : "DENY";
  }
}

/**
 * Same as `decide` but resolves permissions through a custom RoleResolver
 * instead of the PermissionCache (D12 SPI seam).
 */
export function decideWithResolver(
  rule: CompiledRule,
  request: AuthorizationRequest,
  resolver: RoleResolver,
): Decision {
  if (rule.isPublic) return "ALLOW";

  const ruleHasPermissions = (rule.permissions?.length ?? 0) > 0;
  const ruleHasServices = (rule.allowedServices?.length ?? 0) > 0;

  switch (request.authType) {
    case "USER":
      if (!ruleHasPermissions) return "DENY";
      return permissionCheckPasses(rule, request.role, resolver)
        ? "ALLOW"
        : "DENY";
    case "SERVICE":
      if (!ruleHasServices) return "DENY";
      return serviceCheckPasses(rule, request.serviceName) ? "ALLOW" : "DENY";
    case "USER_AND_SERVICE":
      if (!ruleHasPermissions || !ruleHasServices) return "DENY";
      return permissionCheckPasses(rule, request.role, resolver) &&
        serviceCheckPasses(rule, request.serviceName)
        ? "ALLOW"
        : "DENY";
  }
}
