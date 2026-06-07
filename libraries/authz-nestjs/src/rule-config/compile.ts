import { CompiledRule, ConfigError, DecisionMode, RuleInput, Segment } from "./types";
import { compareSpecificity, scoreSegment } from "../decision-engine/scoring";

const ALLOWED_KEYS = new Set([
  "path",
  "methods",
  "permissions",
  "decision",
  "allowedServices",
]);

function parseSegments(path: string): Segment[] {
  if (typeof path !== "string" || path.length === 0) {
    throw new ConfigError(`rule path must be a non-empty string`);
  }
  const raw = path.split("/").filter((s) => s.length > 0);
  return raw.map((value, idx) => {
    if (value === "**") {
      if (idx !== raw.length - 1) {
        throw new ConfigError(
          `"**" is only valid as the final segment in path "${path}"`,
        );
      }
      return { kind: "deep" } as Segment;
    }
    if (value === "*") return { kind: "single" } as Segment;
    if (value.includes("*")) {
      throw new ConfigError(
        `partial wildcards are not supported; use full-segment * or trailing ** only (segment "${value}" in "${path}")`,
      );
    }
    return { kind: "literal", value } as Segment;
  });
}

function compileOne(rule: RuleInput): CompiledRule {
  for (const key of Object.keys(rule)) {
    if (!ALLOWED_KEYS.has(key)) {
      throw new ConfigError(`unknown field "${key}" in rule`);
    }
  }
  if (!Array.isArray(rule.methods) || rule.methods.length === 0) {
    throw new ConfigError(`rule "${rule.path}" must list at least one method`);
  }
  let decision: DecisionMode = "ANY";
  if (rule.decision !== undefined) {
    if (rule.decision !== "ANY" && rule.decision !== "ALL") {
      throw new ConfigError(
        `invalid decision "${rule.decision}" (must be ANY or ALL)`,
      );
    }
    decision = rule.decision;
  }
  const segments = parseSegments(rule.path);
  const scores = segments.map(scoreSegment);
  const literalCount = segments.filter((s) => s.kind === "literal").length;

  return {
    path: rule.path,
    methods: new Set(rule.methods.map((m) => m.toUpperCase())),
    permissions:
      rule.permissions && rule.permissions.length > 0
        ? [...rule.permissions]
        : undefined,
    decision,
    allowedServices:
      rule.allowedServices && rule.allowedServices.length > 0
        ? [...rule.allowedServices]
        : undefined,
    segments,
    scores,
    literalCount,
  };
}

/** Two tied rules are ambiguous only if they can match a common path. */
function patternsOverlap(a: CompiledRule, b: CompiledRule): boolean {
  // Tie from compareSpecificity implies identical score vectors -> same length & kinds.
  // They overlap unless a literal position disagrees.
  const n = Math.min(a.segments.length, b.segments.length);
  for (let i = 0; i < n; i++) {
    const sa = a.segments[i];
    const sb = b.segments[i];
    if (sa.kind === "deep" || sb.kind === "deep") return true;
    if (
      sa.kind === "literal" &&
      sb.kind === "literal" &&
      sa.value !== sb.value
    ) {
      return false;
    }
  }
  return true;
}

function methodsIntersect(a: CompiledRule, b: CompiledRule): boolean {
  for (const m of a.methods) if (b.methods.has(m)) return true;
  return false;
}

/**
 * Compile + validate the rule set. Fails fast (throws ConfigError) on unknown
 * fields, invalid decision, malformed wildcard, or genuine ambiguity.
 */
export function compileRules(rules: RuleInput[]): CompiledRule[] {
  const compiled = rules.map(compileOne);
  for (let i = 0; i < compiled.length; i++) {
    for (let j = i + 1; j < compiled.length; j++) {
      if (
        compareSpecificity(compiled[i], compiled[j]) === 0 &&
        methodsIntersect(compiled[i], compiled[j]) &&
        patternsOverlap(compiled[i], compiled[j])
      ) {
        throw new ConfigError(
          `ambiguous rules: "${compiled[i].path}" and "${compiled[j].path}" ` +
            `have identical specificity for an overlapping path+method`,
        );
      }
    }
  }
  return compiled;
}
