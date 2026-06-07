import { CompiledRule, Segment } from "../rule-config/types";

/** Split a request path into segments, ignoring leading/trailing slashes. */
export function splitPath(path: string): string[] {
  return path.split("/").filter((s) => s.length > 0);
}

/** Score a single segment: literal=2, single (*) =1, deep (**) =0. */
export function scoreSegment(seg: Segment): number {
  switch (seg.kind) {
    case "literal":
      return 2;
    case "single":
      return 1;
    case "deep":
      return 0;
  }
}

/**
 * Does a compiled pattern match the given path segments?
 * `*` matches exactly one segment; `**` matches one or more (final segment only).
 */
export function matchPath(segments: Segment[], pathSegs: string[]): boolean {
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    if (seg.kind === "deep") {
      // ** is always the final segment; it must consume at least one segment.
      return pathSegs.length - i >= 1;
    }
    if (i >= pathSegs.length) return false;
    if (seg.kind === "literal" && seg.value !== pathSegs[i]) return false;
    // single matches any one segment
  }
  return segments.length === pathSegs.length;
}

/**
 * Compare specificity of two compiled rules.
 * Returns >0 if `a` is more specific (should be preferred), <0 if `b` is, 0 if tied.
 * Order: segment scores left-to-right, then more literal segments, then longer pattern.
 */
export function compareSpecificity(a: CompiledRule, b: CompiledRule): number {
  const n = Math.min(a.scores.length, b.scores.length);
  for (let i = 0; i < n; i++) {
    if (a.scores[i] !== b.scores[i]) return a.scores[i] - b.scores[i];
  }
  if (a.literalCount !== b.literalCount) return a.literalCount - b.literalCount;
  if (a.segments.length !== b.segments.length) {
    return a.segments.length - b.segments.length;
  }
  return 0;
}
