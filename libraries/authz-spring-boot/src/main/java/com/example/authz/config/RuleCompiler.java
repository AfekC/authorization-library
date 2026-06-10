package com.example.authz.config;

import com.example.authz.engine.Scoring;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Compiles + validates raw rule maps (from YAML/JSON) into CompiledRules.
 * Fails fast on unknown fields, invalid decision, malformed wildcards, ambiguity.
 */
public final class RuleCompiler {
    private static final Set<String> ALLOWED_KEYS =
            Set.of("path", "methods", "permissions", "decision", "allowedServices", "public");

    private RuleCompiler() {}

    @SuppressWarnings("unchecked")
    public static List<CompiledRule> compile(List<Map<String, Object>> rawRules) {
        List<CompiledRule> compiled = new ArrayList<>();
        for (Map<String, Object> raw : rawRules) {
            compiled.add(compileOne(raw));
        }
        for (int i = 0; i < compiled.size(); i++) {
            for (int j = i + 1; j < compiled.size(); j++) {
                if (Scoring.compareSpecificity(compiled.get(i), compiled.get(j)) == 0
                        && methodsIntersect(compiled.get(i), compiled.get(j))
                        && patternsOverlap(compiled.get(i), compiled.get(j))) {
                    throw new ConfigException("ambiguous rules: \"" + compiled.get(i).path()
                            + "\" and \"" + compiled.get(j).path()
                            + "\" have identical specificity for an overlapping path+method");
                }
            }
        }
        return compiled;
    }

    @SuppressWarnings("unchecked")
    private static CompiledRule compileOne(Map<String, Object> raw) {
        for (String key : raw.keySet()) {
            if (!ALLOWED_KEYS.contains(key)) {
                throw new ConfigException("unknown field \"" + key + "\" in rule");
            }
        }
        Object pathObj = raw.get("path");
        if (!(pathObj instanceof String path) || path.isEmpty()) {
            throw new ConfigException("rule path must be a non-empty string");
        }
        Object methodsObj = raw.get("methods");
        if (!(methodsObj instanceof List<?> methodsList) || methodsList.isEmpty()) {
            throw new ConfigException("rule \"" + path + "\" must list at least one method");
        }
        // methods: ["*"] matches any HTTP method; "*" upper-cases to itself.
        Set<String> methods = new LinkedHashSet<>();
        for (Object m : methodsList) methods.add(String.valueOf(m).toUpperCase());

        // public:true is a no-validation route — mutually exclusive with the
        // permission/service dimensions. Fail fast if combined (§3.1).
        boolean isPublic = false;
        Object publicObj = raw.get("public");
        if (publicObj != null) {
            if (!(publicObj instanceof Boolean b)) {
                throw new ConfigException("rule \"" + path + "\" field \"public\" must be a boolean");
            }
            isPublic = b;
        }
        if (isPublic) {
            if (raw.get("permissions") != null || raw.get("decision") != null
                    || raw.get("allowedServices") != null) {
                throw new ConfigException("rule \"" + path + "\" is public: \"permissions\", "
                        + "\"decision\", and \"allowedServices\" are not allowed on a public rule");
            }
        }

        DecisionMode decision = DecisionMode.ANY;
        Object decisionObj = raw.get("decision");
        if (decisionObj != null) {
            String d = String.valueOf(decisionObj);
            if (!d.equals("ANY") && !d.equals("ALL")) {
                throw new ConfigException("invalid decision \"" + d + "\" (must be ANY or ALL)");
            }
            decision = DecisionMode.valueOf(d);
        }

        List<String> permissions = toStringListOrNull(raw.get("permissions"), path, "permissions");
        List<String> allowedServices = toStringListOrNull(raw.get("allowedServices"), path, "allowedServices");

        List<Segment> segments = parseSegments(path);
        int[] scores = new int[segments.size()];
        int literalCount = 0;
        for (int i = 0; i < segments.size(); i++) {
            scores[i] = Scoring.scoreSegment(segments.get(i));
            if (segments.get(i).kind() == SegmentKind.LITERAL) literalCount++;
        }
        return new CompiledRule(path, methods, permissions, decision, allowedServices,
                segments, scores, literalCount, isPublic);
    }

    private static List<String> toStringListOrNull(Object obj, String path, String field) {
        if (!(obj instanceof List<?> list) || list.isEmpty()) return null;
        List<String> out = new ArrayList<>();
        for (Object o : list) {
            // Fail fast on blank entries: a blank permission/service name would
            // silently become an unreachable rule (it can never match a real
            // role permission or service name).
            if (o == null || String.valueOf(o).isBlank()) {
                throw new ConfigException(
                        "rule \"" + path + "\" has a blank entry in \"" + field + "\"");
            }
            out.add(String.valueOf(o));
        }
        return out;
    }

    private static List<Segment> parseSegments(String path) {
        List<String> raw = Scoring.splitPath(path);
        List<Segment> segs = new ArrayList<>();
        if (raw.isEmpty()) return segs;
        for (int i = 0; i < raw.size(); i++) {
            String value = raw.get(i);
            if (value.equals("**")) {
                if (i != raw.size() - 1) {
                    throw new ConfigException("\"**\" is only valid as the final segment in path \"" + path + "\"");
                }
                segs.add(Segment.deep());
            } else if (value.equals("*")) {
                segs.add(Segment.single());
            } else if (value.contains("*")) {
                throw new ConfigException("partial wildcards are not supported (segment \"" + value + "\" in \"" + path + "\")");
            } else {
                segs.add(Segment.literal(value));
            }
        }
        return segs;
    }

    private static boolean methodsIntersect(CompiledRule a, CompiledRule b) {
        // methods: ["*"] matches any method, so a wildcard on either side always intersects.
        if (a.matchesAnyMethod() || b.matchesAnyMethod()) return true;
        for (String m : a.methods()) if (b.methods().contains(m)) return true;
        return false;
    }

    private static boolean patternsOverlap(CompiledRule a, CompiledRule b) {
        int n = Math.min(a.segments().size(), b.segments().size());
        for (int i = 0; i < n; i++) {
            Segment sa = a.segments().get(i);
            Segment sb = b.segments().get(i);
            if (sa.kind() == SegmentKind.DEEP || sb.kind() == SegmentKind.DEEP) return true;
            if (sa.kind() == SegmentKind.LITERAL && sb.kind() == SegmentKind.LITERAL
                    && !sa.value().equals(sb.value())) {
                return false;
            }
        }
        return true;
    }
}
