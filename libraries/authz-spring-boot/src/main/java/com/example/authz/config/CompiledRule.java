package com.example.authz.config;

import java.util.List;
import java.util.Set;

/** A compiled, validated rule with precomputed matching/scoring metadata. */
public final class CompiledRule {
    private final String path;
    private final Set<String> methods;
    private final List<String> permissions; // null/empty -> no permission dimension
    private final DecisionMode decision;
    private final List<String> allowedServices; // null/empty -> no service dimension
    private final List<Segment> segments;
    private final int[] scores;
    private final int literalCount;

    public CompiledRule(String path, Set<String> methods, List<String> permissions,
                        DecisionMode decision, List<String> allowedServices,
                        List<Segment> segments, int[] scores, int literalCount) {
        this.path = path;
        this.methods = methods;
        this.permissions = permissions;
        this.decision = decision;
        this.allowedServices = allowedServices;
        this.segments = segments;
        this.scores = scores;
        this.literalCount = literalCount;
    }

    public String path() { return path; }
    public Set<String> methods() { return methods; }
    public List<String> permissions() { return permissions; }
    public DecisionMode decision() { return decision; }
    public List<String> allowedServices() { return allowedServices; }
    public List<Segment> segments() { return segments; }
    public int[] scores() { return scores; }
    public int literalCount() { return literalCount; }

    public boolean hasPermissions() { return permissions != null && !permissions.isEmpty(); }
    public boolean hasAllowedServices() { return allowedServices != null && !allowedServices.isEmpty(); }
}
