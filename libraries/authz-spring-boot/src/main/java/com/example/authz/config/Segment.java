package com.example.authz.config;

/** One segment of a compiled path pattern. value is set only for LITERAL. */
public record Segment(SegmentKind kind, String value) {
    public static Segment literal(String value) {
        return new Segment(SegmentKind.LITERAL, value);
    }

    public static Segment single() {
        return new Segment(SegmentKind.SINGLE, null);
    }

    public static Segment deep() {
        return new Segment(SegmentKind.DEEP, null);
    }
}
