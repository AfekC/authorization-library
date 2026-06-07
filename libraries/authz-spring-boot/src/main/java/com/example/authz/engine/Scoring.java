package com.example.authz.engine;

import com.example.authz.config.CompiledRule;
import com.example.authz.config.Segment;

import java.util.ArrayList;
import java.util.List;

/** Path matching + specificity scoring (must match the NestJS implementation). */
public final class Scoring {
    private Scoring() {}

    /** Split a request path into segments, ignoring empty parts. */
    public static List<String> splitPath(String path) {
        List<String> out = new ArrayList<>();
        for (String part : path.split("/")) {
            if (!part.isEmpty()) out.add(part);
        }
        return out;
    }

    public static int scoreSegment(Segment seg) {
        return switch (seg.kind()) {
            case LITERAL -> 2;
            case SINGLE -> 1;
            case DEEP -> 0;
        };
    }

    /** `*` matches one segment; `**` matches one or more (final segment only). */
    public static boolean matchPath(List<Segment> segments, List<String> pathSegs) {
        for (int i = 0; i < segments.size(); i++) {
            Segment seg = segments.get(i);
            if (seg.kind() == com.example.authz.config.SegmentKind.DEEP) {
                return pathSegs.size() - i >= 1;
            }
            if (i >= pathSegs.size()) return false;
            if (seg.kind() == com.example.authz.config.SegmentKind.LITERAL
                    && !seg.value().equals(pathSegs.get(i))) {
                return false;
            }
        }
        return segments.size() == pathSegs.size();
    }

    /**
     * &gt;0 if a is more specific than b. Order: segment scores left-to-right,
     * then more literal segments, then longer pattern.
     */
    public static int compareSpecificity(CompiledRule a, CompiledRule b) {
        int n = Math.min(a.scores().length, b.scores().length);
        for (int i = 0; i < n; i++) {
            if (a.scores()[i] != b.scores()[i]) return a.scores()[i] - b.scores()[i];
        }
        if (a.literalCount() != b.literalCount()) return a.literalCount() - b.literalCount();
        if (a.segments().size() != b.segments().size()) {
            return a.segments().size() - b.segments().size();
        }
        return 0;
    }
}
