package phishguard.text;

import java.util.*;

public class TextResult {
    public final double score;            // 0-100
    public final List<String> reasons;
    public final Set<String> brands;      // brands the message claims to be from (keys match UrlFeatureExtractor)

    public TextResult(double score, List<String> reasons, Set<String> brands) {
        this.score = score;
        this.reasons = reasons;
        this.brands = brands;
    }

    public String level() {
        if (score >= 70) return "High";
        if (score >= 40) return "Medium";
        return "Low";
    }
}