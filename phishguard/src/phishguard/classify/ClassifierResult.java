package phishguard.classify;

import java.util.*;

public class ClassifierResult {
    public final double score;          // 0-100
    public final List<String> reasons;

    public ClassifierResult(double score, List<String> reasons) {
        this.score = score;
        this.reasons = reasons;
    }

    public String level() {
        if (score >= 70) return "High";
        if (score >= 40) return "Medium";
        return "Low";
    }
}