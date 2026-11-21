package phishguard.eval;

import phishguard.classify.*;
import phishguard.data.DatasetLoader;
import phishguard.data.DatasetLoader.Dataset;
import phishguard.features.UrlFeatureExtractor;
import java.util.*;

public class AblationDemo {

    static final Map<String, List<String>> GROUPS = new LinkedHashMap<>();
    static {
        GROUPS.put("length",    List.of("url_length", "path_length", "host_length"));
        GROUPS.put("characters", List.of("dot_count", "hyphen_count", "at_count", "question_count",
                "equals_count", "percent_count", "digit_count", "digit_ratio"));
        GROUPS.put("structure", List.of("is_ip", "is_https", "has_port", "subdomain_count", "parse_error"));
        GROUPS.put("words",     List.of("suspicious_words", "words_in_host", "words_in_path"));
        GROUPS.put("brand",     List.of("brand_mismatch", "lookalike"));
        GROUPS.put("tld_short", List.of("risky_tld", "is_shortener"));
        GROUPS.put("entropy",   List.of("domain_entropy"));
        GROUPS.put("path",      List.of("path_segments", "query_params", "longest_token",
                "has_hex_blob", "ext_php", "ext_html"));
    }

    static Evaluator.Metrics run(Dataset train, Dataset test, Set<String> disabled) {
        UrlFeatureExtractor.DISABLED.clear();
        UrlFeatureExtractor.DISABLED.addAll(disabled);
        try {
            DecisionTreeClassifier dt = new DecisionTreeClassifier(8, 20);
            dt.train(train.urls, train.labels);
            return Evaluator.evaluate(test.urls, test.labels, dt, 50, null);
        } finally {
            UrlFeatureExtractor.DISABLED.clear();      // always reset
        }
    }

    public static void main(String[] args) throws Exception {
        Dataset all = DatasetLoader.load("resources/urls_all.csv", true);
        Dataset[] parts = DatasetLoader.split(all, 0.7, 42);
        Dataset train = parts[0], test = parts[1];
        System.out.println("Decision tree (depth 8, threshold 50). Train: "
                + train.size() + "  Test: " + test.size() + "\n");

        Evaluator.Metrics base = run(train, test, Set.of());
        System.out.printf("ALL FEATURES: acc=%.3f recall=%.3f F1=%.3f FPR=%.3f%n%n",
                base.accuracy(), base.recall(), base.f1(), base.fpr());

        System.out.println("--- Remove ONE group (all others kept) ---");
        System.out.printf("%-12s %8s %8s %8s %8s %10s%n", "removed", "acc", "recall", "F1", "FPR", "F1 change");
        for (Map.Entry<String, List<String>> g : GROUPS.entrySet()) {
            Evaluator.Metrics m = run(train, test, new HashSet<>(g.getValue()));
            System.out.printf("%-12s %8.3f %8.3f %8.3f %8.3f %+10.3f%n",
                    g.getKey(), m.accuracy(), m.recall(), m.f1(), m.fpr(), m.f1() - base.f1());
        }

        System.out.println("\n--- Keep ONLY one group ---");
        System.out.printf("%-12s %8s %8s %8s %8s%n", "only", "acc", "recall", "F1", "FPR");
        for (Map.Entry<String, List<String>> g : GROUPS.entrySet()) {
            Set<String> disabled = new HashSet<>();
            for (List<String> other : GROUPS.values()) disabled.addAll(other);
            disabled.removeAll(g.getValue());
            Evaluator.Metrics m = run(train, test, disabled);
            System.out.printf("%-12s %8.3f %8.3f %8.3f %8.3f%n",
                    g.getKey(), m.accuracy(), m.recall(), m.f1(), m.fpr());
        }
    }
}