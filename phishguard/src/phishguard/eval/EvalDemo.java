package phishguard.eval;

import phishguard.classify.*;
import java.nio.file.*;
import java.util.*;

public class EvalDemo {
    public static void main(String[] args) throws Exception {
        List<String> urls = new ArrayList<>();
        List<Integer> labels = new ArrayList<>();
        for (String line : Files.readAllLines(Paths.get("resources/labeled_urls.csv"))) {
            if (line.isBlank()) continue;
            String[] parts = line.split(",", 2);   // limit 2: URLs may contain commas
            labels.add(Integer.parseInt(parts[0].trim()));
            urls.add(parts[1].trim());
        }

        Classifier clf = new RuleBasedClassifier();
        for (double threshold : new double[]{30, 40, 50, 70}) {
            List<String> errors = new ArrayList<>();
            Evaluator.Metrics m = Evaluator.evaluate(urls, labels, clf, threshold, errors);
            System.out.println("=== Threshold " + (int) threshold + " ===");
            System.out.println(m);
            errors.forEach(e -> System.out.println("  " + e));
            System.out.println();
        }
    }
}