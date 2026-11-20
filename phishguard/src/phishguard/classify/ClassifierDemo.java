package phishguard.classify;

import phishguard.features.UrlFeatureExtractor;
import java.nio.file.*;
import java.util.*;

public class ClassifierDemo {
    public static void main(String[] args) throws Exception {
        UrlFeatureExtractor ex = new UrlFeatureExtractor();
        Classifier clf = new RuleBasedClassifier();
        for (String line : Files.readAllLines(Paths.get("resources/sample_urls.txt"))) {
            if (line.isBlank()) continue;
            ClassifierResult r = clf.classify(ex.extract(line));
            System.out.printf("%s%n  Score: %.0f (%s)%n", line.trim(), r.score, r.level());
            for (String reason : r.reasons) System.out.println("   - " + reason);
        }
    }
}