package phishguard.eval;

import phishguard.classify.*;
import phishguard.data.DatasetLoader;
import phishguard.data.DatasetLoader.Dataset;
import java.util.*;

public class RealEvalDemo {
    public static void main(String[] args) throws Exception {
        Dataset all = DatasetLoader.load("resources/urls_all.csv", true);
        long phish = all.labels.stream().filter(l -> l == 1).count();
        System.out.println("Loaded " + all.size() + " URLs (" + phish + " phishing, "
                + (all.size() - phish) + " legitimate)");

        Dataset[] parts = DatasetLoader.split(all, 0.7, 42);
        Dataset test = parts[1];

        Classifier clf = new RuleBasedClassifier();
        for (double t : new double[]{30, 40, 50, 60, 70}) {
            List<String> errors = new ArrayList<>();
            Evaluator.Metrics m = Evaluator.evaluate(test.urls, test.labels, clf, t, errors);
            System.out.println("=== Threshold " + (int) t + " ===\n" + m + "\n");
        }
    }
}