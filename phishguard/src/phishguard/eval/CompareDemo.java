package phishguard.eval;

import phishguard.classify.*;
import phishguard.data.DatasetLoader;
import phishguard.data.DatasetLoader.Dataset;

public class CompareDemo {
    public static void main(String[] args) throws Exception {
        Dataset all = DatasetLoader.load("resources/urls_all.csv", true);
        Dataset[] parts = DatasetLoader.split(all, 0.7, 42);
        Dataset train = parts[0], test = parts[1];
        System.out.println("Train: " + train.size() + "  Test: " + test.size());

        NaiveBayesClassifier nb = new NaiveBayesClassifier();
        nb.train(train.urls, train.labels);

        System.out.println("=== Rule-based (threshold 40) ===");
        System.out.println(Evaluator.evaluate(test.urls, test.labels, new RuleBasedClassifier(), 40, null));
        System.out.println();
        System.out.println("=== Naive Bayes (threshold 50) ===");
        System.out.println(Evaluator.evaluate(test.urls, test.labels, nb, 50, null));
    }
}