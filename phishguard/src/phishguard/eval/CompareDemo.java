package phishguard.eval;

import phishguard.classify.*;
import phishguard.data.DatasetLoader;
import phishguard.data.DatasetLoader.Dataset;

public class CompareDemo {
    public static void main(String[] args) throws Exception {
        Dataset all = DatasetLoader.load("resources/urls_all.csv", true);
        Dataset[] parts = DatasetLoader.split(all, 0.7, 42);
        Dataset train = parts[0], test = parts[1];
        System.out.println("Train: " + train.size() + "  Test: " + test.size() + "\n");

        NaiveBayesClassifier nb = new NaiveBayesClassifier();
        nb.train(train.urls, train.labels);
        DecisionTreeClassifier dt = new DecisionTreeClassifier(8, 20);
        dt.train(train.urls, train.labels);

        System.out.println("=== Rule-based (threshold 40) ===");
        System.out.println(Evaluator.evaluate(test.urls, test.labels, new RuleBasedClassifier(), 40, null) + "\n");
        System.out.println("=== Naive Bayes (threshold 50) ===");
        System.out.println(Evaluator.evaluate(test.urls, test.labels, nb, 50, null) + "\n");
        System.out.println("=== Decision Tree depth 8 (threshold 50) ===");
        System.out.println(Evaluator.evaluate(test.urls, test.labels, dt, 50, null) + "\n");

        System.out.println("=== Tree depth sweep (threshold 50) ===");
        System.out.println("depth  train_acc  test_acc  test_recall  test_F1");
        for (int depth : new int[]{2, 4, 6, 8, 12, 20}) {
            DecisionTreeClassifier t = new DecisionTreeClassifier(depth, 20);
            t.train(train.urls, train.labels);
            Evaluator.Metrics tr = Evaluator.evaluate(train.urls, train.labels, t, 50, null);
            Evaluator.Metrics te = Evaluator.evaluate(test.urls, test.labels, t, 50, null);
            System.out.printf("%5d  %9.3f  %8.3f  %11.3f  %7.3f%n",
                    depth, tr.accuracy(), te.accuracy(), te.recall(), te.f1());
        }
    }
}