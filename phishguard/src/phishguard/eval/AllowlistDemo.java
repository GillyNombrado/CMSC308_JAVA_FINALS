package phishguard.eval;

import phishguard.classify.*;
import phishguard.data.DatasetLoader;
import phishguard.data.DatasetLoader.Dataset;
import phishguard.features.UrlFeatureExtractor;
import phishguard.risk.SafeDomains;
import java.util.*;

/** E10: does the trusted-domain list help or hurt on the real (Kaggle) test URLs? */
public class AllowlistDemo {
    public static void main(String[] args) throws Exception {
        Dataset all = DatasetLoader.load("resources/urls_all.csv", true);
        Dataset[] parts = DatasetLoader.split(all, 0.7, 42);
        Dataset train = parts[0], test = parts[1];

        int trustedPhish = 0, trustedLegit = 0;
        List<String> phishExamples = new ArrayList<>();
        for (int i = 0; i < test.size(); i++) {
            if (!SafeDomains.isTrustedUrl(test.urls.get(i))) continue;
            if (test.labels.get(i) == 1) { trustedPhish++; if (phishExamples.size() < 8) phishExamples.add(test.urls.get(i)); }
            else trustedLegit++;
        }
        System.out.println("Test URLs on the trusted list: " + (trustedPhish + trustedLegit) + " of " + test.size());
        System.out.println("  legitimate: " + trustedLegit + "   phishing: " + trustedPhish);
        if (!phishExamples.isEmpty()) System.out.println("  phishing URLs the list would wrongly trust (examples):");
        for (String u : phishExamples) System.out.println("    " + (u.length() > 110 ? u.substring(0, 110) + "..." : u));

        DecisionTreeClassifier tree = new DecisionTreeClassifier(8, 20);
        tree.train(train.urls, train.labels);
        UrlFeatureExtractor ex = new UrlFeatureExtractor();

        for (boolean useList : new boolean[]{false, true}) {
            Evaluator.Metrics m = new Evaluator.Metrics();
            for (int i = 0; i < test.size(); i++) {
                String u = test.urls.get(i);
                double score = tree.classify(ex.extract(u)).score;
                if (useList && SafeDomains.isTrustedUrl(u)) score = Math.min(score, 5);
                int pred = score >= 50 ? 1 : 0, act = test.labels.get(i);
                if (pred == 1 && act == 1) m.tp++; else if (pred == 1) m.fp++; else if (act == 0) m.tn++; else m.fn++;
            }
            System.out.println("\n" + (useList ? "Decision tree WITH trusted list" : "Decision tree, no list"));
            System.out.println(m);
        }
    }
}
