package phishguard.eval;

import phishguard.classify.*;
import phishguard.features.UrlFeatureExtractor;
import java.util.*;

public class Evaluator {

    public static class Metrics {
        public int tp, fp, tn, fn;

        public double accuracy()  { return div(tp + tn, tp + tn + fp + fn); }
        public double precision() { return div(tp, tp + fp); }
        public double recall()    { return div(tp, tp + fn); }
        public double f1() {
            double p = precision(), r = recall();
            return div(2 * p * r, p + r);
        }
        public double fpr()       { return div(fp, fp + tn); }

        private static double div(double a, double b) { return b == 0 ? 0 : a / b; }

        @Override
        public String toString() {
            return String.format(
                "TP=%d FP=%d TN=%d FN=%d%nAccuracy=%.3f Precision=%.3f Recall=%.3f F1=%.3f FPR=%.3f",
                tp, fp, tn, fn, accuracy(), precision(), recall(), f1(), fpr());
        }
    }

    /** A URL is predicted as phishing when its score is >= threshold. */
    public static Metrics evaluate(List<String> urls, List<Integer> labels,
                                   Classifier clf, double threshold,
                                   List<String> errorsOut) {
        UrlFeatureExtractor ex = new UrlFeatureExtractor();
        Metrics m = new Metrics();
        for (int i = 0; i < urls.size(); i++) {
            ClassifierResult r = clf.classify(ex.extract(urls.get(i)));
            int predicted = r.score >= threshold ? 1 : 0;
            int actual = labels.get(i);
            if (predicted == 1 && actual == 1) m.tp++;
            else if (predicted == 1 && actual == 0) {
                m.fp++;
                if (errorsOut != null) errorsOut.add("FALSE POSITIVE (" + (int) r.score + "): " + urls.get(i));
            } else if (predicted == 0 && actual == 0) m.tn++;
            else {
                m.fn++;
                if (errorsOut != null) errorsOut.add("FALSE NEGATIVE (" + (int) r.score + "): " + urls.get(i));
            }
        }
        return m;
    }
}