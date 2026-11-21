package phishguard.classify;

import phishguard.features.UrlFeatureExtractor;
import java.util.*;

public class NaiveBayesClassifier implements Classifier {
    private static final double VAR_FLOOR = 1e-2;   // avoids division by ~0 for constant features
    private final List<String> names = new ArrayList<>();
    private final double[][] mean = new double[2][];
    private final double[][] var = new double[2][];
    private final double[] prior = new double[2];

    private double[] vector(Map<String, Double> f) {
        double[] v = new double[names.size()];
        for (int j = 0; j < v.length; j++) v[j] = Math.log1p(f.getOrDefault(names.get(j), 0.0));
        return v;
    }

    public void train(List<String> urls, List<Integer> labels) {
        UrlFeatureExtractor ex = new UrlFeatureExtractor();
        List<double[]> rows = new ArrayList<>();
        for (String u : urls) {
            Map<String, Double> f = ex.extract(u);
            if (names.isEmpty()) names.addAll(f.keySet());
            rows.add(vector(f));
        }
        int d = names.size();
        int[] count = new int[2];
        for (int c = 0; c < 2; c++) { mean[c] = new double[d]; var[c] = new double[d]; }
        for (int i = 0; i < rows.size(); i++) {
            int c = labels.get(i);
            count[c]++;
            for (int j = 0; j < d; j++) mean[c][j] += rows.get(i)[j];
        }
        for (int c = 0; c < 2; c++)
            for (int j = 0; j < d; j++) mean[c][j] /= Math.max(1, count[c]);
        for (int i = 0; i < rows.size(); i++) {
            int c = labels.get(i);
            for (int j = 0; j < d; j++) {
                double diff = rows.get(i)[j] - mean[c][j];
                var[c][j] += diff * diff;
            }
        }
        for (int c = 0; c < 2; c++) {
            for (int j = 0; j < d; j++) var[c][j] = Math.max(VAR_FLOOR, var[c][j] / Math.max(1, count[c]));
            prior[c] = (double) count[c] / rows.size();
        }
    }

    private double logPdf(int c, int j, double x) {
        double diff = x - mean[c][j];
        return -0.5 * Math.log(2 * Math.PI * var[c][j]) - diff * diff / (2 * var[c][j]);
    }

    @Override
    public ClassifierResult classify(Map<String, Double> f) {
        double[] x = vector(f);
        double l0 = Math.log(prior[0]), l1 = Math.log(prior[1]);
        double[] llr = new double[x.length];
        for (int j = 0; j < x.length; j++) {
            double a = logPdf(0, j, x[j]), b = logPdf(1, j, x[j]);
            l0 += a; l1 += b;
            llr[j] = b - a;
        }
        double p = 1.0 / (1.0 + Math.exp(l0 - l1));   // P(phishing | features)

        // Reasons: the features that pushed hardest toward "phishing"
        Integer[] order = new Integer[x.length];
        for (int j = 0; j < order.length; j++) order[j] = j;
        Arrays.sort(order, (a, b) -> Double.compare(llr[b], llr[a]));
        List<String> reasons = new ArrayList<>();
        for (int k = 0; k < Math.min(3, order.length); k++) {
            int j = order[k];
            if (llr[j] > 1.0)
                reasons.add(String.format("%s = %.2f looks like phishing (evidence +%.1f)",
                        names.get(j), f.getOrDefault(names.get(j), 0.0), llr[j]));
        }
        if (reasons.isEmpty()) reasons.add("No strong phishing signals");
        return new ClassifierResult(100 * p, reasons);
    }
}