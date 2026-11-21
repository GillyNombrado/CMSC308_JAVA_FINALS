package phishguard.classify;

import phishguard.features.UrlFeatureExtractor;
import java.util.*;

public class DecisionTreeClassifier implements Classifier {
    private final int maxDepth, minLeaf;
    private final List<String> names = new ArrayList<>();
    private Node root;

    private static class Node {
        int feature = -1;
        double threshold;
        Node left, right;
        int n, pos;
        boolean isLeaf() { return left == null; }
    }

    public DecisionTreeClassifier(int maxDepth, int minLeaf) {
        this.maxDepth = maxDepth;
        this.minLeaf = minLeaf;
    }

    public void train(List<String> urls, List<Integer> labels) {
        UrlFeatureExtractor ex = new UrlFeatureExtractor();
        names.clear();
        double[][] x = new double[urls.size()][];
        for (int i = 0; i < urls.size(); i++) {
            Map<String, Double> f = ex.extract(urls.get(i));
            if (names.isEmpty()) names.addAll(f.keySet());
            x[i] = new double[names.size()];
            for (int j = 0; j < names.size(); j++) x[i][j] = f.getOrDefault(names.get(j), 0.0);
        }
        int[] y = new int[labels.size()];
        for (int i = 0; i < y.length; i++) y[i] = labels.get(i);
        int[] all = new int[urls.size()];
        for (int i = 0; i < all.length; i++) all[i] = i;
        root = build(x, y, all, 0);
    }

    private static double gini(int pos, int n) {
        if (n == 0) return 0;
        double p = (double) pos / n;
        return 2 * p * (1 - p);
    }

    private Node build(double[][] x, int[] y, int[] idx, int depth) {
        Node node = new Node();
        node.n = idx.length;
        for (int i : idx) node.pos += y[i];
        if (depth >= maxDepth || node.n < 2 * minLeaf || node.pos == 0 || node.pos == node.n) return node;

        double parent = gini(node.pos, node.n);
        double bestScore = parent - 1e-9;
        int bestFeature = -1;
        double bestThreshold = 0;

        for (int j = 0; j < names.size(); j++) {
            final int jj = j;
            Integer[] order = new Integer[idx.length];
            for (int k = 0; k < order.length; k++) order[k] = idx[k];
            Arrays.sort(order, (a, b) -> Double.compare(x[a][jj], x[b][jj]));

            int leftPos = 0;
            for (int k = 0; k < order.length - 1; k++) {
                leftPos += y[order[k]];
                double v = x[order[k]][j], next = x[order[k + 1]][j];
                if (v == next) continue;                       // split only between different values
                int nl = k + 1, nr = order.length - nl;
                if (nl < minLeaf || nr < minLeaf) continue;
                double score = (nl * gini(leftPos, nl) + nr * gini(node.pos - leftPos, nr)) / order.length;
                if (score < bestScore) {
                    bestScore = score;
                    bestFeature = j;
                    bestThreshold = (v + next) / 2;
                }
            }
        }
        if (bestFeature < 0) return node;                      // no useful split: leaf

        node.feature = bestFeature;
        node.threshold = bestThreshold;
        List<Integer> l = new ArrayList<>(), r = new ArrayList<>();
        for (int i : idx) (x[i][bestFeature] <= bestThreshold ? l : r).add(i);
        node.left = build(x, y, l.stream().mapToInt(Integer::intValue).toArray(), depth + 1);
        node.right = build(x, y, r.stream().mapToInt(Integer::intValue).toArray(), depth + 1);
        return node;
    }

    @Override
    public ClassifierResult classify(Map<String, Double> f) {
        Node node = root;
        List<String> reasons = new ArrayList<>();
        while (!node.isLeaf()) {
            String name = names.get(node.feature);
            double v = f.getOrDefault(name, 0.0);
            boolean goLeft = v <= node.threshold;
            reasons.add(String.format("%s = %.2f (%s %.2f)", name, v, goLeft ? "<=" : ">", node.threshold));
            node = goLeft ? node.left : node.right;
        }
        double p = (node.pos + 1.0) / (node.n + 2.0);          // Laplace smoothing
        reasons.add(String.format("In training, %d of %d similar URLs were phishing", node.pos, node.n));
        return new ClassifierResult(100 * p, reasons);
    }
}