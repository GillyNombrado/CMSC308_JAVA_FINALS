package phishguard.eval;

import phishguard.classify.DecisionTreeClassifier;
import phishguard.data.DatasetLoader;
import phishguard.data.DatasetLoader.Dataset;
import phishguard.risk.*;
import java.nio.file.*;
import java.util.*;

/** Runs experiments E4 (URL vs text vs combined), E5 (brand check on/off), E6 (weights) and E7 (by source). */
public class HybridEvalDemo {

    static class Row {
        int label; String source, url, message;
    }

    static List<Row> load(String path) throws Exception {
        List<Row> rows = new ArrayList<>();
        for (String line : Files.readAllLines(Paths.get(path))) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] p = line.split("\\|", 4);
            if (p.length < 4) { System.out.println("Skipping bad line: " + line); continue; }
            Row r = new Row();
            r.label = Integer.parseInt(p[0].trim());
            r.source = p[1].trim();
            r.url = p[2].trim();
            r.message = p[3].trim();
            rows.add(r);
        }
        return rows;
    }

    interface Predictor { double score(Row r); }

    static Evaluator.Metrics run(List<Row> rows, Predictor p, double threshold, List<String> errors) {
        Evaluator.Metrics m = new Evaluator.Metrics();
        for (Row r : rows) {
            double s = p.score(r);
            int pred = s >= threshold ? 1 : 0;
            if (pred == 1 && r.label == 1) m.tp++;
            else if (pred == 1) { m.fp++; if (errors != null) errors.add(String.format("FALSE POSITIVE (%.0f) [%s] %s | %s", s, r.source, r.url, r.message)); }
            else if (r.label == 0) m.tn++;
            else { m.fn++; if (errors != null) errors.add(String.format("FALSE NEGATIVE (%.0f) [%s] %s | %s", s, r.source, r.url, r.message)); }
        }
        return m;
    }

    static void line(String name, Evaluator.Metrics m) {
        System.out.printf("%-34s acc=%.3f  precision=%.3f  recall=%.3f  F1=%.3f  FPR=%.3f   (TP=%d FP=%d TN=%d FN=%d)%n",
                name, m.accuracy(), m.precision(), m.recall(), m.f1(), m.fpr(), m.tp, m.fp, m.tn, m.fn);
    }

    public static void main(String[] args) throws Exception {
        List<String> files = new ArrayList<>(Arrays.asList(args));
        if (files.isEmpty()) {
            files.add("resources/messages.csv");
            if (Files.exists(Paths.get("resources/messages_own.csv"))) files.add("resources/messages_own.csv");
        }

        System.out.println("Training the URL model...");
        Dataset all = DatasetLoader.load("resources/urls_all.csv", true);
        Dataset train = DatasetLoader.split(all, 0.7, 42)[0];
        DecisionTreeClassifier tree = new DecisionTreeClassifier(8, 20);
        tree.train(train.urls, train.labels);

        PhishGuardEngine full = new PhishGuardEngine(tree, true, new RiskScorer());
        PhishGuardEngine noBrand = new PhishGuardEngine(tree, true, new RiskScorer(0.5, 0.3, 0));
        final double T = 40;   // Medium or High counts as "scam"

        for (String f : files) {
            List<Row> rows = load(f);
            long scams = rows.stream().filter(r -> r.label == 1).count();
            System.out.println("\n==================================================");
            System.out.println(f + ": " + rows.size() + " rows (" + scams + " scam, " + (rows.size() - scams) + " legitimate)");
            System.out.println("==================================================");

            System.out.println("\n--- E4 and E5: which signals are used (threshold " + (int) T + ") ---");
            line("URL only", run(rows, r -> full.analyze(r.url, null).score, T, null));
            line("Message only", run(rows, r -> full.analyzeMessageOnly(r.message).score, T, null));
            line("Combined, no brand cross-check", run(rows, r -> noBrand.analyze(r.url, r.message).score, T, null));
            List<String> errors = new ArrayList<>();
            line("Combined (full system)", run(rows, r -> full.analyze(r.url, r.message).score, T, errors));

            System.out.println("\n--- E6: weight settings (URL / text / bonus). Tuned on this same data, so treat as exploratory ---");
            double[][] w = {{0.5, 0.3, 20}, {0.4, 0.4, 20}, {0.6, 0.2, 20}, {0.3, 0.5, 20}};
            for (double[] x : w) {
                PhishGuardEngine e = new PhishGuardEngine(tree, true, new RiskScorer(x[0], x[1], x[2]));
                line(String.format("%.1f / %.1f / +%.0f", x[0], x[1], x[2]), run(rows, r -> e.analyze(r.url, r.message).score, T, null));
            }

            System.out.println("\n--- E7: combined system by source type ---");
            for (String src : new String[]{"SMS", "DM", "comment", "post"}) {
                List<Row> sub = new ArrayList<>();
                for (Row r : rows) if (r.source.equalsIgnoreCase(src)) sub.add(r);
                if (sub.isEmpty()) continue;
                line(src + " (" + sub.size() + " rows)", run(sub, r -> full.analyze(r.url, r.message).score, T, null));
            }

            System.out.println("\n--- Mistakes made by the combined system (use these in your error analysis) ---");
            if (errors.isEmpty()) System.out.println("None.");
            errors.forEach(e -> System.out.println("  " + e));
        }
    }
}
