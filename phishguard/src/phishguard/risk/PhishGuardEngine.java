package phishguard.risk;

import phishguard.classify.*;
import phishguard.data.DatasetLoader;
import phishguard.data.DatasetLoader.Dataset;
import phishguard.features.UrlFeatureExtractor;
import phishguard.text.TextResult;
import phishguard.text.TextScamAnalyzer;
import java.util.*;

public class PhishGuardEngine {
    private final UrlFeatureExtractor extractor = new UrlFeatureExtractor();
    private final Classifier urlModel;
    private final Classifier rules = new RuleBasedClassifier();
    private final TextScamAnalyzer textAnalyzer = new TextScamAnalyzer();
    private final BrandChecker brandChecker = new BrandChecker();
    private final RiskScorer scorer;
    private final boolean useRules;

    public PhishGuardEngine(Classifier trainedUrlModel, boolean useRules, RiskScorer scorer) {
        this.urlModel = trainedUrlModel;
        this.useRules = useRules;
        this.scorer = scorer;
    }

    /** Trains the decision tree on the 70% training split (same split and seed as your experiments). */
    public static PhishGuardEngine createDefault() throws Exception {
        Dataset all = DatasetLoader.load("resources/urls_all.csv", true);
        Dataset train = DatasetLoader.split(all, 0.7, 42)[0];
        DecisionTreeClassifier tree = new DecisionTreeClassifier(8, 20);
        tree.train(train.urls, train.labels);
        return new PhishGuardEngine(tree, true, new RiskScorer());
    }

    /** True when the input looks like a link: no spaces, and a host that is a domain name or an IP address. */
    public static boolean isReadableUrl(String url) {
        if (url == null) return false;
        String u = url.trim();
        if (u.isEmpty() || u.length() > 2048 || u.matches(".*\\s.*")) return false;
        String host = BrandChecker.hostOf(u);
        if (host == null || !host.contains(".")) return false;
        return host.matches("[a-z0-9.-]+") && !host.startsWith(".") && !host.endsWith(".") && !host.contains("..");
    }

    /**
     * @param message optional; pass null or blank to analyze the URL alone
     * @throws IllegalArgumentException when the input cannot be read as a link
     */
    public RiskResult analyze(String url, String message) {
        if (!isReadableUrl(url))
            throw new IllegalArgumentException("That does not look like a link. Try something like example.com/page");
        String cleanUrl = url.trim();

        // The tree was trained on normalized URLs, so normalize before using it
        ClassifierResult chosen = urlModel.classify(extractor.extract(DatasetLoader.normalize(cleanUrl)));
        String source = "learned model";

        // The rules read the raw URL (the https signal is still meaningful there)
        if (useRules) {
            ClassifierResult r = rules.classify(extractor.extract(cleanUrl));
            if (r.score > chosen.score) { chosen = r; source = "rules"; }
        }

        TextResult text = (message == null || message.isBlank()) ? null : textAnalyzer.analyze(message);
        BrandCheck brand = brandChecker.check(text == null ? Set.of() : text.brands, cleanUrl);
        return scorer.score(chosen.score, source, chosen.reasons, text, brand);
    }

    /** Analyzes wording only, for a message that contains no link. */
    public RiskResult analyzeMessageOnly(String message) {
        if (message == null || message.trim().length() < 10)
            throw new IllegalArgumentException("Add a bit more text. Messages need at least 10 characters.");
        TextResult t = textAnalyzer.analyze(message);
        List<String> reasons = new ArrayList<>();
        for (String r : t.reasons) reasons.add("Message: " + r);
        reasons.add("No link was found, so only the wording of the message was checked");
        return new RiskResult(t.score, -1, t.score, true, BrandCheck.none(), reasons);
    }
}
