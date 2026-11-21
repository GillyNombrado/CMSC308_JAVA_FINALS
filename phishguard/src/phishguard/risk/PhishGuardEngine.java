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

    /** @param message optional; pass null or blank to analyze the URL alone */
    public RiskResult analyze(String url, String message) {
        String cleanUrl = url == null ? "" : url.trim();

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
}