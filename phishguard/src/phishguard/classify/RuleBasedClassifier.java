package phishguard.classify;

import java.util.*;

public class RuleBasedClassifier implements Classifier {

    @Override
    public ClassifierResult classify(Map<String, Double> f) {
        double score = 0;
        List<String> reasons = new ArrayList<>();

        if (f.get("parse_error") == 1) {
            return new ClassifierResult(60, List.of("URL could not be parsed (+60)"));
        }
        if (f.get("brand_mismatch") == 1) {
            score += 30; reasons.add("Brand name appears, but the real domain is different (+30)");
        }
        if (f.get("lookalike") == 1) {
            score += 30; reasons.add("Domain looks like a known brand's domain (+30)");
        }
        if (f.get("is_ip") == 1) {
            score += 25; reasons.add("Uses an IP address instead of a domain name (+25)");
        }
        if (f.get("at_count") > 0) {
            score += 20; reasons.add("Contains an '@' symbol (+20)");
        }
        if (f.get("risky_tld") == 1) {
            score += 15; reasons.add("Uses a risky top-level domain (+15)");
        }
        if (f.get("is_shortener") == 1) {
            score += 15; reasons.add("Shortened link hides the real destination (+15)");
        }
        if (f.get("subdomain_count") >= 2) {
            score += 15; reasons.add("Many subdomains (+15)");
        }
        double words = f.get("suspicious_words");
        if (words >= 1) {
            double pts = Math.min(20, words * 7);
            score += pts; reasons.add("Suspicious words in URL (+" + (int) pts + ")");
        }
        if (f.get("is_https") == 0) {
            score += 10; reasons.add("Does not use HTTPS (+10)");
        }
        if (f.get("has_port") == 1) {
            score += 10; reasons.add("Non-standard port (+10)");
        }
        if (f.get("hyphen_count") >= 2) {
            score += 10; reasons.add("Many hyphens in the URL (+10)");
        }
        if (f.get("url_length") > 75) {
            score += 10; reasons.add("Very long URL (+10)");
        }

        score = Math.min(100, score);
        if (reasons.isEmpty()) reasons.add("No suspicious signals found");
        return new ClassifierResult(score, reasons);
    }
}