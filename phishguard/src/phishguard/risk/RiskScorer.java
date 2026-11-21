package phishguard.risk;

import phishguard.text.TextResult;
import java.util.*;

public class RiskScorer {

    public enum Rule {
        /** final = wUrl * URL + wText * text + bonus (a clean message lowers the score). */
        WEIGHTED,
        /** Either signal can raise the score; a clean message never lowers a risky link. */
        NOISY_OR
    }

    private final Rule rule;
    private final double wUrl, wText, maxBonus;

    /** A message at or above this text risk is a strong scam signal on its own (WEIGHTED rule only). */
    private static final double STRONG_TEXT = 60;
    private static final double TEXT_FLOOR_SHARE = 0.8;

    /** Default: NOISY_OR with up to +20 for the brand cross-check. */
    public RiskScorer() { this(Rule.NOISY_OR, 0, 0, 20); }

    /** Older weighted rule, kept so the weight experiment can still be run. */
    public RiskScorer(double wUrl, double wText, double maxBonus) { this(Rule.WEIGHTED, wUrl, wText, maxBonus); }

    public static RiskScorer noisyOr(double maxBonus) { return new RiskScorer(Rule.NOISY_OR, 0, 0, maxBonus); }

    private RiskScorer(Rule rule, double wUrl, double wText, double maxBonus) {
        this.rule = rule;
        this.wUrl = wUrl;
        this.wText = wText;
        this.maxBonus = maxBonus;
    }

    public String describe() {
        return rule == Rule.NOISY_OR ? "either signal can raise the score"
                : String.format("weighted %.1f link / %.1f message", wUrl, wText);
    }

    /** @param text may be null when no message was given */
    public RiskResult score(double urlRisk, String urlSource, List<String> urlReasons,
                            TextResult text, BrandCheck brand) {
        boolean hasText = text != null;

        double base;
        if (!hasText) base = urlRisk;
        else if (rule == Rule.NOISY_OR) base = 100 * (1 - (1 - urlRisk / 100) * (1 - text.score / 100));
        else base = wUrl * urlRisk + wText * text.score;

        double bonus = 0;
        if (brand.status == BrandCheck.Status.MISMATCH) bonus = maxBonus;
        else if (brand.status == BrandCheck.Status.UNVERIFIABLE) bonus = maxBonus / 2;

        double finalScore = base + bonus;

        boolean floorApplied = false;
        if (rule == Rule.WEIGHTED && hasText && text.score >= STRONG_TEXT) {
            double floor = TEXT_FLOOR_SHARE * text.score;
            if (floor > finalScore) { finalScore = floor; floorApplied = true; }
        }
        finalScore = Math.max(0, Math.min(100, finalScore));

        List<String> reasons = new ArrayList<>();
        if (floorApplied)
            reasons.add("The message alone is a strong scam signal, so the link's safe appearance does not lower the score");
        if (brand.status != BrandCheck.Status.NONE) {
            String suffix = bonus > 0 ? " (+" + (int) bonus + ")" : "";
            reasons.add("Cross-check: " + brand.reason + suffix);
        }
        for (String r : limit(urlReasons, 4)) reasons.add("URL (" + urlSource + "): " + r);
        if (hasText) for (String r : text.reasons) reasons.add("Message: " + r);

        return new RiskResult(finalScore, urlRisk, hasText ? text.score : -1, hasText, brand, reasons);
    }

    private static List<String> limit(List<String> list, int max) {
        if (list.size() <= max) return list;
        List<String> out = new ArrayList<>(list.subList(0, max - 1));
        out.add(list.get(list.size() - 1));
        return out;
    }
}
