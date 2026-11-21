package phishguard.risk;

import phishguard.text.TextResult;
import java.util.*;

public class RiskScorer {
    private final double wUrl, wText, maxBonus;

    /** Starting weights from the project plan: 50% URL, 30% text, up to +20 for the brand cross-check. */
    public RiskScorer() { this(0.5, 0.3, 20); }

    public RiskScorer(double wUrl, double wText, double maxBonus) {
        this.wUrl = wUrl;
        this.wText = wText;
        this.maxBonus = maxBonus;
    }

    /**
     * @param text may be null when no message was given
     */
    public RiskResult score(double urlRisk, String urlSource, List<String> urlReasons,
                            TextResult text, BrandCheck brand) {
        boolean hasText = text != null;

        // With no message, the URL gets full weight so the system still works on its own
        double base = hasText ? wUrl * urlRisk + wText * text.score : urlRisk;

        double bonus = 0;
        if (brand.status == BrandCheck.Status.MISMATCH) bonus = maxBonus;
        else if (brand.status == BrandCheck.Status.UNVERIFIABLE) bonus = maxBonus / 2;

        double finalScore = Math.max(0, Math.min(100, base + bonus));

        List<String> reasons = new ArrayList<>();
        if (brand.status != BrandCheck.Status.NONE) {
            String suffix = bonus > 0 ? " (+" + (int) bonus + ")" : "";
            reasons.add("Cross-check: " + brand.reason + suffix);
        }
        for (String r : limit(urlReasons, 4)) reasons.add("URL (" + urlSource + "): " + r);
        if (hasText) for (String r : text.reasons) reasons.add("Message: " + r);

        return new RiskResult(finalScore, urlRisk, hasText ? text.score : -1, hasText, brand, reasons);
    }

    /** Keeps the first (max - 1) reasons and the last one (a tree's last line is its plain-language summary). */
    private static List<String> limit(List<String> list, int max) {
        if (list.size() <= max) return list;
        List<String> out = new ArrayList<>(list.subList(0, max - 1));
        out.add(list.get(list.size() - 1));
        return out;
    }
}