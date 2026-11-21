package phishguard.risk;

import java.util.*;

public class RiskResult {
    public final double score;          // final 0-100
    public final double urlScore;
    public final double textScore;      // -1 when no message was given
    public final boolean hasMessage;
    public final BrandCheck brand;
    public final List<String> reasons;

    public RiskResult(double score, double urlScore, double textScore, boolean hasMessage,
                      BrandCheck brand, List<String> reasons) {
        this.score = score;
        this.urlScore = urlScore;
        this.textScore = textScore;
        this.hasMessage = hasMessage;
        this.brand = brand;
        this.reasons = reasons;
    }

    public String level() {
        if (score >= 70) return "High";
        if (score >= 40) return "Medium";
        return "Low";
    }

    public String advice() {
        switch (level()) {
            case "High":
                return "Do not click the link and do not share OTPs, PINs, or passwords. "
                     + "Report it through the official support channel of the brand it imitates.";
            case "Medium":
                return "Be careful. Do not enter personal details. Open the official app or type the "
                     + "official website yourself instead of using this link.";
            default:
                return "No strong warning signs were found. This is an estimate, not a guarantee.";
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("FINAL RISK: %.0f (%s)%n", score, level()));
        sb.append(String.format("  URL risk: %.0f | Message risk: %s | Brand check: %s%n",
                urlScore, hasMessage ? String.format("%.0f", textScore) : "n/a", brand.status));
        for (String r : reasons) sb.append("   - ").append(r).append(System.lineSeparator());
        sb.append("  Advice: ").append(advice());
        return sb.toString();
    }
}