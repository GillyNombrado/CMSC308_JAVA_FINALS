package phishguard.text;

import java.util.*;

public class TextScamAnalyzer {

    private static class Category {
        final String label;
        final int weight;
        final String[] phrases;
        Category(String label, int weight, String... phrases) {
            this.label = label; this.weight = weight; this.phrases = phrases;
        }
    }

    // Phrases are written already normalized: lowercase letters, digits, single spaces.
    private static final List<Category> CATEGORIES = List.of(
        new Category("Urgency wording", 20,
            "claim now", "act now", "within 24 hours", "last chance", "limited slots", "limited time",
            "expires today", "today only", "right now", "immediately", "ngayon na", "agad agad",
            "bilisan mo", "mag reply agad", "before it expires", "hurry"),
        new Category("Prize or reward bait", 25,
            "you won", "you have won", "congratulations", "congrats", "free gift", "claim your prize",
            "claim your reward", "winner", "raffle winner", "free load", "free cash", "gift card",
            "panalo ka", "nanalo ka", "nanalo", "libreng"),
        new Category("Account threat", 25,
            "account locked", "account is locked", "account has been locked", "account suspended",
            "account is suspended", "has been suspended", "suspended", "account blocked",
            "account is blocked", "account will be closed", "unusual activity", "suspicious activity",
            "verify your account", "verify now", "account verification", "confirm your identity",
            "na block ang account", "na lock ang account", "na deactivate", "mawawala ang account"),
        new Category("Request for sensitive information", 30,
            "send your otp", "enter your otp", "share your otp", "reply with your otp", "ibigay ang otp",
            "ibigay mo ang otp", "send your pin", "pin number", "your password", "ilagay ang password",
            "send your details", "magpadala ng details", "card number", "cvv"),
        new Category("Money or job bait", 25,
            "easy income", "work from home", "earn daily", "part time job", "hiring now",
            "guaranteed profit", "double your money", "processing fee", "registration fee", "send fee",
            "send money", "magpadala ng pera", "kumita ng", "pera online", "walang puhunan"),
        new Category("Delivery scam wording", 20,
            "package on hold", "parcel on hold", "unpaid shipping fee", "redelivery fee", "failed delivery",
            "delivery attempt", "customs fee", "update your address", "pending parcel", "hindi na deliver")
    );

    // Phrases that normally appear in genuine notices, so they lower the score.
    private static final String[] SAFE_CUES = {
        "do not share", "never share", "don t share", "huwag ibahagi", "wag ibahagi", "wag ibigay"
    };

    // Brand phrase -> brand key (keys match the BRANDS map in UrlFeatureExtractor)
    private static final Map<String, String> BRAND_WORDS = new LinkedHashMap<>();
    static {
        BRAND_WORDS.put("gcash", "gcash");
        BRAND_WORDS.put("maya", "maya");
        BRAND_WORDS.put("paymaya", "maya");
        BRAND_WORDS.put("bdo", "bdo");
        BRAND_WORDS.put("paypal", "paypal");
        BRAND_WORDS.put("lbc", "lbcexpress");
        BRAND_WORDS.put("shopee", "shopee");
        BRAND_WORDS.put("lazada", "lazada");
    }

    static String normalize(String s) {
        return " " + s.toLowerCase().replaceAll("[^a-z0-9]+", " ").trim() + " ";
    }

    public TextResult analyze(String message) {
        if (message == null || message.isBlank())
            return new TextResult(0, List.of("No message provided"), Set.of());

        String padded = normalize(message);
        double score = 0;
        List<String> reasons = new ArrayList<>();
        int categoriesHit = 0;

        for (Category c : CATEGORIES) {
            List<String> hits = new ArrayList<>();
            for (String p : c.phrases)
                if (padded.contains(" " + p + " ")) hits.add(p);
            if (hits.isEmpty()) continue;
            categoriesHit++;
            int pts = c.weight + Math.min(6, 3 * (hits.size() - 1));   // small bonus for extra hits
            score += pts;
            reasons.add(String.format("%s: %s (+%d)", c.label,
                    String.join(", ", hits.subList(0, Math.min(4, hits.size()))), pts));
        }

        // Combination bonus: scams usually mix several tricks
        if (categoriesHit >= 2) {
            score += 10; reasons.add("Several kinds of scam wording together (+10)");
        }

        // Brands the message claims to be from
        Set<String> brands = new LinkedHashSet<>();
        for (Map.Entry<String, String> b : BRAND_WORDS.entrySet())
            if (padded.contains(" " + b.getKey() + " ")) brands.add(b.getValue());

        if (!brands.isEmpty() && categoriesHit > 0) {
            score += 10; reasons.add("Claims to be from a known brand while using scam wording (+10)");
        }

        // Style signals (use the original text, not the normalized one)
        long letters = message.chars().filter(Character::isLetter).count();
        long upper = message.chars().filter(Character::isUpperCase).count();
        if (letters >= 15 && (double) upper / letters > 0.5) {
            score += 8; reasons.add("Mostly capital letters (+8)");
        }
        long exclaim = message.chars().filter(ch -> ch == '!').count();
        if (exclaim >= 3) {
            score += 5; reasons.add("Many exclamation marks (+5)");
        }
        String lower = message.toLowerCase();
        boolean hasLink = lower.contains("http") || lower.contains("www.") || lower.contains("bit.ly")
                || lower.matches(".*\\b[a-z0-9-]+\\.(com|ph|xyz|top|click|net|org|info)\\b.*");
        if (hasLink && categoriesHit > 0) {
            score += 5; reasons.add("Contains a link alongside scam wording (+5)");
        }

        // Safe cues lower the score (for example genuine OTP notices)
        for (String cue : SAFE_CUES) {
            if (padded.contains(" " + cue + " ")) {
                score = Math.max(0, score - 20);
                reasons.add("Warns the reader not to share codes, like genuine notices do (-20)");
                break;
            }
        }

        score = Math.min(100, score);
        if (reasons.isEmpty()) reasons.add("No scam wording found");
        return new TextResult(score, reasons, brands);
    }
}