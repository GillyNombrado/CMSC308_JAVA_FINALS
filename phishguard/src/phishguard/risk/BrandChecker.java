package phishguard.risk;

import phishguard.features.StringUtils;
import java.util.*;

public class BrandChecker {

    // Keep in sync with the BRANDS map in UrlFeatureExtractor (move both to resources/brands.txt later).
    private static final Map<String, List<String>> OFFICIAL = new LinkedHashMap<>();
    private static final Map<String, String> DISPLAY = new LinkedHashMap<>();
    static {
        OFFICIAL.put("gcash", List.of("gcash.com"));
        OFFICIAL.put("maya", List.of("maya.ph", "paymaya.com"));
        OFFICIAL.put("bdo", List.of("bdo.com.ph"));
        OFFICIAL.put("paypal", List.of("paypal.com"));
        OFFICIAL.put("lbcexpress", List.of("lbcexpress.com"));
        OFFICIAL.put("shopee", List.of("shopee.ph", "shopee.com"));
        OFFICIAL.put("lazada", List.of("lazada.com.ph", "lazada.com"));

        DISPLAY.put("gcash", "GCash");
        DISPLAY.put("maya", "Maya");
        DISPLAY.put("bdo", "BDO");
        DISPLAY.put("paypal", "PayPal");
        DISPLAY.put("lbcexpress", "LBC");
        DISPLAY.put("shopee", "Shopee");
        DISPLAY.put("lazada", "Lazada");
    }

    private static final Set<String> SHORTENERS =
            Set.of("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "ow.ly", "rebrand.ly");

    /**
     * @param messageBrands brand keys the message claims to be from (from TextResult.brands), may be empty
     * @param rawUrl        the URL exactly as the user pasted it
     */
    public BrandCheck check(Set<String> messageBrands, String rawUrl) {
        Set<String> claimed = messageBrands == null ? Set.of() : messageBrands;
        String host = hostOf(rawUrl);

        if (host == null) {
            return claimed.isEmpty() ? BrandCheck.none()
                    : new BrandCheck(BrandCheck.Status.UNVERIFIABLE,
                        "The message names " + names(claimed) + ", but the link could not be read");
        }
        if (SHORTENERS.contains(host)) {
            return claimed.isEmpty() ? BrandCheck.none()
                    : new BrandCheck(BrandCheck.Status.UNVERIFIABLE,
                        "The message names " + names(claimed)
                        + ", but the link is shortened, so its real destination is hidden");
        }

        String reg = StringUtils.registeredDomain(host);

        // Case 1: the message claims a brand
        if (!claimed.isEmpty()) {
            for (String b : claimed)
                if (isOfficial(b, reg))
                    return new BrandCheck(BrandCheck.Status.MATCH,
                            "The message names " + names(claimed) + " and the link goes to its official domain (" + reg + ")");
            String look = lookalike(reg);
            String extra = look == null ? "" : " (the domain also looks like " + look + ")";
            return new BrandCheck(BrandCheck.Status.MISMATCH,
                    "The message claims to be from " + names(claimed) + ", but the link goes to " + reg + extra);
        }

        // Case 2: no brand in the message, so check the URL itself
        Set<String> inHost = brandsInHost(host);
        inHost.removeIf(b -> isOfficial(b, reg));
        if (!inHost.isEmpty())
            return new BrandCheck(BrandCheck.Status.MISMATCH,
                    "The web address uses the name " + names(inHost) + ", but its real domain is " + reg);

        String look = lookalike(reg);
        if (look != null)
            return new BrandCheck(BrandCheck.Status.MISMATCH,
                    "The domain " + reg + " looks like the official domain " + look);

        return BrandCheck.none();
    }

    // ---------- helpers ----------

    /** Extracts the host from a raw URL. Handles a missing scheme, ports, paths and the user@host trick. */
    static String hostOf(String raw) {
        if (raw == null) return null;
        String s = raw.trim().toLowerCase().replaceFirst("^[a-z][a-z0-9+.-]*://", "");
        int cut = s.length();
        for (char c : new char[]{'/', '?', '#'}) {
            int i = s.indexOf(c);
            if (i >= 0 && i < cut) cut = i;
        }
        s = s.substring(0, cut);
        int at = s.lastIndexOf('@');
        if (at >= 0) s = s.substring(at + 1);
        int colon = s.indexOf(':');
        if (colon >= 0) s = s.substring(0, colon);
        return s.isEmpty() ? null : s;
    }

    private static boolean isOfficial(String brandKey, String reg) {
        List<String> domains = OFFICIAL.get(brandKey);
        return domains != null && domains.contains(reg);
    }

    /** Brand keys that appear in the host. Short names (bdo, maya) must match a whole word. */
    private static Set<String> brandsInHost(String host) {
        Set<String> tokens = new HashSet<>(Arrays.asList(host.split("[^a-z0-9]+")));
        Set<String> found = new LinkedHashSet<>();
        for (String key : OFFICIAL.keySet())
            if (key.length() >= 5 ? host.contains(key) : tokens.contains(key)) found.add(key);
        if (host.contains("paymaya")) found.add("maya");
        return found;
    }

    /** Returns the official domain this one imitates (1-2 typos away), or null. */
    private static String lookalike(String reg) {
        for (List<String> domains : OFFICIAL.values())
            if (domains.contains(reg)) return null;               // it IS an official domain
        String label = reg.substring(0, reg.indexOf('.') < 0 ? reg.length() : reg.indexOf('.'));
        for (List<String> domains : OFFICIAL.values())
            for (String d : domains) {
                String official = d.substring(0, d.indexOf('.'));
                if (official.length() < 5 || label.equals(official)) continue;   // short names cause false alarms
                int maxDist = official.length() >= 8 ? 2 : 1;
                if (StringUtils.levenshtein(label, official) <= maxDist) return d;
            }
        return null;
    }

    private static String names(Set<String> keys) {
        List<String> out = new ArrayList<>();
        for (String k : keys) out.add(DISPLAY.getOrDefault(k, k));
        return String.join(" / ", out);
    }
}