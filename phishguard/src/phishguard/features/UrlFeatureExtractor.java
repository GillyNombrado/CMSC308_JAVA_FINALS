package phishguard.features;

import java.net.URI;
import java.util.*;

public class UrlFeatureExtractor {

    // brand keyword -> official registered domains (move to resources/brands.txt later)
    private static final Map<String, List<String>> BRANDS = new LinkedHashMap<>();
    static {
        BRANDS.put("gcash", List.of("gcash.com"));
        BRANDS.put("maya", List.of("maya.ph", "paymaya.com"));
        BRANDS.put("bdo", List.of("bdo.com.ph"));
        BRANDS.put("paypal", List.of("paypal.com"));
        BRANDS.put("lbcexpress", List.of("lbcexpress.com"));
        BRANDS.put("shopee", List.of("shopee.ph", "shopee.com"));
        BRANDS.put("lazada", List.of("lazada.com.ph", "lazada.com"));
    }

    private static final Set<String> RISKY_TLDS =
            Set.of("xyz", "top", "click", "icu", "buzz", "tk", "ml", "ga", "cf", "gq", "rest", "work");
    private static final Set<String> SHORTENERS =
            Set.of("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "ow.ly", "rebrand.ly");
    private static final List<String> SUSPICIOUS_WORDS =
            List.of("login", "signin", "verify", "secure", "account", "update", "bank",
                    "claim", "prize", "confirm", "wallet", "free", "bonus", "suspend");

    public Map<String, Double> extract(String rawUrl) {
        Map<String, Double> f = new LinkedHashMap<>();
        String url = rawUrl == null ? "" : rawUrl.trim();
        String lower = url.toLowerCase();

        String normalized = url.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*") ? url : "http://" + url;
        String host = null, path = "", scheme = "";
        int port = -1;
        try {
            URI uri = new URI(normalized);
            host = uri.getHost();
            path = uri.getPath() == null ? "" : uri.getPath();
            scheme = uri.getScheme() == null ? "" : uri.getScheme();
            port = uri.getPort();
        } catch (Exception ignored) { }

        // Length and character counts
        f.put("url_length", (double) url.length());
        f.put("path_length", (double) path.length());
        f.put("dot_count", (double) StringUtils.count(url, '.'));
        f.put("hyphen_count", (double) StringUtils.count(url, '-'));
        f.put("at_count", (double) StringUtils.count(url, '@'));
        f.put("question_count", (double) StringUtils.count(url, '?'));
        f.put("equals_count", (double) StringUtils.count(url, '='));
        f.put("percent_count", (double) StringUtils.count(url, '%'));
        f.put("digit_count", (double) url.chars().filter(Character::isDigit).count());

        // Unparseable: mark suspicious and stop
        if (host == null) {
            f.put("parse_error", 1.0);
            for (String k : List.of("host_length", "is_ip", "is_https", "has_port", "subdomain_count",
                    "suspicious_words", "brand_mismatch", "lookalike", "risky_tld", "is_shortener", "domain_entropy"))
                f.put(k, 0.0);
            return f;
        }
        host = host.toLowerCase();
        String reg = StringUtils.registeredDomain(host);
        boolean ip = StringUtils.isIp(host);

        f.put("parse_error", 0.0);
        f.put("host_length", (double) host.length());
        f.put("is_ip", ip ? 1.0 : 0.0);
        f.put("is_https", "https".equals(scheme) ? 1.0 : 0.0);
        f.put("has_port", port != -1 ? 1.0 : 0.0);

        // Subdomain count (a leading "www" is ignored so real sites are not penalized)
        String hostNoWww = host.startsWith("www.") ? host.substring(4) : host;
        int subdomains = ip ? 0 : Math.max(0, hostNoWww.split("\\.").length - reg.split("\\.").length);
        f.put("subdomain_count", (double) subdomains);

        int words = 0;
        for (String w : SUSPICIOUS_WORDS) if (lower.contains(w)) words++;
        f.put("suspicious_words", (double) words);

        // Brand impersonation: brand appears in the URL but registered domain is not official
        boolean mismatch = false;
        for (Map.Entry<String, List<String>> b : BRANDS.entrySet())
            if (lower.contains(b.getKey()) && !b.getValue().contains(reg)) mismatch = true;
        f.put("brand_mismatch", mismatch ? 1.0 : 0.0);

        // Lookalike: registered domain is 1-2 edits away from an official domain (but not equal)
        boolean lookalike = false;
        for (List<String> official : BRANDS.values())
            for (String d : official) {
                int dist = StringUtils.levenshtein(reg, d);
                if (dist >= 1 && dist <= 2 && reg.length() >= 5) lookalike = true;
            }
        f.put("lookalike", lookalike ? 1.0 : 0.0);

        f.put("risky_tld", RISKY_TLDS.contains(StringUtils.tld(host)) ? 1.0 : 0.0);
        f.put("is_shortener", SHORTENERS.contains(host) ? 1.0 : 0.0);

        String label = ip ? host : reg.substring(0, reg.indexOf('.') < 0 ? reg.length() : reg.indexOf('.'));
        f.put("domain_entropy", StringUtils.entropy(label));
        return f;
    }
}