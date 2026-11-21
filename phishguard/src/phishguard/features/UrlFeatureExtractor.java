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
            addPathFeatures(f, lower);
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

        // ---- New path/query features (added at the end so older results stay reproducible) ----
        addPathFeatures(f, lower);
        return f;
    }

    /** Features that describe the path and query. Works on the raw lowercase text, so it never fails. */
    private void addPathFeatures(Map<String, Double> f, String lower) {
        String s = lower.replaceFirst("^[a-z][a-z0-9+.-]*://", "");
        int hash = s.indexOf('#');
        if (hash >= 0) s = s.substring(0, hash);

        int cut = s.length();
        for (char c : new char[]{'/', '?'}) {
            int i = s.indexOf(c);
            if (i >= 0 && i < cut) cut = i;
        }
        String hostPart = s.substring(0, cut);
        String rest = s.substring(cut);                       // path + query
        int q = rest.indexOf('?');
        String pathPart = q >= 0 ? rest.substring(0, q) : rest;
        String query = q >= 0 ? rest.substring(q + 1) : "";

        // Path segments and file extension
        int segments = 0;
        String lastSegment = "";
        for (String seg : pathPart.split("/")) {
            if (!seg.isEmpty()) { segments++; lastSegment = seg; }
        }
        int params = query.isEmpty() ? 0 : query.split("&").length;

        // Longest run of letters/digits
        int longest = 0, run = 0;
        for (char c : lower.toCharArray()) {
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) { run++; longest = Math.max(longest, run); }
            else run = 0;
        }

        // Hex-like blob: a token of 16+ hex characters in the path or query
        boolean hexBlob = false;
        for (String t : rest.split("[^a-z0-9]+"))
            if (t.length() >= 16 && t.matches("[0-9a-f]+")) hexBlob = true;

        // Suspicious words: where do they appear?
        int wordsHost = 0, wordsPath = 0;
        for (String w : SUSPICIOUS_WORDS) {
            if (hostPart.contains(w)) wordsHost++;
            if (rest.contains(w)) wordsPath++;
        }

        long digits = lower.chars().filter(Character::isDigit).count();

        f.put("path_segments", (double) segments);
        f.put("query_params", (double) params);
        f.put("digit_ratio", lower.isEmpty() ? 0.0 : (double) digits / lower.length());
        f.put("longest_token", (double) longest);
        f.put("has_hex_blob", hexBlob ? 1.0 : 0.0);
        f.put("ext_php", lastSegment.endsWith(".php") ? 1.0 : 0.0);
        f.put("ext_html", (lastSegment.endsWith(".html") || lastSegment.endsWith(".htm")) ? 1.0 : 0.0);
        f.put("words_in_host", (double) wordsHost);
        f.put("words_in_path", (double) wordsPath);
    }
}