package phishguard.data;

import java.io.PrintWriter;
import java.util.*;

public class SyntheticGenerator {
    static final Random R = new Random(7);

    static final String[] LEGIT = {"wikipedia.org", "google.com", "youtube.com", "gcash.com", "bdo.com.ph",
        "lbcexpress.com", "shopee.ph", "lazada.com.ph", "up.edu.ph", "dost.gov.ph", "bpi.com.ph",
        "metrobank.com.ph", "gov.ph", "pna.gov.ph", "rappler.com", "inquirer.net", "github.com",
        "microsoft.com", "apple.com", "paypal.com", "maya.ph", "ateneo.edu", "dlsu.edu.ph", "philhealth.gov.ph"};
    static final String[] PATHS = {"", "", "/about", "/help/contact", "/products/item?id=", "/news/2026/article",
        "/search?q=load", "/login", "/account/settings", "/support", "/careers", "/faq"};
    static final String[] BRANDS = {"gcash", "maya", "bdo", "paypal", "lbcexpress", "shopee", "lazada"};
    static final String[] WORDS = {"verify", "secure", "login", "update", "account", "claim", "prize",
        "confirm", "support", "wallet", "bonus", "free", "online", "help"};
    static final String[] TLDS = {"xyz", "top", "click", "icu", "buzz", "tk", "work", "info", "online", "site", "com"};

    static String pick(String[] a) { return a[R.nextInt(a.length)]; }

    static String legit() {
        String p = pick(PATHS);
        if (p.endsWith("=")) p += R.nextInt(9999);
        return (R.nextBoolean() ? "https://www." : "https://") + pick(LEGIT) + p;
    }

    static String randomLabel(int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append((char) ('a' + R.nextInt(26)));
        return sb.toString();
    }

    static String lookalike(String brand) {
        StringBuilder sb = new StringBuilder(brand);
        int i = R.nextInt(sb.length());
        char c = sb.charAt(i);
        sb.setCharAt(i, c == 'l' ? '1' : c == 'o' ? '0' : c == 'a' ? '4' : (char) ('a' + R.nextInt(26)));
        return sb.toString();
    }

    static String phish() {
        String brand = pick(BRANDS), w1 = pick(WORDS), w2 = pick(WORDS), tld = pick(TLDS);
        String scheme = R.nextInt(3) == 0 ? "https://" : (R.nextBoolean() ? "http://" : "");
        switch (R.nextInt(7)) {
            case 0: return scheme + brand + "-" + w1 + "-" + w2 + "." + tld + "/" + w1;
            case 1: return scheme + w1 + "." + brand + ".com." + randomLabel(6) + "-" + w2 + "." + tld + "/" + w2;
            case 2: return scheme + R.nextInt(224) + "." + R.nextInt(256) + "." + R.nextInt(256) + "."
                    + R.nextInt(256) + "/" + brand + "/" + w1;
            case 3: return scheme + lookalike(brand) + ".com/" + w1;
            case 4: return scheme + randomLabel(8 + R.nextInt(8)) + "." + tld + "/" + w1 + "?id=" + R.nextInt(99999);
            case 5: return scheme + brand + w1 + "." + tld + "/" + w2 + "/" + w1 + "?ref=" + R.nextInt(999);
            default: return scheme + "www." + brand + "-" + w1 + ".com/" + w2;
        }
    }

    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 500;
        try (PrintWriter out = new PrintWriter("resources/urls_synthetic.csv")) {
            for (int i = 0; i < n; i++) { out.println("0," + legit()); out.println("1," + phish()); }
        }
        System.out.println("Wrote " + (2 * n) + " rows to resources/urls_synthetic.csv");
    }
}