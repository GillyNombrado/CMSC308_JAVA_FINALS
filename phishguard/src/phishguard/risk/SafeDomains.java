package phishguard.risk;

import phishguard.features.StringUtils;
import java.util.*;

/**
 * A short, hand-made list of well-known official domains. A link whose REAL registered domain is on
 * this list gets a low link risk. Rules that keep it safe:
 *  - exact match on the registered domain, so "google.com.evil.xyz" and "g00gle.com" never match;
 *  - services where anyone can publish a page (docs.google.com, github.io, blogspot.com...) are never trusted;
 *  - it only lowers the LINK score. Scam wording in a message can still raise the final score.
 * Review and extend this list yourself. It is a design choice, not a measurement.
 */
public class SafeDomains {

    private static final Set<String> TRUSTED = new HashSet<>(Arrays.asList(
        // global
        "google.com", "youtube.com", "facebook.com", "instagram.com", "twitter.com", "x.com",
        "wikipedia.org", "microsoft.com", "apple.com", "amazon.com", "github.com", "linkedin.com",
        "netflix.com", "paypal.com", "zoom.us", "whatsapp.com", "tiktok.com", "reddit.com",
        "yahoo.com", "bing.com", "canva.com", "imdb.com", "stackoverflow.com", "mozilla.org",
        "adobe.com", "spotify.com", "ebay.com",
        // Philippine banks, e-wallets, shopping, delivery, telcos, utilities
        "gcash.com", "maya.ph", "paymaya.com", "bdo.com.ph", "bpi.com.ph", "metrobank.com.ph",
        "landbank.com", "securitybank.com", "unionbankph.com", "rcbc.com", "pnb.com.ph",
        "shopee.ph", "shopee.com", "lazada.com.ph", "lazada.com", "lbcexpress.com", "jtexpress.ph",
        "grab.com", "globe.com.ph", "smart.com.ph", "meralco.com.ph", "mercurydrug.com",
        // Philippine news and universities
        "inquirer.net", "rappler.com", "gmanetwork.com", "abs-cbn.com", "philstar.com",
        "up.edu.ph", "dlsu.edu.ph", "ateneo.edu", "ust.edu.ph"
    ));

    /** Hosts (and everything under them) where anyone can publish content, so they are never trusted. */
    private static final String[] USER_CONTENT = {
        "docs.google.com", "drive.google.com", "sites.google.com", "forms.gle", "storage.googleapis.com",
        "script.google.com", "github.io", "githubusercontent.com", "gist.github.com",
        "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com", "firebaseapp.com", "web.app",
        "netlify.app", "vercel.app", "pages.dev", "herokuapp.com", "dropbox.com", "onedrive.live.com",
        "sharepoint.com", "mediafire.com", "wetransfer.com",
        "storage.cloud.google.com", "cloud.google.com", "appspot.com", "googleusercontent.com",
        "translate.google.com", "translate.goog"
    };

    /** Signs that a link only forwards the visitor somewhere else (open redirects are common in phishing). */
    private static final String[] REDIRECT_SIGNS = {
        "http://", "https://", "%3a%2f%2f", "%3a//", "/url?", "/redirect", "redir=", "redirect=",
        "continue=", "returnurl=", "return_to=", "next=", "service=", "goto="
    };

    /** @param host a host name such as "www.bdo.com.ph" (any case). */
    public static boolean isTrustedHost(String host) {
        if (host == null || host.isEmpty() || StringUtils.isIp(host)) return false;
        host = host.toLowerCase();
        for (String u : USER_CONTENT)
            if (host.equals(u) || host.endsWith("." + u)) return false;
        String reg = StringUtils.registeredDomain(host);
        return TRUSTED.contains(reg) || reg.endsWith(".gov.ph");
    }

    /** @param url a link as pasted by the user (scheme optional). */
    public static boolean isTrustedUrl(String url) {
        if (url == null) return false;
        String rest = url.trim().toLowerCase().replaceFirst("^[a-z][a-z0-9+.-]*://", "");
        for (String sign : REDIRECT_SIGNS)
            if (rest.contains(sign)) return false;      // a link that forwards elsewhere is never trusted
        return isTrustedHost(BrandChecker.hostOf(url));
    }

    /** The registered domain, for showing in a reason. */
    public static String registeredDomainOf(String url) {
        String h = BrandChecker.hostOf(url);
        return h == null ? "" : StringUtils.registeredDomain(h);
    }
}
