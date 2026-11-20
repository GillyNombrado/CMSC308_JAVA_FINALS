package phishguard.features;

import java.net.URI;
import java.nio.file.*;
import java.util.*;

public class FirstTest {

    static String normalize(String url) {
        return url.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*") ? url : "http://" + url;
    }

    static final Set<String> TWO_PART_TLDS =
            Set.of("com.ph", "gov.ph", "edu.ph", "org.ph", "co.uk");

    static String registeredDomain(String host) {
        String[] p = host.split("\\.");
        if (p.length < 2) return host;
        String lastTwo = p[p.length - 2] + "." + p[p.length - 1];
        if (TWO_PART_TLDS.contains(lastTwo) && p.length >= 3)
            return p[p.length - 3] + "." + lastTwo;
        return lastTwo;
    }

    public static void main(String[] args) throws Exception {
        List<String> urls = Files.readAllLines(Path.of("resources/sample_urls.txt"));
        for (String raw : urls) {
            if (raw.isBlank()) continue;
            try {
                URI uri = new URI(normalize(raw.trim()));
                String host = uri.getHost();
                if (host == null) { System.out.println(raw + " -> UNPARSEABLE (suspicious)"); continue; }
                System.out.println(raw);
                System.out.println("  host:        " + host);
                System.out.println("  registered:  " + registeredDomain(host));
                System.out.println("  length:      " + raw.length());
                System.out.println("  https:       " + "https".equals(uri.getScheme()));
                System.out.println("  is IP host:  " + host.matches("\\d{1,3}(\\.\\d{1,3}){3}"));
                System.out.println("  dots/hyphens:" + raw.chars().filter(c -> c == '.').count()
                        + "/" + raw.chars().filter(c -> c == '-').count());
            } catch (Exception e) {
                System.out.println(raw + " -> PARSE ERROR (suspicious)");
            }
        }
    }
}