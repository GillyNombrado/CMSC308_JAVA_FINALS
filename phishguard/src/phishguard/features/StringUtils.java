package phishguard.features;

import java.util.*;

public class StringUtils {

    private static final Set<String> TWO_PART_TLDS =
            Set.of("com.ph", "gov.ph", "edu.ph", "org.ph", "net.ph", "co.uk");

    public static boolean isIp(String host) {
        return host != null && host.matches("\\d{1,3}(\\.\\d{1,3}){3}");
    }

    public static String registeredDomain(String host) {
        if (host == null || isIp(host)) return host;
        String[] p = host.split("\\.");
        if (p.length < 2) return host;
        String lastTwo = p[p.length - 2] + "." + p[p.length - 1];
        if (TWO_PART_TLDS.contains(lastTwo) && p.length >= 3)
            return p[p.length - 3] + "." + lastTwo;
        return lastTwo;
    }

    public static String tld(String host) {
        int i = host.lastIndexOf('.');
        return i < 0 ? "" : host.substring(i + 1);
    }

    public static double entropy(String s) {
        if (s == null || s.isEmpty()) return 0;
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : s.toCharArray()) freq.merge(c, 1, Integer::sum);
        double h = 0;
        for (int n : freq.values()) {
            double p = (double) n / s.length();
            h -= p * Math.log(p) / Math.log(2);
        }
        return h;
    }

    public static int levenshtein(String a, String b) {
        int[] prev = new int[b.length() + 1], cur = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) prev[j] = j;
        for (int i = 1; i <= a.length(); i++) {
            cur[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                cur[j] = Math.min(Math.min(cur[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
            }
            int[] t = prev; prev = cur; cur = t;
        }
        return prev[b.length()];
    }

    public static long count(String s, char c) {
        return s.chars().filter(x -> x == c).count();
    }
}