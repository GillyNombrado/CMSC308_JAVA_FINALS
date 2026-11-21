package phishguard.data;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public class DatasetConverter {
    public static void main(String[] args) throws Exception {
        String in = args.length > 0 ? args[0] : "resources/raw_dataset.csv";
        String out = args.length > 1 ? args[1] : "resources/urls_all.csv";

        List<String> phishing = new ArrayList<>();
        List<String> legit = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        // ISO_8859_1 never fails on odd bytes, which real URL lists often contain
        for (String line : Files.readAllLines(Paths.get(in), StandardCharsets.ISO_8859_1)) {
            line = line.trim();
            int comma = line.lastIndexOf(',');          // status is after the LAST comma
            if (comma < 0) continue;
            String url = line.substring(0, comma).trim();
            String status = line.substring(comma + 1).trim().toLowerCase();
            if (url.startsWith("\"") && url.endsWith("\"") && url.length() > 1)
                url = url.substring(1, url.length() - 1);
            if (url.isEmpty() || url.equalsIgnoreCase("url")) continue;   // skips the header
            if (!seen.add(url.toLowerCase())) continue;                   // removes duplicates

            if (status.equals("phishing")) phishing.add(url);
            else if (status.equals("legitimate")) legit.add(url);
        }

        // Balance the classes
        Random rnd = new Random(42);
        Collections.shuffle(phishing, rnd);
        Collections.shuffle(legit, rnd);
        int n = Math.min(phishing.size(), legit.size());

        try (PrintWriter w = new PrintWriter(out)) {
            for (int i = 0; i < n; i++) {
                w.println("1," + phishing.get(i));
                w.println("0," + legit.get(i));
            }
        }
        System.out.println("Found " + phishing.size() + " phishing and " + legit.size() + " legitimate.");
        System.out.println("Wrote " + (2 * n) + " balanced rows to " + out);
    }
}