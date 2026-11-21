package phishguard.data;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * Converts the raw Kaggle file (89 columns: url, 87 precomputed features, status) into
 * resources/urls_all.csv with ONE URL and ONE label per line ("1,url" = phishing, "0,url" = legitimate).
 * Only the first column (url) and the last column (status) are used; the precomputed features are ignored
 * on purpose, because they include signals such as page rank and Google index that a URL-only tool cannot see.
 */
public class DatasetConverter {

    /** Splits one CSV line into fields, honoring double quotes. */
    static List<String> parseCsvLine(String line) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (inQuotes) {
                if (c == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') { cur.append('"'); i++; }
                    else inQuotes = false;
                } else cur.append(c);
            } else if (c == '"') inQuotes = true;
            else if (c == ',') { out.add(cur.toString()); cur.setLength(0); }
            else cur.append(c);
        }
        out.add(cur.toString());
        return out;
    }

    public static void main(String[] args) throws Exception {
        String in = args.length > 0 ? args[0] : "resources/raw_dataset.csv";
        String out = args.length > 1 ? args[1] : "resources/urls_all.csv";

        List<String> phishing = new ArrayList<>();
        List<String> legit = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        int skipped = 0;

        List<String> lines = Files.readAllLines(Paths.get(in), StandardCharsets.ISO_8859_1);
        for (int i = 1; i < lines.size(); i++) {                      // line 0 is the header
            String line = lines.get(i).trim();
            if (line.isEmpty()) continue;
            List<String> f = parseCsvLine(line);
            if (f.size() < 2) { skipped++; continue; }
            String url = f.get(0).trim();
            String status = f.get(f.size() - 1).trim().toLowerCase();
            if (url.isEmpty() || url.contains(",") || url.contains("\"")) { skipped++; continue; }
            if (!seen.add(url.toLowerCase())) continue;               // removes duplicates
            if (status.equals("phishing")) phishing.add(url);
            else if (status.equals("legitimate")) legit.add(url);
            else skipped++;
        }

        Random rnd = new Random(42);
        Collections.shuffle(phishing, rnd);
        Collections.shuffle(legit, rnd);
        int n = Math.min(phishing.size(), legit.size());

        try (PrintWriter w = new PrintWriter(out, "UTF-8")) {
            for (int k = 0; k < n; k++) {
                w.println("1," + phishing.get(k));
                w.println("0," + legit.get(k));
            }
        }
        System.out.println("Found " + phishing.size() + " phishing and " + legit.size() + " legitimate (skipped " + skipped + ").");
        System.out.println("Wrote " + (2 * n) + " balanced rows to " + out);
    }
}