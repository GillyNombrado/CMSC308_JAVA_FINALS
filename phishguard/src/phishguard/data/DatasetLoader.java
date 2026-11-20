package phishguard.data;

import java.nio.file.*;
import java.util.*;

public class DatasetLoader {

    public static class Dataset {
        public final List<String> urls = new ArrayList<>();
        public final List<Integer> labels = new ArrayList<>();
        public int size() { return urls.size(); }
    }

    /** Strips scheme, "www." and trailing slash so the model cannot learn dataset quirks. */
    public static String normalize(String url) {
        String u = url.trim().toLowerCase();
        u = u.replaceFirst("^[a-z][a-z0-9+.-]*://", "");
        u = u.replaceFirst("^www\\.", "");
        return u.replaceAll("/+$", "");
    }

    public static Dataset load(String path, boolean normalize) throws Exception {
        Dataset d = new Dataset();
        Set<String> seen = new HashSet<>();
        for (String line : Files.readAllLines(Paths.get(path))) {
            if (line.isBlank() || !line.contains(",")) continue;
            String[] p = line.split(",", 2);
            String url = normalize ? normalize(p[1]) : p[1].trim();
            if (url.isEmpty() || !seen.add(url)) continue;      // removes duplicates
            d.labels.add(Integer.parseInt(p[0].trim()));
            d.urls.add(url);
        }
        return d;
    }

    /** Shuffles with a fixed seed (repeatable results) and splits into train and test. */
    public static Dataset[] split(Dataset d, double trainRatio, long seed) {
        List<Integer> idx = new ArrayList<>();
        for (int i = 0; i < d.size(); i++) idx.add(i);
        Collections.shuffle(idx, new Random(seed));
        Dataset train = new Dataset(), test = new Dataset();
        int cut = (int) (d.size() * trainRatio);
        for (int k = 0; k < idx.size(); k++) {
            Dataset target = k < cut ? train : test;
            target.urls.add(d.urls.get(idx.get(k)));
            target.labels.add(d.labels.get(idx.get(k)));
        }
        return new Dataset[]{train, test};
    }
}