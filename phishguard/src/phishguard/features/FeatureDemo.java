package phishguard.features;

import java.nio.file.*;
import java.util.*;

public class FeatureDemo {
    public static void main(String[] args) throws Exception {
        UrlFeatureExtractor ex = new UrlFeatureExtractor();
        for (String line : Files.readAllLines(Paths.get("resources/sample_urls.txt"))) {
            if (line.isBlank()) continue;
            System.out.println(line.trim());
            ex.extract(line).forEach((k, v) -> System.out.printf("  %-18s %.2f%n", k, v));
        }
    }
}