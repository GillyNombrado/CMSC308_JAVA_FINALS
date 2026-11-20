package phishguard.classify;

import java.util.Map;

public interface Classifier {
    ClassifierResult classify(Map<String, Double> features);
}