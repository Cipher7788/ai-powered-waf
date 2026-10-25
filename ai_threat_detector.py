"""Lightweight advisory anomaly features.

This module intentionally does not train an IsolationForest on each individual request:
doing so has no meaningful reference distribution and produces misleading predictions.
The rule-based WAF remains the enforcement authority until a validated model is supplied.
"""
import math
from collections import Counter
import re


def extract_features(data):
    text = data if isinstance(data, str) else repr(data)
    text = text[:10000]
    if not text:
        return {"length": 0, "entropy": 0.0, "control_ratio": 0.0, "encoding_ratio": 0.0}
    counts = Counter(text)
    entropy = -sum((count / len(text)) * math.log2(count / len(text)) for count in counts.values())
    controls = sum(ord(char) < 32 and char not in "\t\r\n" for char in text)
    encoded = len(re.findall(r"%(?:[0-9a-fA-F]{2})", text))
    return {
        "length": len(text),
        "entropy": round(entropy, 4),
        "control_ratio": controls / len(text),
        "encoding_ratio": encoded / len(text),
    }


def detect_threats(data):
    """Return an advisory one-element prediction list (-1 anomalous, 1 ordinary)."""
    features = extract_features(data)
    anomalous = (
        features["control_ratio"] > 0.01
        or features["encoding_ratio"] > 0.15
        or (features["length"] > 2000 and features["entropy"] > 5.5)
    )
    return [-1 if anomalous else 1]


def adaptive_rules(predictions):
    """Return whether the advisory detector reported an anomaly."""
    return any(int(prediction) == -1 for prediction in predictions)
