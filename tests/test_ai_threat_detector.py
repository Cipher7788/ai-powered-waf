import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

"""Tests for the advisory anomaly feature extractor."""
from ai_threat_detector import detect_threats, extract_features, adaptive_rules


def test_feature_extraction_for_normal_payload():
    features = extract_features({"message": "hello"})
    assert features["length"] > 0
    assert 0 <= features["entropy"]


def test_empty_payload_features():
    features = extract_features("")
    assert features["length"] == 0
    assert features["entropy"] == 0.0


def test_detector_returns_advisory_prediction():
    predictions = detect_threats("ordinary short request")
    assert predictions in ([-1], [1])


def test_detector_flags_encoded_payload_as_advisory_anomaly():
    predictions = detect_threats("%41" * 100)
    assert predictions == [-1]


def test_adaptive_rules_reports_anomaly():
    assert adaptive_rules([-1, 1]) is True


def test_adaptive_rules_reports_normal():
    assert adaptive_rules([1, 1]) is False
