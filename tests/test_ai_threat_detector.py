"""Unit tests for AI Threat Detector."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import pytest
from ai_threat_detector import detect_threats, extract_features, calculate_entropy, adaptive_rules


class TestExtractFeatures:
    def test_returns_numpy_array(self):
        data = np.array([1.0, 2.0, 3.0, 4.0])
        features = extract_features(data)
        assert isinstance(features, np.ndarray)

    def test_feature_shape(self):
        data = np.array([1.0, 2.0, 3.0, 4.0, 5.0])
        features = extract_features(data)
        assert features.shape[1] == 2
        assert len(features) == len(data) - 1


class TestCalculateEntropy:
    def test_returns_float(self):
        data = np.array([1, 1, 2, 2, 3, 3])
        result = calculate_entropy(data)
        assert isinstance(float(result), float)

    def test_uniform_distribution_high_entropy(self):
        data = np.array([1, 2, 3, 4, 5, 6])
        entropy = calculate_entropy(data)
        assert entropy > 0


class TestDetectThreats:
    def test_returns_predictions(self):
        data = np.random.rand(50)
        predictions = detect_threats(data)
        assert predictions is not None
        assert len(predictions) == len(data) - 1

    def test_predictions_are_plus_minus_one(self):
        data = np.random.rand(50)
        predictions = detect_threats(data)
        assert set(predictions).issubset({-1, 1})


class TestAdaptiveRules:
    def test_threat_detected(self, capsys):
        predictions = np.array([-1, 1, -1])
        adaptive_rules(predictions)
        captured = capsys.readouterr()
        assert 'Threat Detected' in captured.out

    def test_no_threat_detected(self, capsys):
        predictions = np.array([1, 1, 1])
        adaptive_rules(predictions)
        captured = capsys.readouterr()
        assert 'No Threat Detected' in captured.out
