"""
test_detection.py

Automated tests for the NTCF detection layer.

Tests:
- Confidence calculation
- ThreatDetector
- Detection service
- Valid inputs
- Invalid inputs
- Unsupported models
- Error handling
"""

from unittest.mock import Mock, patch

import numpy as np
import pandas as pd
import pytest

from detection.confidence_calculator import calculate_confidence
from detection.threat_detector import ThreatDetector
from backend.services.detection_service import detect_threat


# ---------------------------------------------------------------------
# Test Features
# ---------------------------------------------------------------------

@pytest.fixture
def sample_features():
    """
    Small feature DataFrame used by detection tests.

    The detector is mocked in service-level tests, so the exact
    trained-model feature schema is not required here.
    """

    return pd.DataFrame(
        {
            "duration": [1],
            "src_bytes": [100],
            "dst_bytes": [50],
        }
    )


@pytest.fixture
def feature_payload():
    """
    Valid detection API payload.
    """

    return {
        "model_name": "decision_tree",
        "features": {
            "duration": 1,
            "src_bytes": 100,
            "dst_bytes": 50,
        },
    }


# =====================================================================
# Confidence Calculator Tests
# =====================================================================

class TestConfidenceCalculator:

    def test_predict_proba_confidence(
        self,
        sample_features,
    ):
        """
        Verify confidence calculation when the model
        provides predict_proba().
        """

        model = Mock()

        model.predict_proba.return_value = np.array(
            [
                [0.20, 0.80]
            ]
        )

        confidence = calculate_confidence(
            model,
            sample_features,
        )

        assert isinstance(
            confidence,
            float,
        )

        assert confidence == pytest.approx(
            0.80
        )

    def test_predict_proba_returns_maximum_probability(
        self,
        sample_features,
    ):
        """
        Verify that the highest class probability
        is returned.
        """

        model = Mock()

        model.predict_proba.return_value = np.array(
            [
                [0.10, 0.30, 0.60]
            ]
        )

        confidence = calculate_confidence(
            model,
            sample_features,
        )

        assert confidence == pytest.approx(
            0.60
        )

    def test_decision_function_confidence(
        self,
        sample_features,
    ):
        """
        Verify confidence calculation using
        decision_function().
        """

        model = Mock(
            spec=[
                "decision_function"
            ]
        )

        model.decision_function.return_value = np.array(
            [1.0, 2.0]
        )

        confidence = calculate_confidence(
            model,
            sample_features,
        )

        assert isinstance(
            confidence,
            float,
        )

        assert 0.0 <= confidence <= 1.0

    def test_fallback_confidence(
        self,
        sample_features,
    ):
        """
        Verify that models without probability
        interfaces return 1.0.
        """

        model = object()

        confidence = calculate_confidence(
            model,
            sample_features,
        )

        assert confidence == 1.0

    def test_confidence_error_falls_back_to_one(
        self,
        sample_features,
    ):
        """
        Verify that errors during confidence
        calculation return the documented fallback.
        """

        model = Mock()

        model.predict_proba.side_effect = Exception(
            "prediction error"
        )

        confidence = calculate_confidence(
            model,
            sample_features,
        )

        assert confidence == 1.0


# =====================================================================
# ThreatDetector Tests
# =====================================================================

class TestThreatDetector:

    def test_detector_initializes_with_default_model(self):
        """
        Verify ThreatDetector creates a predictor.
        """

        with patch(
            "detection.threat_detector.PredictionService"
        ) as prediction_service:

            detector = ThreatDetector()

            prediction_service.assert_called_once_with(
                model_name="random_forest"
            )

            assert detector.predictor is not None

    def test_detector_initializes_with_selected_model(self):
        """
        Verify that the requested model name is
        passed to PredictionService.
        """

        with patch(
            "detection.threat_detector.PredictionService"
        ) as prediction_service:

            ThreatDetector(
                model_name="decision_tree"
            )

            prediction_service.assert_called_once_with(
                model_name="decision_tree"
            )

    def test_detect_returns_success_for_normal_prediction(
        self,
        sample_features,
    ):
        """
        Verify that a normal prediction is labelled
        Normal.
        """

        with patch(
            "detection.threat_detector.PredictionService"
        ) as prediction_service:

            prediction_service.return_value.predict.return_value = (
                "normal",
                0.95,
            )

            detector = ThreatDetector()

            result = detector.detect(
                sample_features
            )

        assert result["status"] == "success"
        assert result["prediction"] == "normal"
        assert result["label"] == "Normal"
        assert result["confidence"] == 0.95

    def test_detect_returns_threat_label(
        self,
        sample_features,
    ):
        """
        Verify that non-normal predictions are
        labelled Threat.
        """

        with patch(
            "detection.threat_detector.PredictionService"
        ) as prediction_service:

            prediction_service.return_value.predict.return_value = (
                "neptune",
                0.91,
            )

            detector = ThreatDetector()

            result = detector.detect(
                sample_features
            )

        assert result["status"] == "success"
        assert result["prediction"] == "neptune"
        assert result["label"] == "Threat"
        assert result["confidence"] == 0.91

    def test_detect_rounds_confidence(
        self,
        sample_features,
    ):
        """
        Verify confidence is rounded to four decimal
        places.
        """

        with patch(
            "detection.threat_detector.PredictionService"
        ) as prediction_service:

            prediction_service.return_value.predict.return_value = (
                "normal",
                0.987654321,
            )

            detector = ThreatDetector()

            result = detector.detect(
                sample_features
            )

        assert result["confidence"] == 0.9877

    def test_detect_handles_prediction_error(
        self,
        sample_features,
    ):
        """
        Verify prediction errors are converted into
        a structured error response.
        """

        with patch(
            "detection.threat_detector.PredictionService"
        ) as prediction_service:

            prediction_service.return_value.predict.side_effect = (
                Exception("model failure")
            )

            detector = ThreatDetector()

            result = detector.detect(
                sample_features
            )

        assert result["status"] == "error"
        assert "message" in result
        assert "model failure" in result["message"]


# =====================================================================
# Detection Service Tests
# =====================================================================

class TestDetectionService:

    def test_non_dictionary_payload_is_rejected(self):
        """
        Verify that detection_service rejects payloads
        that are not JSON objects.
        """

        result = detect_threat(
            None
        )

        assert result["success"] is False
        assert result["status_code"] == 400
        assert result["message"] == (
            "JSON object expected."
        )

    def test_list_payload_is_rejected(self):
        """
        Verify list payloads are rejected.
        """

        result = detect_threat(
            []
        )

        assert result["success"] is False
        assert result["status_code"] == 400

    def test_missing_features_is_rejected(self):
        """
        Verify that the features field is required.
        """

        result = detect_threat(
            {
                "model_name": "decision_tree"
            }
        )

        assert result["success"] is False
        assert result["status_code"] == 400
        assert result["message"] == (
            "Missing 'features' field."
        )

    def test_successful_detection(
        self,
        feature_payload,
    ):
        """
        Verify successful detection service response.
        """

        mock_result = {
            "status": "success",
            "prediction": "normal",
            "label": "Normal",
            "confidence": 0.97,
        }

        with patch(
            "backend.services.detection_service.ThreatDetector"
        ) as detector_class:

            detector_class.return_value.detect.return_value = (
                mock_result
            )

            result = detect_threat(
                feature_payload
            )

        assert result["success"] is True
        assert result["status_code"] == 200
        assert result["prediction"] == "normal"
        assert result["label"] == "Normal"
        assert result["confidence"] == 0.97

    def test_model_name_is_passed_to_detector(
        self,
        feature_payload,
    ):
        """
        Verify that the requested model is passed
        to ThreatDetector.
        """

        with patch(
            "backend.services.detection_service.ThreatDetector"
        ) as detector_class:

            detector_class.return_value.detect.return_value = {
                "status": "success",
                "prediction": "normal",
                "label": "Normal",
                "confidence": 0.90,
            }

            detect_threat(
                feature_payload
            )

            detector_class.assert_called_once_with(
                model_name="decision_tree"
            )

    def test_detection_failure_returns_bad_request(
        self,
        feature_payload,
    ):
        """
        Verify that a detector-level failure is
        returned as HTTP 400.
        """

        with patch(
            "backend.services.detection_service.ThreatDetector"
        ) as detector_class:

            detector_class.return_value.detect.return_value = {
                "status": "error",
                "message": "Detection failed.",
            }

            result = detect_threat(
                feature_payload
            )

        assert result["success"] is False
        assert result["status_code"] == 400
        assert result["message"] == (
            "Detection failed."
        )

    def test_detector_exception_returns_server_error(
        self,
        feature_payload,
    ):
        """
        Verify unexpected detector exceptions
        return HTTP 500.
        """

        with patch(
            "backend.services.detection_service.ThreatDetector"
        ) as detector_class:

            detector_class.side_effect = Exception(
                "Unexpected detector error"
            )

            result = detect_threat(
                feature_payload
            )

        assert result["success"] is False
        assert result["status_code"] == 500
        assert "Unexpected detector error" in (
            result["message"]
        )

    def test_empty_features_are_accepted_by_service(
        self,
    ):
        """
        Verify that the service reaches the detector
        when an empty feature object is supplied.

        Feature-schema validation belongs to the model/
        preprocessing layer, not this service.
        """

        payload = {
            "model_name": "decision_tree",
            "features": {},
        }

        with patch(
            "backend.services.detection_service.ThreatDetector"
        ) as detector_class:

            detector_class.return_value.detect.return_value = {
                "status": "success",
                "prediction": "normal",
                "label": "Normal",
                "confidence": 0.80,
            }

            result = detect_threat(
                payload
            )

        assert result["success"] is True
        assert result["status_code"] == 200