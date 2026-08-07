"""
detection_service.py

Backend service for exposing NTCF threat detection.
"""

import pandas as pd

from detection.threat_detector import ThreatDetector


def detect_threat(payload):
    """
    Perform threat detection from API input.
    """

    if not isinstance(payload, dict):
        return {
            "success": False,
            "status_code": 400,
            "message": "JSON object expected."
        }

    model_name = payload.get("model_name", "random_forest")

    features = payload.get("features")

    if features is None:
        return {
            "success": False,
            "status_code": 400,
            "message": "Missing 'features' field."
        }

    try:

        df = pd.DataFrame([features])

        detector = ThreatDetector(
            model_name=model_name
        )

        result = detector.detect(df)

        if result["status"] == "success":

            return {
                "success": True,
                "status_code": 200,
                "prediction": result["prediction"],
                "label": result["label"],
                "confidence": result["confidence"],
            }

        return {
            "success": False,
            "status_code": 400,
            "message": result["message"],
        }

    except Exception as error:

        return {
            "success": False,
            "status_code": 500,
            "message": str(error),
        }