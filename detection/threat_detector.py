"""
threat_detector.py

Threat detection engine for NTCF.
"""

from detection.prediction_service import PredictionService


class ThreatDetector:

    def __init__(
        self,
        model_name="decision_tree",
    ):
        self.predictor = PredictionService(
            model_name=model_name
        )

    def detect(
        self,
        features,
    ):
        try:

            prediction, confidence = (
                self.predictor.predict(
                    features
                )
            )

            prediction_str = str(
                prediction
            )

            if (
                prediction_str.lower()
                == "normal"
            ):
                label = "Normal"
            else:
                label = "Threat"

            return {
                "prediction": prediction_str,
                "label": label,
                "confidence": round(
                    confidence,
                    4,
                ),
                "status": "success",
            }

        except Exception as error:

            return {
                "status": "error",
                "message": str(error),
            }