"""
threat_detector.py

Threat detection engine for NTCF.
"""

from detection.prediction_service import (
    PredictionService,
)


class ThreatDetector:

    def __init__(self):

        self.predictor = PredictionService()

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

            if prediction == 0:

                label = "Normal"

            else:

                label = "Threat"

            return {

                "prediction": int(
                    prediction
                ),

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

                "message": str(
                    error
                ),

            }