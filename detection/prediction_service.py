"""
prediction_service.py

Loads the trained ML model and generates predictions.
"""

import joblib
from pathlib import Path

from detection.confidence_calculator import calculate_confidence


ARTIFACT_DIR = Path(
    "ml/artifacts"
)

MODEL_PATH = (
    ARTIFACT_DIR
    / "random_forest_model.pkl"
)


class PredictionService:

    def __init__(self):

        self.model = joblib.load(
            MODEL_PATH
        )

    def predict(
        self,
        features,
    ):

        prediction = self.model.predict(
            features
        )[0]

        confidence = calculate_confidence(
            self.model,
            features,
        )

        return prediction, confidence