"""
prediction_service.py

Loads the trained ML model and generates predictions.

Supports:
- Decision Tree
- Random Forest
- Support Vector Machine (SVM)
"""

from pathlib import Path

from detection.confidence_calculator import (
    calculate_confidence,
)

from ml.models import (
    decision_tree_model,
    random_forest_model,
    svm_model,
)


ARTIFACT_DIR = Path("ml/artifacts")


def load_selected_model(
    model_name="random_forest",
):
    """
    Load the selected trained model.

    This function adapts to each model's loading API without
    requiring any changes to the individual model modules.
    """

    model_name = model_name.lower()

    if model_name == "decision_tree":

        return decision_tree_model.load_model()

    elif model_name == "random_forest":

        return (
            random_forest_model
            .RandomForestModel
            .load(
                ARTIFACT_DIR
                / "random_forest_model.pkl"
            )
        )

    elif model_name == "svm":

        return svm_model.load_model()

    raise ValueError(
        f"Unsupported model: {model_name}"
    )


class PredictionService:

    def __init__(
        self,
        model_name="random_forest",
    ):

        self.model = load_selected_model(
            model_name
        )

    def predict(
        self,
        features,
    ):

        prediction = (
            self.model
            .predict(features)[0]
        )

        confidence = (
            calculate_confidence(
                self.model,
                features,
            )
        )

        return (
            prediction,
            confidence,
        )