"""
confidence_calculator.py

Calculates confidence scores for NTCF predictions.

Supports:
- Decision Tree
- Random Forest
- Support Vector Machine (SVM)

Falls back to a confidence of 1.0 if the model
does not expose probability estimates.
"""

import numpy as np


def calculate_confidence(
    model,
    features,
):
    """
    Return prediction confidence for any supported model.

    Parameters
    ----------
    model
        Trained machine learning model.

    features
        Preprocessed feature vector.

    Returns
    -------
    float
        Confidence score between 0 and 1.
    """

    try:

        if hasattr(
            model,
            "predict_proba",
        ):

            probabilities = (
                model.predict_proba(
                    features
                )
            )

            return float(
                np.max(
                    probabilities
                )
            )

        elif hasattr(
            model,
            "decision_function",
        ):

            scores = (
                model.decision_function(
                    features
                )
            )

            scores = np.atleast_1d(
                scores
            )

            scores = np.exp(scores - np.max(scores))

            probabilities = (
                scores
                / np.sum(scores)
            )

            return float(
                np.max(
                    probabilities
                )
            )

        return 1.0

    except Exception:

        return 1.0