"""
confidence_calculator.py

Calculates confidence scores for NTCF predictions.
"""

import numpy as np


def calculate_confidence(model, features):
    """
    Return prediction confidence.

    If the model supports probability prediction,
    return the maximum probability.
    """

    if hasattr(model, "predict_proba"):

        probabilities = model.predict_proba(features)

        return float(
            np.max(probabilities)
        )

    return 1.0