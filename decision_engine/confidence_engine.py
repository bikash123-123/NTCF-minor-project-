"""
confidence_engine.py

Evaluate prediction confidence and assign confidence levels
for the Network Threat Cognition Framework (NTCF).
"""


HIGH_CONFIDENCE_THRESHOLD = 0.90
MEDIUM_CONFIDENCE_THRESHOLD = 0.70


def evaluate_confidence(confidence_score):
    """
    Evaluate prediction confidence.

    Parameters
    ----------
    confidence_score : float
        Model confidence score.

    Returns
    -------
    str
        Confidence level.
    """

    if confidence_score >= HIGH_CONFIDENCE_THRESHOLD:
        return "high"

    if confidence_score >= MEDIUM_CONFIDENCE_THRESHOLD:
        return "medium"

    return "low"


def process_prediction(prediction, confidence_score):
    """
    Process a prediction and confidence score.

    Parameters
    ----------
    prediction : str
        Predicted class.

    confidence_score : float
        Prediction confidence.

    Returns
    -------
    dict
        Prediction information.
    """

    return {
        "prediction": prediction,
        "confidence_score": confidence_score,
        "confidence_level": evaluate_confidence(confidence_score),
    }