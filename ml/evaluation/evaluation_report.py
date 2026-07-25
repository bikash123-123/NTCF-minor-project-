"""
evaluation_report.py

Utility functions for generating classification reports
and complete evaluation summaries.

This module is shared by all machine learning models
used in the Network Threat Cognition Framework (NTCF).
"""

from sklearn.metrics import classification_report

from ml.evaluation.metrics import calculate_all_metrics


def generate_classification_report(y_true, y_pred):
    """
    Generate a classification report.

    Parameters
    ----------
    y_true : array-like
        Ground truth labels.

    y_pred : array-like
        Predicted labels.

    Returns
    -------
    str
        Classification report.
    """

    return classification_report(
        y_true,
        y_pred,
        zero_division=0,
    )


def generate_evaluation_report(y_true, y_pred):
    """
    Generate a complete evaluation report.

    Returns
    -------
    dict
        Metrics and classification report.
    """

    metrics = calculate_all_metrics(
        y_true,
        y_pred,
    )

    report = generate_classification_report(
        y_true,
        y_pred,
    )

    return {
        "metrics": metrics,
        "classification_report": report,
    }


if __name__ == "__main__":

    y_true = [
        "Normal",
        "DoS",
        "Probe",
        "Normal"
    ]

    y_pred = [
        "Normal",
        "DoS",
        "Normal",
        "Normal"
    ]

    results = generate_evaluation_report(
        y_true,
        y_pred,
    )

    print("\nEvaluation Metrics\n")

    for metric, value in results["metrics"].items():
        print(f"{metric}: {value:.4f}")

    print("\nClassification Report\n")

    print(results["classification_report"])