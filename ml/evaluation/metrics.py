"""
metrics.py

Utility functions for evaluating machine learning models.

This module provides reusable evaluation metrics for
classification models used in the Network Threat Cognition
Framework (NTCF).
"""

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)


def calculate_accuracy(y_true, y_pred):
    """
    Calculate classification accuracy.
    """
    return accuracy_score(y_true, y_pred)


def calculate_precision(y_true, y_pred, average="weighted"):
    """
    Calculate precision score.
    """
    return precision_score(
        y_true,
        y_pred,
        average=average,
        zero_division=0,
    )


def calculate_recall(y_true, y_pred, average="weighted"):
    """
    Calculate recall score.
    """
    return recall_score(
        y_true,
        y_pred,
        average=average,
        zero_division=0,
    )


def calculate_f1_score(y_true, y_pred, average="weighted"):
    """
    Calculate F1-score.
    """
    return f1_score(
        y_true,
        y_pred,
        average=average,
        zero_division=0,
    )


def calculate_all_metrics(y_true, y_pred):
    """
    Calculate all evaluation metrics.

    Returns
    -------
    dict
        Dictionary containing all metrics.
    """

    return {
        "Accuracy": calculate_accuracy(
            y_true,
            y_pred,
        ),
        "Precision": calculate_precision(
            y_true,
            y_pred,
        ),
        "Recall": calculate_recall(
            y_true,
            y_pred,
        ),
        "F1-Score": calculate_f1_score(
            y_true,
            y_pred,
        ),
    }


if __name__ == "__main__":

    y_true = ["Normal", "DoS", "Probe", "Normal"]
    y_pred = ["Normal", "DoS", "Normal", "Normal"]

    metrics = calculate_all_metrics(
        y_true,
        y_pred,
    )

    print(metrics)