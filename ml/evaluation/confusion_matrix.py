"""
confusion_matrix.py

Utility functions for generating confusion matrices.

This module provides reusable confusion matrix utilities
for evaluating machine learning models in the Network
Threat Cognition Framework (NTCF).
"""

import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay


def generate_confusion_matrix(y_true, y_pred):
    """
    Generate a confusion matrix.

    Parameters
    ----------
    y_true : array-like
        Ground truth labels.

    y_pred : array-like
        Predicted labels.

    Returns
    -------
    ndarray
        Confusion matrix.
    """

    return confusion_matrix(
        y_true,
        y_pred
    )


def plot_confusion_matrix(y_true, y_pred):
    """
    Display a confusion matrix plot.
    """

    matrix = confusion_matrix(
        y_true,
        y_pred
    )

    display = ConfusionMatrixDisplay(
        confusion_matrix=matrix
    )

    display.plot(
        cmap="Blues"
    )

    plt.title("Confusion Matrix")
    plt.show()


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

    matrix = generate_confusion_matrix(
        y_true,
        y_pred
    )

    print(matrix)

    plot_confusion_matrix(
        y_true,
        y_pred
    )