"""
svm_model.py

Reusable Support Vector Machine (SVM) model for the
Network Threat Cognition Framework (NTCF).

This module provides functionality to train,
evaluate, save, and load an SVM classifier.
"""

from pathlib import Path

import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
)
from sklearn.svm import SVC

from ml.config.columns import TARGET_COLUMN


def load_processed_data(
    train_path="data/processed/train_processed.csv",
    test_path="data/processed/test_processed.csv",
):
    """
    Load processed training and testing datasets.

    Parameters
    ----------
    train_path : str
        Path to processed training dataset.

    test_path : str
        Path to processed testing dataset.

    Returns
    -------
    tuple
        X_train, X_test, y_train, y_test
    """

    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    X_train = train_df.drop(columns=[TARGET_COLUMN])
    y_train = train_df[TARGET_COLUMN]

    X_test = test_df.drop(columns=[TARGET_COLUMN])
    y_test = test_df[TARGET_COLUMN]

    return X_train, X_test, y_train, y_test


def create_model(
    kernel="rbf",
    C=1.0,
    gamma="scale",
):
    """
    Create an SVM classifier.

    Parameters
    ----------
    kernel : str
        Kernel type.

    C : float
        Regularization parameter.

    gamma : str
        Kernel coefficient.

    Returns
    -------
    SVC
        Configured SVM classifier.
    """

    model = SVC(
        kernel=kernel,
        C=C,
        gamma=gamma,
    )

    return model


def train_model(
    model,
    X_train,
    y_train,
):
    """
    Train the SVM model.

    Parameters
    ----------
    model : SVC

    X_train : pandas.DataFrame

    y_train : pandas.Series

    Returns
    -------
    SVC
        Trained model.
    """

    model.fit(
        X_train,
        y_train,
    )

    return model


def predict(
    model,
    X_test,
):
    """
    Generate predictions.

    Parameters
    ----------
    model : SVC

    X_test : pandas.DataFrame

    Returns
    -------
    pandas.Series
        Predicted labels.
    """

    predictions = model.predict(X_test)

    return predictions


def evaluate_model(
    y_test,
    predictions,
):
    """
    Evaluate the trained model.

    Parameters
    ----------
    y_test : pandas.Series

    predictions : pandas.Series

    Returns
    -------
    dict
        Model evaluation metrics.
    """

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    report = classification_report(
        y_test,
        predictions,
        output_dict=True,
        zero_division=0,
    )

    return {
        "accuracy": accuracy,
        "classification_report": report,
    }


def save_model(
    model,
    file_path="ml/artifacts/svm_model.pkl",
):
    """
    Save trained SVM model.

    Parameters
    ----------
    model : SVC

    file_path : str
        Destination path.
    """

    path = Path(file_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(
        model,
        path,
    )


def load_model(
    file_path="ml/artifacts/svm_model.pkl",
):
    """
    Load trained SVM model.

    Parameters
    ----------
    file_path : str

    Returns
    -------
    SVC
        Loaded model.
    """

    return joblib.load(file_path)


if __name__ == "__main__":

    X_train, X_test, y_train, y_test = load_processed_data()

    model = create_model()

    model = train_model(
        model,
        X_train,
        y_train,
    )

    predictions = predict(
        model,
        X_test,
    )

    results = evaluate_model(
        y_test,
        predictions,
    )

    print(f"Accuracy: {results['accuracy']:.4f}")

    save_model(model)

    print("SVM model saved successfully.")