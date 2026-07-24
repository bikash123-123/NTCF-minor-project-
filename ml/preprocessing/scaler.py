"""
scaler.py

Reusable feature scaling module for the
Network Threat Cognition Framework (NTCF).
"""

from pathlib import Path

import joblib
import pandas as pd

from sklearn.preprocessing import StandardScaler

from ml.config.columns import NUMERICAL_COLUMNS


def create_scaler():
    """
    Create a StandardScaler.

    Returns
    -------
    StandardScaler
    """

    return StandardScaler()


def fit_scaler(dataframe):
    """
    Fit scaler using training data.
    """

    scaler = create_scaler()

    scaler.fit(
        dataframe[NUMERICAL_COLUMNS]
    )

    return scaler


def transform_features(
    scaler,
    dataframe
):
    """
    Scale numerical features.
    """

    scaled = scaler.transform(
        dataframe[NUMERICAL_COLUMNS]
    )

    scaled_df = pd.DataFrame(
        scaled,
        columns=NUMERICAL_COLUMNS,
        index=dataframe.index
    )

    return scaled_df


def save_scaler(
    scaler,
    file_path="ml/artifacts/scaler.pkl"
):
    """
    Save fitted scaler.
    """

    path = Path(file_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    joblib.dump(
        scaler,
        path
    )


def load_scaler(
    file_path="ml/artifacts/scaler.pkl"
):
    """
    Load fitted scaler.
    """

    return joblib.load(file_path)