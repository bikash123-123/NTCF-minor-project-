"""
preprocessing_service.py

Prepares raw NTCF feature data for the trained ML model.
"""

from pathlib import Path

import joblib
import pandas as pd

from ml.config.columns import (
    CATEGORICAL_COLUMNS,
    NUMERICAL_COLUMNS,
)


ARTIFACT_DIR = Path("ml/artifacts")

ENCODER_PATH = ARTIFACT_DIR / "encoder.pkl"
SCALER_PATH = ARTIFACT_DIR / "scaler.pkl"


def load_preprocessing_artifacts():
    """
    Load the fitted encoder and scaler used during training.
    """

    encoder = joblib.load(ENCODER_PATH)
    scaler = joblib.load(SCALER_PATH)

    return encoder, scaler


def preprocess_features(features):
    """
    Convert raw NSL-KDD feature data into the
    same 122-feature representation used during training.
    """

    dataframe = pd.DataFrame([features])

    encoder, scaler = load_preprocessing_artifacts()

    required_columns = (
        CATEGORICAL_COLUMNS
        + NUMERICAL_COLUMNS
    )

    missing_columns = [
        column
        for column in required_columns
        if column not in dataframe.columns
    ]

    if missing_columns:
        raise ValueError(
            "Missing required features: "
            + ", ".join(missing_columns)
        )

    encoded = encoder.transform(
        dataframe[CATEGORICAL_COLUMNS]
    )

    encoded_columns = encoder.get_feature_names_out(
        CATEGORICAL_COLUMNS
    )

    encoded_df = pd.DataFrame(
        encoded,
        columns=encoded_columns,
        index=dataframe.index,
    )

    scaled = scaler.transform(
        dataframe[NUMERICAL_COLUMNS]
    )

    scaled_df = pd.DataFrame(
        scaled,
        columns=NUMERICAL_COLUMNS,
        index=dataframe.index,
    )

    result = pd.concat(
        [
            scaled_df,
            encoded_df,
        ],
        axis=1,
    )

    return result