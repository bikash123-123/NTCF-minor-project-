"""
encoder.py

Reusable categorical feature encoding module for the
Network Threat Cognition Framework (NTCF).

This module provides functionality for encoding categorical
features into numerical representations suitable for machine
learning models.
"""
from pathlib import Path

import joblib
import pandas as pd

from sklearn.preprocessing import OneHotEncoder

from ml.config.columns import CATEGORICAL_COLUMNS

def create_encoder():
    """
    Create a OneHotEncoder configured for the NTCF dataset.

    Returns
    -------
    OneHotEncoder
        Configured encoder.
    """

    encoder = OneHotEncoder(
        handle_unknown="ignore",
        sparse_output=False
    )

    return encoder
def fit_encoder(dataframe):
    """
    Fit the encoder using the training dataset.

    Parameters
    ----------
    dataframe : pandas.DataFrame

    Returns
    -------
    OneHotEncoder
        Fitted encoder.
    """

    encoder = create_encoder()

    encoder.fit(dataframe[CATEGORICAL_COLUMNS])

    return encoder
def transform_features(encoder, dataframe):
    """
    Transform categorical features using a fitted encoder.

    Parameters
    ----------
    encoder : OneHotEncoder

    dataframe : pandas.DataFrame

    Returns
    -------
    pandas.DataFrame
        Encoded categorical features.
    """

    encoded = encoder.transform(
        dataframe[CATEGORICAL_COLUMNS]
    )

    feature_names = encoder.get_feature_names_out(
        CATEGORICAL_COLUMNS
    )

    encoded_df = pd.DataFrame(
        encoded,
        columns=feature_names,
        index=dataframe.index
    )

    return encoded_df
def save_encoder(
    encoder,
    file_path="ml/artifacts/encoder.pkl"
):
    """
    Save a fitted encoder to disk.
    """

    path = Path(file_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    joblib.dump(
        encoder,
        path
    )
def load_encoder(
    file_path="ml/artifacts/encoder.pkl"
):
    """
    Load a previously saved encoder.
    """

    return joblib.load(file_path)
