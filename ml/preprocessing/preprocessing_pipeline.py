"""
Complete preprocessing pipeline for the Network Threat Cognition Framework (NTCF).
"""

from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

from ml.preprocessing.data_loader import load_dataset
from ml.preprocessing.cleaner import (
    remove_missing_values,
    remove_duplicates,
    handle_invalid_values,
    standardize_text,
    split_features_target,
    save_processed_data,
)
from ml.preprocessing.encoder import (
    fit_encoder,
    transform_features as encode_features,
    save_encoder,
)
from ml.preprocessing.scaler import (
    fit_scaler,
    transform_features as scale_features,
    save_scaler,
)
from ml.config.columns import (
    CATEGORICAL_COLUMNS,
    NUMERICAL_COLUMNS,
)


def preprocess_dataset(
    file_path=None,
    test_size=0.2,
    random_state=42,
    save_output=False,
):
    """
    Execute the complete preprocessing pipeline.

    Parameters
    ----------
    file_path : str or Path, optional
        Dataset path.

    test_size : float
        Fraction of data reserved for testing.

    random_state : int
        Fixed seed for reproducibility.

    save_output : bool
        Save cleaned dataset if True.

    Returns
    -------
    tuple
        (
            X_train,
            X_test,
            y_train,
            y_test,
            encoder,
            scaler
        )
    """

    # -------------------------------------------------
    # Load dataset
    # -------------------------------------------------

    df = load_dataset(file_path)

    # -------------------------------------------------
    # Cleaning
    # -------------------------------------------------

    df = remove_missing_values(df)
    df = remove_duplicates(df)
    df = handle_invalid_values(df)
    df = standardize_text(df)

    if save_output:
        output_dir = Path("data/processed")
        output_dir.mkdir(parents=True, exist_ok=True)

        save_processed_data(
            df,
            output_dir / "cleaned_dataset.csv",
        )

    # -------------------------------------------------
    # Separate features and target
    # -------------------------------------------------

    X, y = split_features_target(df)

    # -------------------------------------------------
    # Train/Test Split
    # -------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        shuffle=True,
    )

    # -------------------------------------------------
    # Encoder
    # Fit ONLY on training data
    # -------------------------------------------------

    encoder = fit_encoder(X_train)

    X_train_encoded = encode_features(
        encoder,
        X_train,
    )

    X_test_encoded = encode_features(
        encoder,
        X_test,
    )

    save_encoder(encoder)

    # -------------------------------------------------
    # Scaler
    # Fit ONLY on training data
    # -------------------------------------------------

    scaler = fit_scaler(X_train)

    X_train_scaled = scale_features(
        scaler,
        X_train,
    )

    X_test_scaled = scale_features(
        scaler,
        X_test,
    )

    save_scaler(scaler)

    # -------------------------------------------------
    # Combine encoded + scaled features
    # -------------------------------------------------

    X_train_final = pd.concat(
        [
            X_train_scaled.reset_index(drop=True),
            X_train_encoded.reset_index(drop=True),
        ],
        axis=1,
    )

    X_test_final = pd.concat(
        [
            X_test_scaled.reset_index(drop=True),
            X_test_encoded.reset_index(drop=True),
        ],
        axis=1,
    )

    return (
        X_train_final,
        X_test_final,
        y_train.reset_index(drop=True),
        y_test.reset_index(drop=True),
        encoder,
        scaler,
    )