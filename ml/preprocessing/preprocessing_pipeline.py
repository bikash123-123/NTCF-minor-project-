"""
Complete preprocessing pipeline for the NTCF project.
"""

from pathlib import Path

from ml.preprocessing.data_loader import load_dataset
from ml.preprocessing.cleaner import (
    remove_missing_values,
    remove_duplicates,
    handle_invalid_values,
    standardize_text,
    split_features_target,
    save_processed_data
)
def preprocess_dataset(file_path=None, save_output=False):
    """
    Load and preprocess the NSL-KDD dataset.

    Parameters
    ----------
    file_path : str or Path, optional
        Path to dataset file.
    save_output : bool, default=False
        Save cleaned dataset to data/processed/.

    Returns
    -------
    tuple
        X, y, cleaned_df
    """

    # 1. Load dataset
    df = load_dataset(file_path)

    # 2. Remove missing values
    df = remove_missing_values(df)

    # 3. Remove duplicates
    df = remove_duplicates(df)

    # 4. Remove invalid values
    df = handle_invalid_values(df)

    # 5. Standardize text columns
    df = standardize_text(df)

    # 6. Save cleaned dataset if requested
    if save_output:
        output_dir = Path("data/processed")
        output_dir.mkdir(parents=True, exist_ok=True)

        save_processed_data(
            df,
            output_dir / "cleaned_dataset.csv"
        )

    # 7. Separate features and target
    X, y = split_features_target(df)

    return X, y, df