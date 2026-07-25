"""
data_loader.py

Reusable dataset loading module for the Network Threat Cognition Framework (NTCF).

This module provides functionality to safely load the NSL-KDD dataset
without modifying the original raw data.
"""

from pathlib import Path

import pandas as pd

from ml.config.columns import ALL_COLUMNS


def load_dataset(file_path=None):
    """
    Load an NSL-KDD dataset.

    Parameters
    ----------
    file_path : str or Path, optional
        Path to the dataset file.
        If None, the default training dataset
        (data/raw/KDDTrain+.txt) is loaded.

    Returns
    -------
    pandas.DataFrame
        Loaded dataset.

    Raises
    ------
    ValueError
        If the dataset path is empty or invalid.

    FileNotFoundError
        If the dataset file does not exist.

    RuntimeError
        If an unexpected error occurs while loading the dataset.
    """

    # Load the default training dataset if no path is provided
    if file_path is None:
        project_root = Path(__file__).resolve().parents[2]
        file_path = project_root / "data" / "raw" / "KDDTrain+.txt"

    if not file_path:
        raise ValueError("Dataset path cannot be empty.")

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    if not path.is_file():
        raise ValueError(f"'{path}' is not a valid dataset file.")

    try:
        dataset = pd.read_csv(
            path,
            header=None,
            names=ALL_COLUMNS
        )

        return dataset

    except Exception as error:
        raise RuntimeError(
            f"Failed to load dataset: {error}"
        ) from error