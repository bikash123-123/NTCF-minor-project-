"""
data_loader.py

Reusable dataset loading module for the Network Threat Cognition Framework (NTCF).

This module provides functionality to safely load the NSL-KDD dataset
without modifying the original raw data.
"""

from pathlib import Path
import pandas as pd


# Column names for the NSL-KDD dataset
COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty"
]


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
        file_path = Path("data/raw/KDDTrain+.txt")

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
            names=COLUMN_NAMES
        )

        return dataset

    except Exception as error:
        raise RuntimeError(
            f"Failed to load dataset: {error}"
        ) from error