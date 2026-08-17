"""
test_attack_samples.py

Loads labelled NSL-KDD test samples for controlled NTCF testing.

This module does NOT capture or generate network traffic.
It only provides existing NSL-KDD test samples to the
NTCF inference pipeline.

Supported categories:
    - R2L
    - U2R
"""

from pathlib import Path

import pandas as pd

from ml.config.columns import (
    ALL_COLUMNS,
    FEATURE_COLUMNS,
)


# ---------------------------------------------------------------------
# Dataset location
# ---------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "KDDTest+.txt"
)


# ---------------------------------------------------------------------
# NSL-KDD attack categories
# ---------------------------------------------------------------------

R2L_ATTACKS = {
    "guess_passwd",
    "ftp_write",
    "imap",
    "phf",
    "multihop",
    "warezmaster",
    "warezclient",
    "spy",
}

U2R_ATTACKS = {
    "buffer_overflow",
    "loadmodule",
    "perl",
    "rootkit",
}


def load_test_dataset():
    """
    Load the NSL-KDD test dataset.

    Returns
    -------
    pandas.DataFrame
        Complete KDDTest+ dataset with labels.
    """

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"NSL-KDD test dataset not found: {DATASET_PATH}"
        )

    dataframe = pd.read_csv(
        DATASET_PATH,
        header=None,
    )

    if dataframe.shape[1] != len(ALL_COLUMNS):
        raise ValueError(
            "Unexpected KDDTest+ column count. "
            f"Expected {len(ALL_COLUMNS)}, "
            f"found {dataframe.shape[1]}."
        )

    dataframe.columns = ALL_COLUMNS

    # NSL-KDD labels may contain a trailing period.
    dataframe["label"] = (
        dataframe["label"]
        .astype(str)
        .str.strip()
        .str.rstrip(".")
    )

    return dataframe


def get_attack_category(label):
    """
    Map an individual NSL-KDD attack label to its
    broad attack category.

    Returns
    -------
    str
        R2L, U2R, or OTHER.
    """

    label = str(label).strip().rstrip(".")

    if label in R2L_ATTACKS:
        return "R2L"

    if label in U2R_ATTACKS:
        return "U2R"

    return "OTHER"


def get_test_samples(
    category=None,
    limit=None,
    shuffle=False,
    random_state=42,
):
    """
    Return selected NSL-KDD test samples.

    Parameters
    ----------
    category : str or None
        "R2L", "U2R", or None.

    limit : int or None
        Maximum number of samples to return.

    shuffle : bool
        Whether to shuffle selected samples.

    random_state : int
        Random seed used when shuffle=True.

    Returns
    -------
    list of dict
        Each item contains:
            source
            attack
            category
            features
    """

    dataframe = load_test_dataset()

    if category is not None:
        category = category.upper()

        if category not in {"R2L", "U2R"}:
            raise ValueError(
                "category must be 'R2L', 'U2R', or None."
            )

        dataframe = dataframe[
            dataframe["label"].apply(
                get_attack_category
            )
            == category
        ]

    if shuffle:
        dataframe = dataframe.sample(
            frac=1,
            random_state=random_state,
        )

    if limit is not None:
        if limit <= 0:
            raise ValueError(
                "limit must be greater than zero."
            )

        dataframe = dataframe.head(limit)

    samples = []

    for _, row in dataframe.iterrows():

        features = {
            column: row[column]
            for column in FEATURE_COLUMNS
        }

        attack = str(row["label"])

        samples.append(
            {
                "source": "TEST",
                "attack": attack,
                "category": get_attack_category(
                    attack
                ),
                "features": features,
            }
        )

    return samples


def get_r2l_samples(limit=10):
    """
    Convenience function for R2L testing.
    """

    return get_test_samples(
        category="R2L",
        limit=limit,
        shuffle=True,
    )


def get_u2r_samples(limit=10):
    """
    Convenience function for U2R testing.
    """

    return get_test_samples(
        category="U2R",
        limit=limit,
        shuffle=True,
    )


# ---------------------------------------------------------------------
# Manual execution
# ---------------------------------------------------------------------

if __name__ == "__main__":

    print("\nLoading NSL-KDD test samples...\n")

    r2l_samples = get_r2l_samples(
        limit=5
    )

    u2r_samples = get_u2r_samples(
        limit=5
    )

    print(
        f"R2L samples selected: {len(r2l_samples)}"
    )

    for sample in r2l_samples:
        print(
            f"TEST | R2L | {sample['attack']}"
        )

    print(
        f"\nU2R samples selected: {len(u2r_samples)}"
    )

    for sample in u2r_samples:
        print(
            f"TEST | U2R | {sample['attack']}"
        )

    print("\nTest sample loading complete.")