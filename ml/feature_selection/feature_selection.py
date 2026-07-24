"""
feature_selection.py

Reusable feature selection module for the
Network Threat Cognition Framework (NTCF).
"""

from pathlib import Path
import json

import pandas as pd

from sklearn.ensemble import RandomForestClassifier


def compute_feature_importance(X, y):
    """
    Train a Random Forest model and compute feature importance.

    Parameters
    ----------
    X : pandas.DataFrame
        Feature matrix.

    y : pandas.Series
        Target labels.

    Returns
    -------
    pandas.DataFrame
        Features sorted by importance.
    """

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    model.fit(X, y)

    importance = pd.DataFrame({
        "feature": X.columns,
        "importance": model.feature_importances_
    })

    importance = importance.sort_values(
        by="importance",
        ascending=False
    )

    importance.reset_index(
        drop=True,
        inplace=True
    )

    return importance


def select_top_features(feature_importance, top_n=20):
    """
    Select the top N most important features.
    """

    return feature_importance.head(top_n)["feature"].tolist()


def save_selected_features(
    features,
    file_path="ml/feature_selection/selected_features.json"
):
    """
    Save selected feature names.
    """

    path = Path(file_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(path, "w") as file:
        json.dump(
            features,
            file,
            indent=4
        )


def load_selected_features(
    file_path="ml/feature_selection/selected_features.json"
):
    """
    Load selected feature names.
    """

    with open(file_path, "r") as file:
        return json.load(file)