"""
model_comparison.py

Compare the three machine-learning models used by NTCF:

- Decision Tree
- Random Forest
- Support Vector Machine (SVM)

All models are evaluated on the same processed test dataset
using the same evaluation metrics.
"""

from __future__ import annotations

import time
from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
)

from ml.models import (
    decision_tree_model,
    random_forest_model,
    svm_model,
)

from ml.training.save_models import (
    load_trained_model,
)


# ---------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------

BASE_DIR = Path(
    __file__
).resolve().parents[2]

TEST_DATA = (
    BASE_DIR
    / "data"
    / "processed"
    / "test_processed.csv"
)


TARGET_COLUMN = "label"


# ---------------------------------------------------------------------
# Load Test Data
# ---------------------------------------------------------------------

def load_test_data(
    test_path=TEST_DATA,
):
    """
    Load the processed test dataset.

    Returns
    -------
    tuple
        X_test, y_test
    """

    test_df = pd.read_csv(
        test_path
    )

    X_test = test_df.drop(
        columns=[
            TARGET_COLUMN
        ]
    )

    y_test = test_df[
        TARGET_COLUMN
    ]

    return X_test, y_test


# ---------------------------------------------------------------------
# Load Trained Models
# ---------------------------------------------------------------------

def load_models():
    """
    Load all three trained NTCF models.

    Returns
    -------
    dict
        Mapping of model names to trained models.
    """

    models = {

        "Decision Tree": (
            load_trained_model(
                module=decision_tree_model,
                model_name="decision_tree",
            )
        ),

        "Random Forest": (
            load_trained_model(
                module=random_forest_model,
                model_name="random_forest",
            )
        ),

        "SVM": (
            load_trained_model(
                module=svm_model,
                model_name="svm",
            )
        ),

    }

    return models


# ---------------------------------------------------------------------
# Evaluate One Model
# ---------------------------------------------------------------------

def evaluate_model(
    model,
    model_name,
    X_test,
    y_test,
):
    """
    Evaluate one trained model.

    All models use the same test data and
    the same evaluation methodology.
    """

    start_time = time.perf_counter()

    predictions = model.predict(
        X_test
    )

    prediction_time = (
        time.perf_counter()
        - start_time
    )

    return {

        "model": model_name,

        "accuracy": accuracy_score(
            y_test,
            predictions,
        ),

        "precision": precision_score(
            y_test,
            predictions,
            average="weighted",
            zero_division=0,
        ),

        "recall": recall_score(
            y_test,
            predictions,
            average="weighted",
            zero_division=0,
        ),

        "f1_score": f1_score(
            y_test,
            predictions,
            average="weighted",
            zero_division=0,
        ),

        "prediction_time_seconds": (
            prediction_time
        ),

    }


# ---------------------------------------------------------------------
# Compare All Models
# ---------------------------------------------------------------------

def compare_models(
    models,
    X_test,
    y_test,
):
    """
    Compare Decision Tree, Random Forest,
    and SVM.

    Returns
    -------
    pandas.DataFrame
        Comparison results.
    """

    required_models = {

        "Decision Tree",

        "Random Forest",

        "SVM",

    }

    if set(
        models.keys()
    ) != required_models:

        raise ValueError(
            "Models must contain exactly: "
            "Decision Tree, Random Forest, and SVM."
        )

    results = []

    for model_name in [

        "Decision Tree",

        "Random Forest",

        "SVM",

    ]:

        result = evaluate_model(

            model=models[
                model_name
            ],

            model_name=model_name,

            X_test=X_test,

            y_test=y_test,

        )

        results.append(
            result
        )

    return pd.DataFrame(
        results
    )


# ---------------------------------------------------------------------
# Identify Best Model
# ---------------------------------------------------------------------

def identify_best_model(
    results,
):
    """
    Identify the best-performing model.

    F1-score is used as the primary selection
    metric because it balances precision and
    recall for threat detection.
    """

    if results.empty:

        raise ValueError(
            "Comparison results are empty."
        )

    best_index = (
        results[
            "f1_score"
        ].idxmax()
    )

    return results.loc[
        best_index
    ]


# ---------------------------------------------------------------------
# Complete Comparison
# ---------------------------------------------------------------------

def run_model_comparison():
    """
    Load models and test data, compare all models,
    and identify the best-performing model.
    """

    models = load_models()

    X_test, y_test = (
        load_test_data()
    )

    results = compare_models(

        models=models,

        X_test=X_test,

        y_test=y_test,

    )

    best_model = (
        identify_best_model(
            results
        )
    )

    return results, best_model


# ---------------------------------------------------------------------
# Script Execution
# ---------------------------------------------------------------------

if __name__ == "__main__":

    results, best_model = (
        run_model_comparison()
    )

    print(
        "\nModel Comparison Results:"
    )

    print(
        results.to_string(
            index=False
        )
    )

    print(
        "\nBest Performing Model:"
    )

    print(
        best_model[
            "model"
        ]
    )

    print(
        f"F1-score: "
        f"{best_model['f1_score']:.4f}"
    )