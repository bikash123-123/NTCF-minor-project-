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

import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
)

from ml.models.random_forest_model import RandomForestModel


# ---------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[2]

TEST_DATA = (
    BASE_DIR
    / "data"
    / "processed"
    / "test_processed.csv"
)

ARTIFACT_DIR = (
    BASE_DIR
    / "ml"
    / "artifacts"
)

DECISION_TREE_MODEL = (
    ARTIFACT_DIR
    / "decision_tree_model.pkl"
)

RANDOM_FOREST_MODEL = (
    ARTIFACT_DIR
    / "random_forest_model.pkl"
)

SVM_MODEL = (
    ARTIFACT_DIR
    / "svm_model.pkl"
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

    test_df = pd.read_csv(test_path)

    X_test = test_df.drop(
        columns=[TARGET_COLUMN]
    )

    y_test = test_df[TARGET_COLUMN]

    return X_test, y_test


# ---------------------------------------------------------------------
# Load Trained Models
# ---------------------------------------------------------------------

def load_models():
    """
    Load all three trained NTCF models.

    Decision Tree:
        Loaded using joblib.

    Random Forest:
        Loaded using RandomForestModel.load().

    SVM:
        Loaded using joblib.

    Returns
    -------
    dict
        Mapping of model names to trained models.
    """

    print("Loading trained models...")

    # -------------------------------------------------
    # Decision Tree
    # -------------------------------------------------

    if not DECISION_TREE_MODEL.exists():
        raise FileNotFoundError(
            f"Decision Tree model not found at: "
            f"{DECISION_TREE_MODEL}"
        )

    decision_tree = joblib.load(
        DECISION_TREE_MODEL
    )

    print(
        "Decision Tree loaded successfully."
    )

    # -------------------------------------------------
    # Random Forest
    # -------------------------------------------------

    if not RANDOM_FOREST_MODEL.exists():
        raise FileNotFoundError(
            f"Random Forest model not found at: "
            f"{RANDOM_FOREST_MODEL}"
        )

    random_forest = RandomForestModel.load(
        RANDOM_FOREST_MODEL
    )

    print(
        "Random Forest loaded successfully."
    )

    # -------------------------------------------------
    # SVM
    # -------------------------------------------------

    if not SVM_MODEL.exists():
        raise FileNotFoundError(
            f"SVM model not found at: "
            f"{SVM_MODEL}"
        )

    svm = joblib.load(
        SVM_MODEL
    )

    print(
        "SVM loaded successfully."
    )

    return {
        "Decision Tree": decision_tree,
        "Random Forest": random_forest,
        "SVM": svm,
    }


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

    print(
        f"\nEvaluating {model_name}..."
    )

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

    if set(models.keys()) != required_models:
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
            model=models[model_name],
            model_name=model_name,
            X_test=X_test,
            y_test=y_test,
        )

        results.append(result)

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
        results["f1_score"].idxmax()
    )

    return results.loc[
        best_index
    ]


# ---------------------------------------------------------------------
# Complete Comparison
# ---------------------------------------------------------------------

def run_model_comparison():
    """
    Load models and test data,
    compare all models,
    and identify the best-performing model.
    """

    models = load_models()

    print(
        "\nLoading test dataset..."
    )

    X_test, y_test = (
        load_test_data()
    )

    print(
        f"Test samples: {len(X_test)}"
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

    try:

        results, best_model = (
            run_model_comparison()
        )

        print(
            "\n"
            + "=" * 70
        )

        print(
            "MODEL COMPARISON RESULTS"
        )

        print(
            "=" * 70
        )

        print(
            results.to_string(
                index=False
            )
        )

        print(
            "\n"
            + "=" * 70
        )

        print(
            "BEST PERFORMING MODEL"
        )

        print(
            "=" * 70
        )

        print(
            f"Model: "
            f"{best_model['model']}"
        )

        print(
            f"Accuracy: "
            f"{best_model['accuracy']:.4f}"
        )

        print(
            f"Precision: "
            f"{best_model['precision']:.4f}"
        )

        print(
            f"Recall: "
            f"{best_model['recall']:.4f}"
        )

        print(
            f"F1-score: "
            f"{best_model['f1_score']:.4f}"
        )

        print(
            f"Prediction time: "
            f"{best_model['prediction_time_seconds']:.6f} seconds"
        )

        print(
            "=" * 70
        )

    except FileNotFoundError as error:

        print(
            "\nMODEL OR DATA FILE NOT FOUND:"
        )

        print(error)

    except Exception as error:

        print(
            "\nUNEXPECTED ERROR:"
        )

        print(error)