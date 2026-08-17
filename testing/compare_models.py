"""
compare_models.py

Compare NTCF ML models with special focus on R2L detection.

This is an evaluation-only script.
It does NOT modify:
    - packet capture
    - preprocessing
    - APIs
    - existing model artifacts

Models evaluated:
    1. Existing Decision Tree
    2. Balanced Decision Tree
    3. Existing Random Forest
    4. Balanced Random Forest
    5. Linear SVM with balanced class weights

The main selection metric is R2L recall.
"""

from pathlib import Path

import pandas as pd

from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    balanced_accuracy_score,
)


# ---------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[1]

TRAIN_DATA = (
    BASE_DIR
    / "data"
    / "processed"
    / "train_processed.csv"
)

TEST_DATA = (
    BASE_DIR
    / "data"
    / "processed"
    / "test_processed.csv"
)


# ---------------------------------------------------------------------
# R2L attack classes in NSL-KDD
# ---------------------------------------------------------------------

R2L_CLASSES = {
    "guess_passwd",
    "ftp_write",
    "imap",
    "phf",
    "multihop",
    "warezmaster",
    "warezclient",
    "spy",
}


# ---------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------

def load_data():

    print("\nLoading processed datasets...")

    train_df = pd.read_csv(TRAIN_DATA)
    test_df = pd.read_csv(TEST_DATA)

    X_train = train_df.drop(
        columns=["label"]
    )

    y_train = train_df["label"]

    X_test = test_df.drop(
        columns=["label"]
    )

    y_test = test_df["label"]

    print(
        f"Training samples: {len(train_df)}"
    )

    print(
        f"Testing samples:  {len(test_df)}"
    )

    return (
        X_train,
        X_test,
        y_train,
        y_test,
    )


# ---------------------------------------------------------------------
# Convert multiclass predictions to R2L / NOT-R2L
# ---------------------------------------------------------------------

def convert_to_r2l(labels):

    return [
        "R2L"
        if label in R2L_CLASSES
        else "NOT_R2L"
        for label in labels
    ]


# ---------------------------------------------------------------------
# Evaluate model
# ---------------------------------------------------------------------

def evaluate_model(
    model_name,
    model,
    X_train,
    X_test,
    y_train,
    y_test,
):

    print("\n" + "=" * 72)

    print(
        f"TRAINING: {model_name}"
    )

    print("=" * 72)

    model.fit(
        X_train,
        y_train,
    )

    print("Training complete.")

    predictions = model.predict(
        X_test
    )

    # -------------------------------------------------------------
    # Overall accuracy
    # -------------------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    # -------------------------------------------------------------
    # R2L category evaluation
    # -------------------------------------------------------------

    actual_r2l = convert_to_r2l(
        y_test
    )

    predicted_r2l = convert_to_r2l(
        predictions
    )

    r2l_precision = precision_score(
        actual_r2l,
        predicted_r2l,
        pos_label="R2L",
        zero_division=0,
    )

    r2l_recall = recall_score(
        actual_r2l,
        predicted_r2l,
        pos_label="R2L",
        zero_division=0,
    )

    r2l_f1 = f1_score(
        actual_r2l,
        predicted_r2l,
        pos_label="R2L",
        zero_division=0,
    )

    balanced_accuracy = (
        balanced_accuracy_score(
            actual_r2l,
            predicted_r2l,
        )
    )

    # -------------------------------------------------------------
    # Exact R2L class accuracy
    # -------------------------------------------------------------

    r2l_mask = y_test.isin(
        R2L_CLASSES
    )

    r2l_test_actual = y_test[
        r2l_mask
    ]

    r2l_test_predicted = (
        pd.Series(
            predictions,
            index=y_test.index,
        )[r2l_mask]
    )

    if len(r2l_test_actual) > 0:

        exact_r2l_accuracy = (
            accuracy_score(
                r2l_test_actual,
                r2l_test_predicted,
            )
        )

    else:

        exact_r2l_accuracy = 0.0

    # -------------------------------------------------------------
    # Results
    # -------------------------------------------------------------

    print(
        f"\nOverall accuracy: "
        f"{accuracy:.4f}"
    )

    print(
        f"R2L precision:     "
        f"{r2l_precision:.4f}"
    )

    print(
        f"R2L recall:        "
        f"{r2l_recall:.4f}"
    )

    print(
        f"R2L F1:            "
        f"{r2l_f1:.4f}"
    )

    print(
        f"R2L balanced acc.:  "
        f"{balanced_accuracy:.4f}"
    )

    print(
        f"R2L exact accuracy:"
        f" {exact_r2l_accuracy:.4f}"
    )

    return {
        "model": model_name,
        "accuracy": accuracy,
        "r2l_precision": r2l_precision,
        "r2l_recall": r2l_recall,
        "r2l_f1": r2l_f1,
        "r2l_balanced_accuracy":
            balanced_accuracy,
        "r2l_exact_accuracy":
            exact_r2l_accuracy,
    }


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():

    print("\n")
    print("=" * 72)
    print("NTCF MODEL COMPARISON - R2L FOCUS")
    print("=" * 72)

    print(
        "\nIMPORTANT:"
    )

    print(
        "This evaluation does NOT modify existing "
        "model artifacts."
    )

    print(
        "Models are trained temporarily in memory."
    )

    (
        X_train,
        X_test,
        y_train,
        y_test,
    ) = load_data()

    results = []

    # =============================================================
    # 1. Existing Decision Tree
    # =============================================================

    existing_dt = DecisionTreeClassifier(
        criterion="gini",
        max_depth=20,
        min_samples_split=2,
        random_state=42,
    )

    results.append(
        evaluate_model(
            "Decision Tree",
            existing_dt,
            X_train,
            X_test,
            y_train,
            y_test,
        )
    )

    # =============================================================
    # 2. Balanced Decision Tree
    # =============================================================

    balanced_dt = DecisionTreeClassifier(
        criterion="gini",
        max_depth=20,
        min_samples_split=2,
        class_weight="balanced",
        random_state=42,
    )

    results.append(
        evaluate_model(
            "Balanced Decision Tree",
            balanced_dt,
            X_train,
            X_test,
            y_train,
            y_test,
        )
    )

    # =============================================================
    # 3. Random Forest
    # =============================================================

    random_forest = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
    )

    results.append(
        evaluate_model(
            "Random Forest",
            random_forest,
            X_train,
            X_test,
            y_train,
            y_test,
        )
    )

    # =============================================================
    # 4. Balanced Random Forest
    # =============================================================

    balanced_random_forest = (
        RandomForestClassifier(
            n_estimators=100,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
    )

    results.append(
        evaluate_model(
            "Balanced Random Forest",
            balanced_random_forest,
            X_train,
            X_test,
            y_train,
            y_test,
        )
    )

    # =============================================================
    # 5. Balanced Linear SVM
    # =============================================================

    linear_svm = LinearSVC(
        C=1.0,
        class_weight="balanced",
        random_state=42,
        max_iter=5000,
    )

    results.append(
        evaluate_model(
            "Balanced Linear SVM",
            linear_svm,
            X_train,
            X_test,
            y_train,
            y_test,
        )
    )

    # =============================================================
    # Comparison
    # =============================================================

    results_df = pd.DataFrame(
        results
    )

    print("\n")
    print("=" * 72)
    print("MODEL COMPARISON")
    print("=" * 72)

    display_df = results_df.copy()

    for column in display_df.columns:

        if column != "model":

            display_df[column] = (
                display_df[column]
                .map(
                    lambda value:
                    f"{value:.4f}"
                )
            )

    print(
        display_df.to_string(
            index=False
        )
    )

    # =============================================================
    # Best model by R2L recall
    # =============================================================

    best_r2l = results_df.loc[
        results_df[
            "r2l_recall"
        ].idxmax()
    ]

    print("\n")
    print("=" * 72)
    print("BEST MODEL FOR R2L RECALL")
    print("=" * 72)

    print(
        f"Model: "
        f"{best_r2l['model']}"
    )

    print(
        f"R2L recall: "
        f"{best_r2l['r2l_recall']:.4f}"
    )

    print(
        f"R2L F1: "
        f"{best_r2l['r2l_f1']:.4f}"
    )

    print(
        f"Overall accuracy: "
        f"{best_r2l['accuracy']:.4f}"
    )

    # =============================================================
    # Save comparison results
    # =============================================================

    output_path = (
        BASE_DIR
        / "testing"
        / "model_comparison_results.csv"
    )

    results_df.to_csv(
        output_path,
        index=False,
    )

    print("\n")
    print(
        "Results saved to:"
    )

    print(output_path)

    print("\n")
    print("=" * 72)
    print("COMPARISON COMPLETE")
    print("=" * 72)


if __name__ == "__main__":

    main()