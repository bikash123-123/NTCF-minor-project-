"""
evaluate_r2l_u2r.py

Compare the existing Decision Tree with a temporary
class-balanced Decision Tree.

This is an evaluation experiment only.

It does NOT:
- modify packet capture
- modify preprocessing
- modify the existing model artifact
- modify the API
- replace decision_tree_model.pkl

The purpose is to determine whether class balancing
improves R2L/U2R detection.
"""

from pathlib import Path

import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.tree import DecisionTreeClassifier


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

MODEL_PATH = (
    BASE_DIR
    / "ml"
    / "artifacts"
    / "decision_tree_model.pkl"
)

TARGET_COLUMN = "label"


# ---------------------------------------------------------------------
# Attack groups
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


def load_data():
    """Load processed training and testing datasets."""

    train_df = pd.read_csv(TRAIN_DATA)
    test_df = pd.read_csv(TEST_DATA)

    X_train = train_df.drop(
        columns=[TARGET_COLUMN]
    )

    y_train = train_df[TARGET_COLUMN]

    X_test = test_df.drop(
        columns=[TARGET_COLUMN]
    )

    y_test = test_df[TARGET_COLUMN]

    return (
        X_train,
        y_train,
        X_test,
        y_test,
    )


def evaluate_predictions(
    name,
    y_true,
    predictions,
):
    """Print overall and R2L/U2R evaluation metrics."""

    accuracy = accuracy_score(
        y_true,
        predictions,
    )

    print("\n" + "=" * 72)
    print(name)
    print("=" * 72)

    print(
        f"\nOverall accuracy: {accuracy:.4f}"
    )

    # -------------------------------------------------------------
    # R2L / U2R subset
    # -------------------------------------------------------------

    target_labels = sorted(
        R2L_ATTACKS | U2R_ATTACKS
    )

    mask = y_true.isin(
        target_labels
    )

    y_attack = y_true[mask]
    p_attack = pd.Series(
        predictions,
        index=y_true.index,
    )[mask]

    if len(y_attack) == 0:

        print(
            "\nNo R2L/U2R samples found."
        )

        return

    print(
        f"\nR2L/U2R test samples: "
        f"{len(y_attack)}"
    )

    attack_accuracy = accuracy_score(
        y_attack,
        p_attack,
    )

    print(
        f"R2L/U2R exact-class accuracy: "
        f"{attack_accuracy:.4f}"
    )

    # -------------------------------------------------------------
    # Broad category evaluation
    # -------------------------------------------------------------

    def to_category(label):

        if label in R2L_ATTACKS:
            return "R2L"

        if label in U2R_ATTACKS:
            return "U2R"

        return "OTHER"

    true_categories = y_attack.map(
        to_category
    )

    predicted_categories = p_attack.map(
        to_category
    )

    print("\nR2L/U2R category report:")

    print(
        classification_report(
            true_categories,
            predicted_categories,
            labels=["R2L", "U2R"],
            zero_division=0,
        )
    )

    # -------------------------------------------------------------
    # R2L recall
    # -------------------------------------------------------------

    r2l_mask = (
        true_categories == "R2L"
    )

    if r2l_mask.sum() > 0:

        r2l_recall = (
            predicted_categories[r2l_mask]
            == "R2L"
        ).mean()

        print(
            f"R2L category recall: "
            f"{r2l_recall:.4f}"
        )

    # -------------------------------------------------------------
    # U2R recall
    # -------------------------------------------------------------

    u2r_mask = (
        true_categories == "U2R"
    )

    if u2r_mask.sum() > 0:

        u2r_recall = (
            predicted_categories[u2r_mask]
            == "U2R"
        ).mean()

        print(
            f"U2R category recall: "
            f"{u2r_recall:.4f}"
        )

    # -------------------------------------------------------------
    # Exact attack report
    # -------------------------------------------------------------

    print(
        "\nExact R2L/U2R classification report:"
    )

    print(
        classification_report(
            y_attack,
            p_attack,
            labels=target_labels,
            zero_division=0,
        )
    )


def print_confusion_matrix(
    name,
    y_true,
    predictions,
):
    """Print a confusion matrix for the R2L/U2R samples."""

    target_labels = sorted(
        R2L_ATTACKS | U2R_ATTACKS
    )

    mask = y_true.isin(
        target_labels
    )

    y_attack = y_true[mask]

    p_attack = pd.Series(
        predictions,
        index=y_true.index,
    )[mask]

    if len(y_attack) == 0:
        return

    matrix = confusion_matrix(
        y_attack,
        p_attack,
        labels=target_labels,
    )

    print("\n" + "-" * 72)
    print(name)
    print("-" * 72)

    print(
        "\nRows = actual attack"
    )

    print(
        "Columns = predicted attack"
    )

    matrix_df = pd.DataFrame(
        matrix,
        index=target_labels,
        columns=target_labels,
    )

    print(
        matrix_df.to_string()
    )


def main():

    print("\n" + "=" * 72)
    print("NTCF R2L/U2R MODEL EVALUATION")
    print("=" * 72)

    print(
        "\nLoading processed datasets..."
    )

    (
        X_train,
        y_train,
        X_test,
        y_test,
    ) = load_data()

    print(
        f"Training samples: {len(X_train)}"
    )

    print(
        f"Testing samples:  {len(X_test)}"
    )

    # -------------------------------------------------------------
    # Load existing model
    # -------------------------------------------------------------

    print(
        "\nLoading existing Decision Tree..."
    )

    existing_model = joblib.load(
        MODEL_PATH
    )

    print(
        "Existing model loaded."
    )

    print(
        "\nExisting model classes:"
    )

    print(
        existing_model.classes_
    )

    # -------------------------------------------------------------
    # Existing model evaluation
    # -------------------------------------------------------------

    existing_predictions = (
        existing_model.predict(
            X_test
        )
    )

    evaluate_predictions(
        "EXISTING DECISION TREE",
        y_test,
        existing_predictions,
    )

    print_confusion_matrix(
        "EXISTING MODEL - R2L/U2R CONFUSION MATRIX",
        y_test,
        existing_predictions,
    )

    # -------------------------------------------------------------
    # Build temporary balanced model
    # -------------------------------------------------------------

    print(
        "\nTraining temporary balanced Decision Tree..."
    )

    balanced_model = DecisionTreeClassifier(
        criterion="gini",
        max_depth=20,
        min_samples_split=2,
        class_weight="balanced",
        random_state=42,
    )

    balanced_model.fit(
        X_train,
        y_train,
    )

    print(
        "Temporary balanced model trained."
    )

    # -------------------------------------------------------------
    # Balanced model evaluation
    # -------------------------------------------------------------

    balanced_predictions = (
        balanced_model.predict(
            X_test
        )
    )

    evaluate_predictions(
        "TEMPORARY BALANCED DECISION TREE",
        y_test,
        balanced_predictions,
    )

    print_confusion_matrix(
        "BALANCED MODEL - R2L/U2R CONFUSION MATRIX",
        y_test,
        balanced_predictions,
    )

    # -------------------------------------------------------------
    # Direct comparison
    # -------------------------------------------------------------

    print("\n" + "=" * 72)
    print("COMPARISON")
    print("=" * 72)

    target_labels = sorted(
        R2L_ATTACKS | U2R_ATTACKS
    )

    attack_mask = y_test.isin(
        target_labels
    )

    true_attack = y_test[attack_mask]

    existing_attack = pd.Series(
        existing_predictions,
        index=y_test.index,
    )[attack_mask]

    balanced_attack = pd.Series(
        balanced_predictions,
        index=y_test.index,
    )[attack_mask]

    existing_category = true_attack.map(
        lambda label:
        "R2L"
        if label in R2L_ATTACKS
        else "U2R"
    )

    existing_pred_category = (
        existing_attack.map(
            lambda label:
            "R2L"
            if label in R2L_ATTACKS
            else (
                "U2R"
                if label in U2R_ATTACKS
                else "OTHER"
            )
        )
    )

    balanced_pred_category = (
        balanced_attack.map(
            lambda label:
            "R2L"
            if label in R2L_ATTACKS
            else (
                "U2R"
                if label in U2R_ATTACKS
                else "OTHER"
            )
        )
    )

    existing_r2l_mask = (
        existing_category == "R2L"
    )

    balanced_r2l_mask = (
        existing_category == "R2L"
    )

    existing_u2r_mask = (
        existing_category == "U2R"
    )

    balanced_u2r_mask = (
        existing_category == "U2R"
    )

    if existing_r2l_mask.sum() > 0:

        existing_r2l_recall = (
            (
                existing_pred_category[
                    existing_r2l_mask
                ]
                == "R2L"
            ).mean()
        )

        balanced_r2l_recall = (
            (
                balanced_pred_category[
                    balanced_r2l_mask
                ]
                == "R2L"
            ).mean()
        )

    else:

        existing_r2l_recall = 0.0
        balanced_r2l_recall = 0.0

    if existing_u2r_mask.sum() > 0:

        existing_u2r_recall = (
            (
                existing_pred_category[
                    existing_u2r_mask
                ]
                == "U2R"
            ).mean()
        )

        balanced_u2r_recall = (
            (
                balanced_pred_category[
                    balanced_u2r_mask
                ]
                == "U2R"
            ).mean()
        )

    else:

        existing_u2r_recall = 0.0
        balanced_u2r_recall = 0.0

    print(
        "\nCategory recall comparison:"
    )

    print(
        f"\nR2L:"
    )

    print(
        f"  Existing: {existing_r2l_recall:.4f}"
    )

    print(
        f"  Balanced: {balanced_r2l_recall:.4f}"
    )

    print(
        f"\nU2R:"
    )

    print(
        f"  Existing: {existing_u2r_recall:.4f}"
    )

    print(
        f"  Balanced: {balanced_u2r_recall:.4f}"
    )

    print(
        "\nNo model artifact was changed."
    )

    print(
        "No packet-capture files were changed."
    )

    print(
        "No API files were changed."
    )

    print(
        "\nEvaluation complete."
    )


if __name__ == "__main__":
    main()