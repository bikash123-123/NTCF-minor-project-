"""
decision_tree_model.py

Decision Tree model implementation for the
Network Threat Cognition Framework (NTCF).

This module loads the processed dataset, trains a Decision Tree
classifier, generates predictions, and provides utilities for
saving and loading the trained model.
"""

from pathlib import Path
import joblib
import pandas as pd

from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score


# ---------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[2]

TRAIN_DATA = BASE_DIR / "data" / "processed" / "train_processed.csv"
TEST_DATA = BASE_DIR / "data" / "processed" / "test_processed.csv"

ARTIFACT_DIR = BASE_DIR / "ml" / "artifacts"
MODEL_PATH = ARTIFACT_DIR / "decision_tree_model.pkl"

TARGET_COLUMN = "label"


# ---------------------------------------------------------------------
# Dataset Loading
# ---------------------------------------------------------------------

def load_processed_data():
    """
    Load the processed training and testing datasets.

    Returns
    -------
    tuple
        X_train, X_test, y_train, y_test
    """

    train_df = pd.read_csv(TRAIN_DATA)
    test_df = pd.read_csv(TEST_DATA)

    X_train = train_df.drop(columns=[TARGET_COLUMN])
    y_train = train_df[TARGET_COLUMN]

    X_test = test_df.drop(columns=[TARGET_COLUMN])
    y_test = test_df[TARGET_COLUMN]

    return X_train, X_test, y_train, y_test


# ---------------------------------------------------------------------
# Model Creation
# ---------------------------------------------------------------------

def build_model(
    criterion="gini",
    max_depth=20,
    min_samples_split=2,
    random_state=42
):
    """
    Create a Decision Tree classifier.

    Returns
    -------
    DecisionTreeClassifier
    """

    return DecisionTreeClassifier(
        criterion=criterion,
        max_depth=max_depth,
        min_samples_split=min_samples_split,
        random_state=random_state
    )


# ---------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------

def train_model(model, X_train, y_train):
    """
    Train the Decision Tree model.
    """

    model.fit(X_train, y_train)

    return model


# ---------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------

def predict(model, X_test):
    """
    Generate predictions.
    """

    return model.predict(X_test)


# ---------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------

def evaluate_model(model, X_test, y_test):
    """
    Evaluate model performance.

    Returns
    -------
    float
        Accuracy score
    """

    predictions = predict(model, X_test)

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    return accuracy


# ---------------------------------------------------------------------
# Save Model
# ---------------------------------------------------------------------

def save_model(model, model_path=MODEL_PATH):
    """
    Save trained model.
    """

    ARTIFACT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    joblib.dump(model, model_path)


# ---------------------------------------------------------------------
# Load Model
# ---------------------------------------------------------------------

def load_model(model_path=MODEL_PATH):
    """
    Load a saved Decision Tree model.
    """

    return joblib.load(model_path)


# ---------------------------------------------------------------------
# Example Execution
# ---------------------------------------------------------------------

if __name__ == "__main__":

    X_train, X_test, y_train, y_test = load_processed_data()

    model = build_model()

    train_model(
        model,
        X_train,
        y_train
    )

    accuracy = evaluate_model(
        model,
        X_test,
        y_test
    )

    save_model(model)

    print(f"Decision Tree Accuracy: {accuracy:.4f}")
    print(f"Model saved to: {MODEL_PATH}")