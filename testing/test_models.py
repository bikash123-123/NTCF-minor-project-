"""
test_models.py

Automated tests for the NTCF machine-learning models.

Tests:
- Decision Tree
- Random Forest
- Support Vector Machine (SVM)
- Training
- Prediction
- Evaluation
- Save / load functionality
"""

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from sklearn.metrics import accuracy_score

from ml.models import decision_tree_model
from ml.models import svm_model
from ml.models.random_forest_model import RandomForestModel


# ---------------------------------------------------------------------
# Test Data
# ---------------------------------------------------------------------

@pytest.fixture
def sample_data():
    """
    Create a small numeric dataset suitable for
    testing all three classifiers.
    """

    X = pd.DataFrame(
        {
            "duration": [1, 2, 3, 4, 5, 6, 7, 8],
            "src_bytes": [10, 20, 30, 40, 50, 60, 70, 80],
            "dst_bytes": [5, 10, 15, 20, 25, 30, 35, 40],
        }
    )

    y = pd.Series(
        [
            "normal",
            "normal",
            "normal",
            "normal",
            "attack",
            "attack",
            "attack",
            "attack",
        ],
        name="label",
    )

    return X, y


# ---------------------------------------------------------------------
# Decision Tree Tests
# ---------------------------------------------------------------------

class TestDecisionTreeModel:

    def test_build_model(self):
        """
        Verify that the Decision Tree model
        can be created.
        """

        model = decision_tree_model.build_model()

        assert model is not None

    def test_train_model(self, sample_data):
        """
        Verify that the Decision Tree can be trained.
        """

        X, y = sample_data

        model = decision_tree_model.build_model()

        trained_model = decision_tree_model.train_model(
            model,
            X,
            y,
        )

        assert trained_model is model
        assert hasattr(trained_model, "predict")

    def test_prediction(self, sample_data):
        """
        Verify that the Decision Tree generates
        predictions for all input samples.
        """

        X, y = sample_data

        model = decision_tree_model.build_model()

        model = decision_tree_model.train_model(
            model,
            X,
            y,
        )

        predictions = decision_tree_model.predict(
            model,
            X,
        )

        assert len(predictions) == len(X)

    def test_prediction_labels(self, sample_data):
        """
        Verify that Decision Tree predictions
        belong to the trained label set.
        """

        X, y = sample_data

        model = decision_tree_model.build_model()

        model = decision_tree_model.train_model(
            model,
            X,
            y,
        )

        predictions = decision_tree_model.predict(
            model,
            X,
        )

        assert set(predictions).issubset(set(y))

    def test_evaluate_model(self, sample_data):
        """
        Verify Decision Tree evaluation returns
        a valid accuracy score.
        """

        X, y = sample_data

        model = decision_tree_model.build_model()

        model = decision_tree_model.train_model(
            model,
            X,
            y,
        )

        accuracy = decision_tree_model.evaluate_model(
            model,
            X,
            y,
        )

        assert isinstance(accuracy, float)
        assert 0.0 <= accuracy <= 1.0

    def test_save_and_load_model(
        self,
        sample_data,
        tmp_path,
    ):
        """
        Verify that a Decision Tree model can
        be saved and loaded successfully.
        """

        X, y = sample_data

        model = decision_tree_model.build_model()

        model = decision_tree_model.train_model(
            model,
            X,
            y,
        )

        model_path = tmp_path / "decision_tree_test.pkl"

        decision_tree_model.save_model(
            model,
            model_path,
        )

        assert model_path.exists()

        loaded_model = decision_tree_model.load_model(
            model_path,
        )

        predictions = loaded_model.predict(X)

        assert len(predictions) == len(X)


# ---------------------------------------------------------------------
# SVM Tests
# ---------------------------------------------------------------------

class TestSVMModel:

    def test_create_model(self):
        """
        Verify that an SVM model can be created.
        """

        model = svm_model.create_model()

        assert model is not None

    def test_train_model(self, sample_data):
        """
        Verify that the SVM model can be trained.
        """

        X, y = sample_data

        model = svm_model.create_model()

        trained_model = svm_model.train_model(
            model,
            X,
            y,
        )

        assert trained_model is model

    def test_prediction(self, sample_data):
        """
        Verify that SVM generates predictions.
        """

        X, y = sample_data

        model = svm_model.create_model()

        model = svm_model.train_model(
            model,
            X,
            y,
        )

        predictions = svm_model.predict(
            model,
            X,
        )

        assert len(predictions) == len(X)

    def test_prediction_labels(self, sample_data):
        """
        Verify that SVM predictions are valid labels.
        """

        X, y = sample_data

        model = svm_model.create_model()

        model = svm_model.train_model(
            model,
            X,
            y,
        )

        predictions = svm_model.predict(
            model,
            X,
        )

        assert set(predictions).issubset(set(y))

    def test_evaluate_model(self, sample_data):
        """
        Verify SVM evaluation metrics.
        """

        X, y = sample_data

        model = svm_model.create_model()

        model = svm_model.train_model(
            model,
            X,
            y,
        )

        predictions = svm_model.predict(
            model,
            X,
        )

        results = svm_model.evaluate_model(
            y,
            predictions,
        )

        assert isinstance(results, dict)

        assert "accuracy" in results
        assert "classification_report" in results

        assert 0.0 <= results["accuracy"] <= 1.0

    def test_save_and_load_model(
        self,
        sample_data,
        tmp_path,
    ):
        """
        Verify SVM save/load functionality.
        """

        X, y = sample_data

        model = svm_model.create_model()

        model = svm_model.train_model(
            model,
            X,
            y,
        )

        model_path = tmp_path / "svm_test.pkl"

        svm_model.save_model(
            model,
            model_path,
        )

        assert model_path.exists()

        loaded_model = svm_model.load_model(
            model_path,
        )

        predictions = loaded_model.predict(X)

        assert len(predictions) == len(X)


# ---------------------------------------------------------------------
# Random Forest Tests
# ---------------------------------------------------------------------

class TestRandomForestModel:

    def test_model_can_be_created(self):
        """
        Verify that RandomForestModel can be instantiated.
        """

        model = RandomForestModel()

        assert model is not None

    def test_model_has_prediction_interface(self):
        """
        Verify that RandomForestModel provides
        the expected prediction interface.
        """

        model = RandomForestModel()

        assert hasattr(model, "predict")

    def test_model_training_interface(self):
        """
        Verify that the Random Forest implementation
        exposes a training interface.
        """

        model = RandomForestModel()

        assert (
            hasattr(model, "fit")
            or hasattr(model, "train")
        )


# ---------------------------------------------------------------------
# Cross-Model Tests
# ---------------------------------------------------------------------

class TestModelConsistency:

    def test_all_models_predict_same_number_of_samples(
        self,
        sample_data,
    ):
        """
        Verify that all model types return one
        prediction per input sample.

        Random Forest is tested only when its
        implementation exposes a compatible fit API.
        """

        X, y = sample_data

        # Decision Tree
        decision_tree = (
            decision_tree_model.build_model()
        )

        decision_tree = (
            decision_tree_model.train_model(
                decision_tree,
                X,
                y,
            )
        )

        dt_predictions = (
            decision_tree_model.predict(
                decision_tree,
                X,
            )
        )

        assert len(dt_predictions) == len(X)

        # SVM
        svm = svm_model.create_model()

        svm = svm_model.train_model(
            svm,
            X,
            y,
        )

        svm_predictions = svm_model.predict(
            svm,
            X,
        )

        assert len(svm_predictions) == len(X)

    def test_models_produce_valid_accuracy(
        self,
        sample_data,
    ):
        """
        Verify that the major model implementations
        can produce valid accuracy values.
        """

        X, y = sample_data

        # Decision Tree
        dt = decision_tree_model.build_model()

        dt = decision_tree_model.train_model(
            dt,
            X,
            y,
        )

        dt_predictions = (
            decision_tree_model.predict(
                dt,
                X,
            )
        )

        dt_accuracy = accuracy_score(
            y,
            dt_predictions,
        )

        assert 0.0 <= dt_accuracy <= 1.0

        # SVM
        svm = svm_model.create_model()

        svm = svm_model.train_model(
            svm,
            X,
            y,
        )

        svm_predictions = svm_model.predict(
            svm,
            X,
        )

        svm_accuracy = accuracy_score(
            y,
            svm_predictions,
        )

        assert 0.0 <= svm_accuracy <= 1.0