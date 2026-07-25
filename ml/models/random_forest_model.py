"""
Random Forest Classifier for Network Threat Classification
============================================================

Part of the Network Threat Cognition Framework (NTCF).

This module wraps `sklearn.ensemble.RandomForestClassifier` with the
plumbing needed to use it as one of NTCF's threat-classification models:

    * documented, sensible default hyperparameters for intrusion detection
    * training / prediction / evaluation helpers
    * persistence (save/load) via joblib so a trained model can be
      reloaded later purely for inference (e.g. by the detection service)
    * feature importance inspection
    * a machine-readable configuration snapshot for reproducibility

Typical usage
-------------
    from ml.models.random_forest_model import RandomForestModel

    model = RandomForestModel(n_estimators=300, max_depth=25)
    model.train(X_train, y_train)

    predictions = model.predict(X_test)
    metrics = model.evaluate(X_test, y_test)

    model.save("ml/artifacts/random_forest_model.joblib")

    # Later on, purely for inference:
    loaded = RandomForestModel.load("ml/artifacts/random_forest_model.joblib")
    loaded.predict(new_flows)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

logger = logging.getLogger(__name__)

ArrayLike = Union[np.ndarray, Sequence[Sequence[float]]]

# ---------------------------------------------------------------------------
# Default hyperparameters
# ---------------------------------------------------------------------------
# These defaults are tuned for tabular network-flow data:
#   - a large-ish forest (n_estimators) for stable probability estimates
#   - a bounded max_depth to keep training/inference fast and reduce
#     overfitting to noisy flow features
#   - "balanced_subsample" class weighting because threat datasets are
#     typically dominated by benign traffic, with attack classes being
#     comparatively rare
DEFAULT_HYPERPARAMETERS: Dict[str, Any] = {
    "n_estimators": 300,
    "criterion": "gini",
    "max_depth": 25,
    "min_samples_split": 4,
    "min_samples_leaf": 2,
    "max_features": "sqrt",
    "bootstrap": True,
    "class_weight": "balanced_subsample",
    "n_jobs": -1,
    "random_state": 42,
}


class RandomForestModel:
    """A configurable, persistable Random Forest classifier for NTCF.

    Parameters
    ----------
    feature_names:
        Optional list of feature column names. Stored purely for
        documentation / reproducibility purposes and, if provided, used
        to validate incoming data shape.
    **hyperparameters:
        Any keyword argument accepted by
        `sklearn.ensemble.RandomForestClassifier`. Values provided here
        override the corresponding entry in `DEFAULT_HYPERPARAMETERS`;
        anything not provided falls back to the default.
    """

    def __init__(
        self,
        feature_names: Optional[List[str]] = None,
        **hyperparameters: Any,
    ) -> None:
        self.hyperparameters: Dict[str, Any] = {**DEFAULT_HYPERPARAMETERS, **hyperparameters}
        self.feature_names: Optional[List[str]] = feature_names
        self.class_labels_: Optional[List[Any]] = None
        self.is_trained: bool = False
        self.trained_at: Optional[str] = None
        self.training_metadata: Dict[str, Any] = {}

        self.model: RandomForestClassifier = RandomForestClassifier(**self.hyperparameters)

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    def configure(self, **hyperparameters: Any) -> "RandomForestModel":
        """Update hyperparameters and rebuild the underlying estimator.

        Re-configuring after training resets the fitted state, since the
        underlying `RandomForestClassifier` is rebuilt from scratch.
        """
        self.hyperparameters.update(hyperparameters)
        self.model = RandomForestClassifier(**self.hyperparameters)
        self.is_trained = False
        self.trained_at = None
        return self

    def get_config(self) -> Dict[str, Any]:
        """Return a JSON-serialisable snapshot of the model configuration.

        Useful for documenting exactly which hyperparameters and features
        produced a given trained artifact.
        """
        return {
            "model_type": "RandomForestClassifier",
            "hyperparameters": self.hyperparameters,
            "feature_names": self.feature_names,
            "n_features": len(self.feature_names) if self.feature_names else None,
            "class_labels": self.class_labels_,
            "is_trained": self.is_trained,
            "trained_at": self.trained_at,
            "training_metadata": self.training_metadata,
        }

    def document_config(self, path: Union[str, Path]) -> Path:
        """Write `get_config()` to a JSON file for record-keeping."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.get_config(), f, indent=2, default=str)
        logger.info("Wrote model configuration to %s", path)
        return path

    # ------------------------------------------------------------------
    # Training / inference
    # ------------------------------------------------------------------
    def train(self, X_train: ArrayLike, y_train: ArrayLike) -> "RandomForestModel":
        """Fit the Random Forest on training data.

        Parameters
        ----------
        X_train: array-like of shape (n_samples, n_features)
        y_train: array-like of shape (n_samples,)
        """
        X_train = self._validate_features(X_train)

        self.model.fit(X_train, y_train)
        self.class_labels_ = list(self.model.classes_)
        self.is_trained = True
        self.trained_at = datetime.now(timezone.utc).isoformat()
        self.training_metadata = {
            "n_samples": int(X_train.shape[0]),
            "n_features": int(X_train.shape[1]),
            "n_classes": len(self.class_labels_),
        }
        logger.info(
            "Trained RandomForestModel on %s samples / %s features / %s classes",
            X_train.shape[0], X_train.shape[1], len(self.class_labels_),
        )
        return self

    def predict(self, X: ArrayLike) -> np.ndarray:
        """Predict threat class labels for the given samples."""
        self._require_trained()
        X = self._validate_features(X)
        return self.model.predict(X)

    def predict_proba(self, X: ArrayLike) -> np.ndarray:
        """Predict class probabilities for the given samples."""
        self._require_trained()
        X = self._validate_features(X)
        return self.model.predict_proba(X)

    def predict_one(self, x: Sequence[float]) -> Any:
        """Convenience helper to classify a single flow/record."""
        prediction = self.predict(np.asarray(x).reshape(1, -1))
        return prediction[0]

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------
    def evaluate(self, X_test: ArrayLike, y_test: ArrayLike) -> Dict[str, Any]:
        """Generate predictions on the test set and compute metrics.

        Returns a dictionary with accuracy, macro/weighted precision,
        recall, F1, the full sklearn classification report, and the
        confusion matrix.
        """
        self._require_trained()
        y_pred = self.predict(X_test)

        metrics: Dict[str, Any] = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision_macro": precision_score(y_test, y_pred, average="macro", zero_division=0),
            "recall_macro": recall_score(y_test, y_pred, average="macro", zero_division=0),
            "f1_macro": f1_score(y_test, y_pred, average="macro", zero_division=0),
            "precision_weighted": precision_score(y_test, y_pred, average="weighted", zero_division=0),
            "recall_weighted": recall_score(y_test, y_pred, average="weighted", zero_division=0),
            "f1_weighted": f1_score(y_test, y_pred, average="weighted", zero_division=0),
            "classification_report": classification_report(y_test, y_pred, zero_division=0),
            "confusion_matrix": confusion_matrix(y_test, y_pred, labels=self.class_labels_).tolist(),
            "labels": self.class_labels_,
        }
        return metrics

    def feature_importance(self, top_n: Optional[int] = None) -> List[Dict[str, Any]]:
        """Return feature importances sorted from most to least important.

        If `feature_names` was not provided, generic names (feature_0, ...)
        are used instead.
        """
        self._require_trained()
        importances = self.model.feature_importances_
        names = self.feature_names or [f"feature_{i}" for i in range(len(importances))]
        ranked = sorted(
            (
                {"feature": name, "importance": float(score)}
                for name, score in zip(names, importances)
            ),
            key=lambda item: item["importance"],
            reverse=True,
        )
        return ranked[:top_n] if top_n else ranked

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def save(self, path: Union[str, Path]) -> Path:
        """Persist the trained model (and its metadata) to disk with joblib."""
        self._require_trained()
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "model": self.model,
            "hyperparameters": self.hyperparameters,
            "feature_names": self.feature_names,
            "class_labels": self.class_labels_,
            "trained_at": self.trained_at,
            "training_metadata": self.training_metadata,
        }
        joblib.dump(payload, path)
        logger.info("Saved RandomForestModel to %s", path)
        return path

    @classmethod
    def load(cls, path: Union[str, Path]) -> "RandomForestModel":
        """Load a previously saved model and return a ready-to-use instance."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"No model artifact found at {path}")

        payload = joblib.load(path)

        instance = cls(feature_names=payload.get("feature_names"), **payload["hyperparameters"])
        instance.model = payload["model"]
        instance.class_labels_ = payload.get("class_labels")
        instance.is_trained = True
        instance.trained_at = payload.get("trained_at")
        instance.training_metadata = payload.get("training_metadata", {})
        logger.info("Loaded RandomForestModel from %s", path)
        return instance

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _require_trained(self) -> None:
        if not self.is_trained:
            raise RuntimeError(
                "RandomForestModel must be trained (or loaded from disk) before "
                "it can predict, evaluate, or be saved."
            )

    def _validate_features(self, X: ArrayLike) -> np.ndarray:
        """Coerce input to a numpy array and sanity-check its feature count."""
        X_arr = X.values if hasattr(X, "values") else np.asarray(X)
        if self.feature_names and X_arr.shape[1] != len(self.feature_names):
            raise ValueError(
                f"Expected {len(self.feature_names)} features "
                f"({self.feature_names}), got {X_arr.shape[1]}."
            )
        return X_arr

    def __repr__(self) -> str:
        status = "trained" if self.is_trained else "untrained"
        return (
            f"RandomForestModel(status={status}, "
            f"n_estimators={self.hyperparameters.get('n_estimators')}, "
            f"max_depth={self.hyperparameters.get('max_depth')})"
        )
