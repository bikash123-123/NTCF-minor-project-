"""
confidence_calculator.py

Calibrated confidence calculation for the NTCF detection pipeline.

IMPORTANT
---------
- The existing Decision Tree is NOT retrained.
- The existing Decision Tree artifact is NOT modified.
- No additional model artifact is created.
- No additional project file is required.
- The existing calculate_confidence(model, features) API is preserved.

Calibration strategy
--------------------
A Decision Tree can return max(predict_proba()) == 1.0 for many
different terminal leaves. Therefore raw tree probability alone is
not a reliable confidence measure.

This implementation uses information already available from the
existing Decision Tree:

    model.predict_proba()
        |
        +-- raw probability
        +-- probability margin

    model.apply()
        |
        +-- leaf identity
        +-- empirical leaf reliability

    model.classes_
        |
        +-- predicted-class reliability

Calibration reference
---------------------
KDDTest+ is used as a post-hoc calibration reference.

For every KDDTest+ sample we calculate:

    - predicted class
    - raw probability
    - probability margin
    - tree leaf
    - whether the prediction was correct

Live confidence is then estimated from:

    1. leaf reliability
    2. predicted-class reliability
    3. raw-probability-bin reliability
    4. probability margin

Rare leaves/classes are smoothed toward safer priors.

The classifier itself remains completely untouched.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import warnings

import joblib
import numpy as np
import pandas as pd


# ============================================================
# Project paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "KDDTest+.txt"
)

ARTIFACT_DIR = (
    PROJECT_ROOT
    / "ml"
    / "artifacts"
)

ENCODER_PATH = (
    ARTIFACT_DIR
    / "encoder.pkl"
)

SCALER_PATH = (
    ARTIFACT_DIR
    / "scaler.pkl"
)


# ============================================================
# NSL-KDD columns
# ============================================================

ALL_COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "label",
    "difficulty",
]

TARGET_COLUMN = "label"

CATEGORICAL_COLUMNS = [
    "protocol_type",
    "service",
    "flag",
]

NUMERICAL_COLUMNS = [
    column
    for column in ALL_COLUMNS
    if column not in (
        CATEGORICAL_COLUMNS
        + [
            "label",
            "difficulty",
        ]
    )
]


# ============================================================
# Confidence limits
# ============================================================

MIN_CONFIDENCE = 0.01
MAX_CONFIDENCE = 0.99


# ============================================================
# Calibration parameters
# ============================================================

# Bayesian smoothing strength.
#
# Higher values pull rare leaves/classes toward their prior.
# A moderate value is useful because R2L/U2R have comparatively
# fewer observations in NSL-KDD.
SMOOTHING_STRENGTH = 8.0


# Minimum useful leaf support.
#
# The value is retained as a named parameter for clarity and
# future tuning. The current calculation uses the actual support
# together with Bayesian smoothing.
LEAF_MIN_SUPPORT = 5


# Signal weights.
#
# Leaf reliability is strongest because a Decision Tree prediction
# is fundamentally determined by its terminal leaf.
LEAF_WEIGHT = 0.45
CLASS_WEIGHT = 0.25
RAW_WEIGHT = 0.20
MARGIN_WEIGHT = 0.10


# ============================================================
# Runtime calibration cache
# ============================================================

_CALIBRATION_CACHE = {}


# ============================================================
# Utility functions
# ============================================================

def _clip_confidence(value):
    """
    Keep confidence inside the NTCF confidence range.
    """

    try:
        value = float(value)

    except (
        TypeError,
        ValueError,
    ):
        return MIN_CONFIDENCE

    if not np.isfinite(value):
        return MIN_CONFIDENCE

    return float(
        np.clip(
            value,
            MIN_CONFIDENCE,
            MAX_CONFIDENCE,
        )
    )


def _safe_string(value):
    """
    Normalize labels consistently.
    """

    if value is None:
        return ""

    return (
        str(value)
        .strip()
        .lower()
        .rstrip(".")
    )


def _beta_smoothed_rate(
    correct,
    total,
    prior,
    strength=SMOOTHING_STRENGTH,
):
    """
    Bayesian/Beta-style smoothing.

    Formula:

        correct + prior * strength
        --------------------------
              total + strength

    This prevents small samples from producing extreme confidence.
    """

    correct = float(correct)
    total = float(total)

    prior = float(
        np.clip(
            prior,
            MIN_CONFIDENCE,
            MAX_CONFIDENCE,
        )
    )

    if total <= 0:
        return prior

    value = (
        correct
        + prior * strength
    ) / (
        total
        + strength
    )

    return float(
        np.clip(
            value,
            MIN_CONFIDENCE,
            MAX_CONFIDENCE,
        )
    )


# ============================================================
# Raw probability information
# ============================================================

def _probability_information(
    model,
    features,
):
    """
    Extract model probability information.

    Returns
    -------
    dict
        probabilities
        predicted_class
        raw_probability
        margin
        leaf_id
    """

    probabilities = model.predict_proba(
        features
    )

    probabilities = np.asarray(
        probabilities,
        dtype=float,
    )

    if probabilities.ndim != 2:
        raise ValueError(
            "Expected a two-dimensional probability matrix; "
            f"received {probabilities.shape}."
        )

    if probabilities.shape[0] == 0:
        raise ValueError(
            "Model returned no probability rows."
        )

    probabilities = probabilities[0]

    if probabilities.size == 0:
        raise ValueError(
            "Model returned an empty probability vector."
        )

    if not np.all(
        np.isfinite(
            probabilities
        )
    ):
        raise ValueError(
            "Model returned non-finite probabilities."
        )

    probabilities = np.clip(
        probabilities,
        0.0,
        1.0,
    )

    total = float(
        probabilities.sum()
    )

    if total <= 0:
        raise ValueError(
            "Model probabilities have zero total."
        )

    probabilities = (
        probabilities / total
    )

    order = np.argsort(
        probabilities
    )[::-1]

    best_index = int(
        order[0]
    )

    raw_probability = float(
        probabilities[best_index]
    )

    if probabilities.size >= 2:
        second_probability = float(
            probabilities[order[1]]
        )

    else:
        second_probability = 0.0

    margin = (
        raw_probability
        - second_probability
    )

    predicted_class = None

    if hasattr(
        model,
        "classes_",
    ):
        classes = np.asarray(
            model.classes_
        )

        if best_index < len(classes):
            predicted_class = _safe_string(
                classes[best_index]
            )

    if predicted_class is None:
        prediction = model.predict(
            features
        )

        prediction = np.asarray(
            prediction
        )

        if prediction.size == 0:
            raise ValueError(
                "Model returned no prediction."
            )

        predicted_class = _safe_string(
            prediction[0]
        )

    leaf_id = None

    if hasattr(
        model,
        "apply",
    ):
        try:
            leaves = model.apply(
                features
            )

            leaves = np.asarray(
                leaves
            )

            if leaves.size > 0:
                leaf_id = int(
                    leaves.reshape(-1)[0]
                )

        except Exception:
            leaf_id = None

    return {
        "probabilities": probabilities,
        "predicted_class": predicted_class,
        "raw_probability": raw_probability,
        "margin": float(
            np.clip(
                margin,
                0.0,
                1.0,
            )
        ),
        "leaf_id": leaf_id,
    }


# ============================================================
# Load KDDTest+
# ============================================================

def _load_calibration_dataset():
    """
    Load KDDTest+.

    KDDTest+ is intentionally used for calibration rather than
    the training observations.
    """

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            "Calibration dataset not found: "
            f"{DATASET_PATH}"
        )

    dataframe = pd.read_csv(
        DATASET_PATH,
        header=None,
        names=ALL_COLUMNS,
    )

    dataframe = dataframe.dropna()
    dataframe = dataframe.drop_duplicates()

    dataframe = dataframe[
        dataframe["duration"] >= 0
    ]

    for column in CATEGORICAL_COLUMNS:
        dataframe[column] = (
            dataframe[column]
            .astype(str)
            .str.strip()
            .str.lower()
        )

    dataframe[TARGET_COLUMN] = (
        dataframe[TARGET_COLUMN]
        .astype(str)
        .str.strip()
        .str.lower()
        .str.rstrip(".")
    )

    X = dataframe.drop(
        columns=[
            TARGET_COLUMN,
            "difficulty",
        ]
    )

    y = dataframe[TARGET_COLUMN]

    return X, y


# ============================================================
# Transform calibration features
# ============================================================

def _prepare_calibration_features(X):
    """
    Transform KDDTest+ using the existing NTCF encoder and scaler.

    No preprocessing artifact is modified.
    """

    if not ENCODER_PATH.exists():
        raise FileNotFoundError(
            "NTCF encoder artifact not found: "
            f"{ENCODER_PATH}"
        )

    if not SCALER_PATH.exists():
        raise FileNotFoundError(
            "NTCF scaler artifact not found: "
            f"{SCALER_PATH}"
        )

    encoder = joblib.load(
        ENCODER_PATH
    )

    scaler = joblib.load(
        SCALER_PATH
    )

    # --------------------------------------------------------
    # Categorical features
    # --------------------------------------------------------

    encoded = encoder.transform(
        X[CATEGORICAL_COLUMNS]
    )

    encoded_columns = (
        encoder.get_feature_names_out(
            CATEGORICAL_COLUMNS
        )
    )

    encoded_df = pd.DataFrame(
        encoded,
        columns=encoded_columns,
        index=X.index,
    )

    # --------------------------------------------------------
    # Numerical features
    # --------------------------------------------------------

    scaled = scaler.transform(
        X[NUMERICAL_COLUMNS]
    )

    scaled_df = pd.DataFrame(
        scaled,
        columns=NUMERICAL_COLUMNS,
        index=X.index,
    )

    # --------------------------------------------------------
    # Match the existing NTCF feature order:
    #
    # numerical features first
    # encoded categorical features second
    # --------------------------------------------------------

    return pd.concat(
        [
            scaled_df,
            encoded_df,
        ],
        axis=1,
    )


# ============================================================
# Build calibration reference
# ============================================================

def _build_calibration_reference(model):
    """
    Build empirical reliability statistics from KDDTest+.

    Statistics are maintained for:

        - global correctness
        - predicted class
        - Decision Tree leaf
        - raw probability bins
    """

    X_raw, y_true = (
        _load_calibration_dataset()
    )

    X_calibration = (
        _prepare_calibration_features(
            X_raw
        )
    )

    probabilities = model.predict_proba(
        X_calibration
    )

    probabilities = np.asarray(
        probabilities,
        dtype=float,
    )

    if probabilities.ndim != 2:
        raise ValueError(
            "Expected a two-dimensional probability matrix."
        )

    predictions = model.predict(
        X_calibration
    )

    predictions = np.asarray(
        predictions
    )

    predictions = np.array(
        [
            _safe_string(value)
            for value in predictions
        ],
        dtype=object,
    )

    true_labels = np.array(
        [
            _safe_string(value)
            for value in y_true
        ],
        dtype=object,
    )

    if len(predictions) != len(true_labels):
        raise ValueError(
            "Prediction/label length mismatch."
        )

    correct = (
        predictions == true_labels
    ).astype(float)

    valid = np.isfinite(
        probabilities
    ).all(axis=1)

    valid &= np.isfinite(
        correct
    )

    probabilities = probabilities[valid]
    predictions = predictions[valid]
    true_labels = true_labels[valid]
    correct = correct[valid]

    valid_indices = np.flatnonzero(
        valid
    )

    X_valid = X_calibration.iloc[
        valid_indices
    ]

    if len(correct) < 100:
        raise ValueError(
            "Insufficient calibration samples. "
            f"Only {len(correct)} valid samples available."
        )

    # --------------------------------------------------------
    # Global accuracy
    # --------------------------------------------------------

    global_accuracy = float(
        np.mean(correct)
    )

    # --------------------------------------------------------
    # Raw probability and margin
    # --------------------------------------------------------

    raw_confidences = np.max(
        probabilities,
        axis=1,
    )

    sorted_probabilities = np.sort(
        probabilities,
        axis=1,
    )

    if probabilities.shape[1] >= 2:
        margins = (
            sorted_probabilities[:, -1]
            - sorted_probabilities[:, -2]
        )

    else:
        margins = raw_confidences

    # --------------------------------------------------------
    # Predicted-class statistics
    # --------------------------------------------------------

    class_stats = defaultdict(
        lambda: {
            "correct": 0.0,
            "total": 0.0,
        }
    )

    for prediction, is_correct in zip(
        predictions,
        correct,
    ):
        stats = class_stats[prediction]

        stats["total"] += 1.0
        stats["correct"] += float(
            is_correct
        )

    # --------------------------------------------------------
    # Decision Tree leaf statistics
    # --------------------------------------------------------

    leaf_stats = defaultdict(
        lambda: {
            "correct": 0.0,
            "total": 0.0,
        }
    )

    leaf_ids = None

    if hasattr(
        model,
        "apply",
    ):
        try:
            leaf_ids = np.asarray(
                model.apply(
                    X_valid
                )
            ).reshape(-1)

        except Exception:
            leaf_ids = None

    if leaf_ids is not None:
        for leaf, is_correct in zip(
            leaf_ids,
            correct,
        ):
            stats = leaf_stats[int(leaf)]

            stats["total"] += 1.0
            stats["correct"] += float(
                is_correct
            )

    # --------------------------------------------------------
    # Reliability by raw probability bins
    #
    # Ten broad probability ranges.
    # --------------------------------------------------------

    probability_bins = []

    for lower in np.linspace(
        0.0,
        0.9,
        10,
    ):
        upper = lower + 0.1

        mask = (
            (raw_confidences >= lower)
            &
            (
                (raw_confidences < upper)
                |
                (upper >= 1.0)
            )
        )

        count = int(
            np.sum(mask)
        )

        if count > 0:
            probability_bins.append(
                {
                    "lower": float(lower),
                    "upper": float(upper),
                    "correct": float(
                        np.sum(
                            correct[mask]
                        )
                    ),
                    "total": float(count),
                }
            )

    return {
        "global_accuracy": global_accuracy,
        "class_stats": dict(class_stats),
        "leaf_stats": dict(leaf_stats),
        "probability_bins": probability_bins,
        "sample_count": len(correct),
    }


# ============================================================
# Calibration cache
# ============================================================

def _get_calibration_reference(model):
    """
    Return the cached calibration reference for the model instance.
    """

    model_key = id(model)

    if model_key in _CALIBRATION_CACHE:
        return _CALIBRATION_CACHE[model_key]

    reference = _build_calibration_reference(
        model
    )

    _CALIBRATION_CACHE[
        model_key
    ] = reference

    return reference


# ============================================================
# Probability-bin reliability
# ============================================================

def _probability_reliability(
    raw_probability,
    reference,
):
    """
    Return smoothed empirical reliability for the raw probability
    range.

    If the range is not represented in KDDTest+, global accuracy
    is used.
    """

    raw_probability = float(
        np.clip(
            raw_probability,
            0.0,
            1.0,
        )
    )

    for bucket in reference[
        "probability_bins"
    ]:
        lower = bucket["lower"]
        upper = bucket["upper"]

        if (
            raw_probability >= lower
            and (
                raw_probability < upper
                or upper >= 1.0
            )
        ):
            return _beta_smoothed_rate(
                bucket["correct"],
                bucket["total"],
                reference["global_accuracy"],
            )

    return float(
        reference["global_accuracy"]
    )


# ============================================================
# Calibrated Decision Tree confidence
# ============================================================

def _calculate_probability_confidence(
    model,
    features,
):
    """
    Calculate calibrated confidence for a model exposing
    predict_proba().

    Decision Tree confidence is based on:

        leaf reliability
        class reliability
        probability reliability
        probability margin
    """

    information = (
        _probability_information(
            model,
            features,
        )
    )

    raw_probability = information[
        "raw_probability"
    ]

    margin = information[
        "margin"
    ]

    predicted_class = information[
        "predicted_class"
    ]

    leaf_id = information[
        "leaf_id"
    ]

    reference = (
        _get_calibration_reference(
            model
        )
    )

    global_accuracy = reference[
        "global_accuracy"
    ]

    # --------------------------------------------------------
    # 1. Class reliability
    # --------------------------------------------------------

    class_stats = reference[
        "class_stats"
    ].get(
        predicted_class
    )

    if class_stats is None:
        class_reliability = (
            global_accuracy
        )

    else:
        class_reliability = (
            _beta_smoothed_rate(
                class_stats["correct"],
                class_stats["total"],
                global_accuracy,
            )
        )

    # --------------------------------------------------------
    # 2. Leaf reliability
    # --------------------------------------------------------

    leaf_reliability = (
        global_accuracy
    )

    leaf_support = 0

    if leaf_id is not None:
        leaf_stats = reference[
            "leaf_stats"
        ].get(
            int(leaf_id)
        )

        if leaf_stats is not None:
            leaf_support = int(
                leaf_stats["total"]
            )

            leaf_reliability = (
                _beta_smoothed_rate(
                    leaf_stats["correct"],
                    leaf_stats["total"],
                    class_reliability,
                )
            )

    # --------------------------------------------------------
    # 3. Raw-probability reliability
    # --------------------------------------------------------

    probability_reliability = (
        _probability_reliability(
            raw_probability,
            reference,
        )
    )

    # --------------------------------------------------------
    # 4. Margin signal
    #
    # Margin itself is not treated as a probability.
    # It only moves the class reliability upward
    # conservatively when the top class is clearly separated.
    # --------------------------------------------------------

    margin_signal = (
        class_reliability
        + (
            0.5
            * margin
            * (
                1.0
                - class_reliability
            )
        )
    )

    # --------------------------------------------------------
    # 5. Weighted calibration
    # --------------------------------------------------------

    confidence = (
        LEAF_WEIGHT
        * leaf_reliability
        +
        CLASS_WEIGHT
        * class_reliability
        +
        RAW_WEIGHT
        * probability_reliability
        +
        MARGIN_WEIGHT
        * margin_signal
    )

    # --------------------------------------------------------
    # 6. Unseen leaf handling
    #
    # If KDDTest+ never reached this leaf, do not pretend
    # that leaf has empirical calibration evidence.
    # --------------------------------------------------------

    if (
        leaf_id is None
        or leaf_support == 0
    ):
        confidence = (
            0.70
            * class_reliability
            +
            0.20
            * probability_reliability
            +
            0.10
            * margin_signal
        )

    # --------------------------------------------------------
    # 7. Final safety bounds
    # --------------------------------------------------------

    confidence = float(
        np.clip(
            confidence,
            MIN_CONFIDENCE,
            MAX_CONFIDENCE,
        )
    )

    return _clip_confidence(
        confidence
    )


# ============================================================
# SVM fallback
# ============================================================

def _calculate_decision_function_confidence(
    model,
    features,
):
    """
    Calculate a probability-like confidence for models exposing
    decision_function() but not predict_proba().

    This preserves compatibility with the existing SVM path.
    """

    scores = model.decision_function(
        features
    )

    scores = np.asarray(
        scores,
        dtype=float,
    )

    if scores.ndim == 0:
        value = float(scores)

        scores = np.asarray(
            [
                -value,
                value,
            ]
        )

    elif scores.ndim == 2:
        if scores.shape[0] == 0:
            raise ValueError(
                "Model returned no decision scores."
            )

        scores = scores[0]

    elif scores.ndim != 1:
        raise ValueError(
            "Unexpected decision-function shape: "
            f"{scores.shape}"
        )

    if scores.size == 1:
        value = float(scores[0])

        scores = np.asarray(
            [
                -value,
                value,
            ]
        )

    if not np.all(
        np.isfinite(scores)
    ):
        raise ValueError(
            "Model returned non-finite decision scores."
        )

    # Stable softmax.
    shifted = (
        scores
        - np.max(scores)
    )

    exponentials = np.exp(
        shifted
    )

    probabilities = (
        exponentials
        / np.sum(exponentials)
    )

    return _clip_confidence(
        np.max(probabilities)
    )


# ============================================================
# Public NTCF API
# ============================================================

def calculate_confidence(
    model,
    features,
):
    """
    Calculate calibrated confidence for NTCF.

    Parameters
    ----------
    model:
        Existing trained NTCF model.

    features:
        Features already processed by the NTCF preprocessing
        service.

    Returns
    -------
    float
        Confidence in the range 0.01 - 0.99.

    Existing API preserved:

        calculate_confidence(model, features)

    Decision Tree path:

        predict_proba()
            |
            +-- raw probability
            +-- margin
            |
        apply()
            |
            +-- leaf reliability
            |
        predicted class
            |
            +-- class reliability
            |
            v
        calibrated confidence

    Failure behavior
    ----------------
    Calibration failure never produces confidence=1.0.

    The function falls back to a conservative probability-based
    estimate and ultimately to MIN_CONFIDENCE if necessary.
    """

    if model is None:
        return MIN_CONFIDENCE

    # --------------------------------------------------------
    # Preferred path:
    #
    # Decision Tree / models exposing predict_proba()
    # --------------------------------------------------------

    if hasattr(
        model,
        "predict_proba",
    ):
        try:
            return _calculate_probability_confidence(
                model,
                features,
            )

        except Exception as error:
            warnings.warn(
                "Calibrated probability confidence "
                "calculation failed: "
                f"{error}. "
                "Falling back to conservative raw probability.",
                RuntimeWarning,
            )

            try:
                information = (
                    _probability_information(
                        model,
                        features,
                    )
                )

                raw_probability = (
                    information[
                        "raw_probability"
                    ]
                )

                # Never expose raw tree probability directly.
                #
                # Even a raw probability of 1.0 is shrunk toward
                # a neutral estimate.
                conservative = (
                    0.60
                    * raw_probability
                    +
                    0.40
                    * 0.50
                )

                return _clip_confidence(
                    conservative
                )

            except Exception:
                pass

    # --------------------------------------------------------
    # SVM compatibility
    # --------------------------------------------------------

    if hasattr(
        model,
        "decision_function",
    ):
        try:
            return (
                _calculate_decision_function_confidence(
                    model,
                    features,
                )
            )

        except Exception as error:
            warnings.warn(
                "decision_function() confidence "
                f"calculation failed: {error}",
                RuntimeWarning,
            )

    # --------------------------------------------------------
    # Safe final fallback
    # --------------------------------------------------------

    return MIN_CONFIDENCE


# ============================================================
# Optional cache reset
# ============================================================

def clear_calibration_cache():
    """
    Clear the in-memory calibration cache.

    Useful during development/testing when:

        - the model instance changes
        - KDDTest+ changes
        - preprocessing artifacts change

    This does NOT modify any model or preprocessing artifact.
    """

    _CALIBRATION_CACHE.clear()