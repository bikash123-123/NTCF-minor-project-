"""
train_models.py

Reusable model training pipeline for the
Network Threat Cognition Framework (NTCF).

Connects preprocessing, feature selection, model training,
and model artifact saving into a single reusable workflow:

    raw data -> preprocessing -> feature selection
             -> model training -> evaluation -> artifact saving

Models are trained through a small registry so the pipeline stays
reusable as new models are added: any module under ml/models/ that
exposes the standard model interface (create_model, train_model,
predict, evaluate_model, save_model) is picked up automatically.
Modules that have not been implemented yet are skipped with a
warning instead of breaking the pipeline.
"""

from ml.feature_selection.feature_selection import load_selected_features
from ml.models import decision_tree_model, random_forest_model, svm_model
from ml.preprocessing.preprocessing_pipeline import preprocess_dataset
from ml.training.save_models import (
    save_evaluation_results,
    save_trained_model,
    save_training_manifest,
)

# ---------------------------------------------------------------------
# Reproducibility configuration
#
# These values are fixed and threaded through preprocessing, the
# train/test split, and every model so a training run can be
# reproduced exactly.
# ---------------------------------------------------------------------

RANDOM_STATE = 42
TEST_SIZE = 0.2

# ---------------------------------------------------------------------
# Model registry
# ---------------------------------------------------------------------

MODEL_REGISTRY = {
    "random_forest": random_forest_model,
    "decision_tree": decision_tree_model,
    "svm": svm_model,
}

REQUIRED_MODEL_INTERFACE = (
    "create_model",
    "train_model",
    "predict",
    "evaluate_model",
    "save_model",
)


def get_configured_models(registry=None):
    """
    Filter the model registry down to modules that implement the
    full model interface, so unfinished model files don't break
    the pipeline.

    Parameters
    ----------
    registry : dict, optional
        Mapping of model name -> model module. Defaults to
        MODEL_REGISTRY.

    Returns
    -------
    dict
        Mapping of model name -> model module, for models that are
        ready to train.
    """

    if registry is None:
        registry = MODEL_REGISTRY

    configured = {}

    for name, module in registry.items():
        if all(hasattr(module, fn) for fn in REQUIRED_MODEL_INTERFACE):
            configured[name] = module
        else:
            print(
                f"[train_models] Skipping '{name}': "
                "model interface not implemented yet."
            )

    return configured


def apply_selected_features(X_train, X_test):
    """
    Restrict the processed feature matrices to the features chosen
    during feature selection, so training and inference always use
    the exact same columns in the exact same order.

    Parameters
    ----------
    X_train : pandas.DataFrame
    X_test : pandas.DataFrame

    Returns
    -------
    tuple
        (X_train_selected, X_test_selected, selected_features)
    """

    selected_features = load_selected_features()

    missing = [
        feature
        for feature in selected_features
        if feature not in X_train.columns
    ]

    if missing:
        raise ValueError(
            "Selected features missing from processed data: "
            f"{missing}"
        )

    return (
        X_train[selected_features],
        X_test[selected_features],
        selected_features,
    )


def train_configured_models(
    file_path=None,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    registry=None,
):
    """
    Run the full reusable training workflow.

    Parameters
    ----------
    file_path : str or Path, optional
        Dataset to train on. Defaults to the standard NSL-KDD
        training set (see ml.preprocessing.data_loader).

    test_size : float
        Fraction of data reserved for testing.

    random_state : int
        Fixed seed used for the train/test split and for every
        configured model, for reproducibility.

    registry : dict, optional
        Mapping of model name -> model module. Defaults to
        MODEL_REGISTRY.

    Returns
    -------
    dict
        Results keyed by model name, each containing the trained
        model instance and its evaluation metrics.
    """

    # -------------------------------------------------
    # Preprocessing
    # (also fits and saves the encoder + scaler artifacts)
    # -------------------------------------------------

    (
        X_train,
        X_test,
        y_train,
        y_test,
        encoder,
        scaler,
    ) = preprocess_dataset(
        file_path=file_path,
        test_size=test_size,
        random_state=random_state,
    )

    # -------------------------------------------------
    # Feature selection
    # -------------------------------------------------

    X_train, X_test, selected_features = apply_selected_features(
        X_train,
        X_test,
    )

    # -------------------------------------------------
    # Determine which models are ready to train
    # -------------------------------------------------

    configured_models = get_configured_models(registry)

    if not configured_models:
        raise RuntimeError(
            "No configured models available to train. Implement at "
            "least one model module under ml/models/ before running "
            "the training pipeline."
        )

    # -------------------------------------------------
    # Train, evaluate, and save each configured model
    # -------------------------------------------------

    results = {}

    for name, module in configured_models.items():
        print(f"[train_models] Training '{name}'...")

        model = module.create_model()
        model = module.train_model(model, X_train, y_train)

        predictions = module.predict(model, X_test)
        metrics = module.evaluate_model(y_test, predictions)

        save_trained_model(module, model, name)

        results[name] = {
            "model": model,
            "metrics": metrics,
        }

        print(
            f"[train_models] '{name}' accuracy: "
            f"{metrics['accuracy']:.4f}"
        )

    # -------------------------------------------------
    # Save evaluation results and a reproducibility manifest
    # -------------------------------------------------

    save_evaluation_results(results)

    save_training_manifest(
        model_names=list(configured_models.keys()),
        selected_features=selected_features,
        random_state=random_state,
        test_size=test_size,
    )

    return results


if __name__ == "__main__":

    train_configured_models()

    print("Training pipeline completed successfully.")
