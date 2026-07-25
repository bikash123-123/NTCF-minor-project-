"""
save_models.py

Reusable utilities for persisting trained model artifacts,
evaluation results, and training run metadata for the
Network Threat Cognition Framework (NTCF).

Keeping this separate from train_models.py means any future
training entry point (a script, a notebook, an API endpoint)
can reuse the exact same saving conventions.
"""

import json
import platform
from datetime import datetime, timezone
from pathlib import Path

import sklearn

ARTIFACTS_DIR = Path("ml/artifacts")


def save_trained_model(module, model, model_name, artifacts_dir=ARTIFACTS_DIR):
    """
    Save a trained model using its own module's save_model function.

    Artifacts are always written as ``<model_name>_model.pkl`` so
    saved files stay consistent regardless of a model module's own
    default path, and so they can be located deterministically
    during inference.

    Parameters
    ----------
    module : module
        The model module (e.g. ml.models.svm_model). Must expose
        a save_model(model, file_path=...) function.

    model : object
        The trained model instance.

    model_name : str
        Registry name for the model, e.g. "svm".

    artifacts_dir : str or Path
        Directory where model artifacts are stored.

    Returns
    -------
    Path
        Path the model was saved to.
    """

    artifacts_dir = Path(artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    file_path = artifacts_dir / f"{model_name}_model.pkl"

    module.save_model(model, file_path=str(file_path))

    return file_path


def load_trained_model(module, model_name, artifacts_dir=ARTIFACTS_DIR):
    """
    Load a previously trained model using its own module's
    load_model function.

    Parameters
    ----------
    module : module
        The model module (e.g. ml.models.svm_model). Must expose
        a load_model(file_path=...) function.

    model_name : str
        Registry name for the model, e.g. "svm".

    artifacts_dir : str or Path
        Directory where model artifacts are stored.

    Returns
    -------
    object
        The loaded model instance.
    """

    artifacts_dir = Path(artifacts_dir)
    file_path = artifacts_dir / f"{model_name}_model.pkl"

    if not file_path.exists():
        raise FileNotFoundError(
            f"No saved artifact found for '{model_name}' at {file_path}"
        )

    return module.load_model(file_path=str(file_path))


def save_evaluation_results(
    results,
    file_path=ARTIFACTS_DIR / "evaluation_results.json",
):
    """
    Save evaluation metrics for every trained model in a single
    file, so results from a training run can be reviewed or
    compared later without re-running training.

    Parameters
    ----------
    results : dict
        Mapping of model name -> {"model": ..., "metrics": ...},
        as produced by train_configured_models.

    file_path : str or Path
        Destination path.

    Returns
    -------
    Path
        Path the evaluation results were saved to.
    """

    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    serializable_results = {
        name: data["metrics"]
        for name, data in results.items()
    }

    with open(file_path, "w") as file:
        json.dump(serializable_results, file, indent=4)

    return file_path


def save_training_manifest(
    model_names,
    selected_features,
    random_state,
    test_size,
    file_path=ARTIFACTS_DIR / "training_manifest.json",
):
    """
    Save reproducibility metadata describing exactly how a set of
    models was trained: which models, which features, which split,
    and which seed. This lets a training run be audited or
    reproduced later, and lets inference code confirm it is using
    artifacts trained on a compatible feature set.

    Parameters
    ----------
    model_names : list of str
        Names of the models trained in this run.

    selected_features : list of str
        Feature columns used for training, in order.

    random_state : int
        Random seed used for the train/test split and models.

    test_size : float
        Fraction of data reserved for testing.

    file_path : str or Path
        Destination path.

    Returns
    -------
    Path
        Path the manifest was saved to.
    """

    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    manifest = {
        "trained_models": model_names,
        "selected_features": selected_features,
        "random_state": random_state,
        "test_size": test_size,
        "sklearn_version": sklearn.__version__,
        "python_version": platform.python_version(),
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }

    with open(file_path, "w") as file:
        json.dump(manifest, file, indent=4)

    return file_path
