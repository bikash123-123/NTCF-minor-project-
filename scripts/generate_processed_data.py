"""
Generate processed datasets for model training.

This script runs the complete preprocessing pipeline and saves
the processed train and test datasets to data/processed/.
"""

from pathlib import Path
import pandas as pd
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ml.preprocessing.preprocessing_pipeline import preprocess_dataset
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

def main():
    """
    Generate processed datasets.
    """

    # Run preprocessing pipeline
    X_train, X_test, y_train, y_test, encoder, scaler = preprocess_dataset()

    # Combine features and labels
    train_df = X_train.copy()
    train_df["label"] = y_train.values

    test_df = X_test.copy()
    test_df["label"] = y_test.values

    # Output directory
    output_dir = Path("data/processed")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save datasets
    train_df.to_csv(
        output_dir / "train_processed.csv",
        index=False
    )

    test_df.to_csv(
        output_dir / "test_processed.csv",
        index=False
    )

    print("Processed datasets generated successfully!")
    print(f"Saved to: {output_dir.resolve()}")


if __name__ == "__main__":
    main()