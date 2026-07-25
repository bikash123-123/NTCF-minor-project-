import os
import tempfile
import unittest
from sklearn.preprocessing import StandardScaler

from ml.preprocessing.scaler import (
    fit_scaler,
    transform_features as transform_scaled_features,
    save_scaler,
    load_scaler,
)
from ml.feature_selection.feature_selection import (
    compute_feature_importance,
    select_top_features,
    save_selected_features,
    load_selected_features,
)
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from ml.preprocessing.preprocessing_pipeline import preprocess_dataset

import pandas as pd
from sklearn.preprocessing import OneHotEncoder

from ml.preprocessing.data_loader import load_dataset
from ml.preprocessing.encoder import (
    fit_encoder,
    transform_features,
    save_encoder,
    load_encoder,
)


class TestDataLoader(unittest.TestCase):
    """Unit tests for the dataset loading module."""

    def test_load_default_dataset(self):
        """Test loading the default training dataset."""
        dataset = load_dataset()

        self.assertIsInstance(dataset, pd.DataFrame)
        self.assertFalse(dataset.empty)
        self.assertEqual(dataset.shape[1], 43)

    def test_load_test_dataset(self):
        """Test loading the test dataset."""
        dataset = load_dataset("data/raw/KDDTest+.txt")

        self.assertIsInstance(dataset, pd.DataFrame)
        self.assertFalse(dataset.empty)
        self.assertEqual(dataset.shape[1], 43)

    def test_missing_file(self):
        """Test loading a file that does not exist."""
        with self.assertRaises(FileNotFoundError):
            load_dataset("data/raw/does_not_exist.txt")

    def test_empty_path(self):
        """Test an empty dataset path."""
        with self.assertRaises(ValueError):
            load_dataset("")

    def test_invalid_directory(self):
        """Test passing a directory instead of a file."""
        with self.assertRaises(ValueError):
            load_dataset("data/raw")


class TestEncoder(unittest.TestCase):
    """Unit tests for the encoder module."""

    @classmethod
    def setUpClass(cls):
        """Load the dataset once for all encoder tests."""
        cls.df = load_dataset()

    def test_fit_encoder(self):
        """Test fitting the encoder."""

        encoder = fit_encoder(self.df)

        self.assertIsInstance(
            encoder,
            OneHotEncoder
        )

    def test_transform_features(self):
        """Test transforming categorical features."""

        encoder = fit_encoder(self.df)

        encoded_df = transform_features(
            encoder,
            self.df
        )

        self.assertIsInstance(
            encoded_df,
            pd.DataFrame
        )

        self.assertEqual(
            len(encoded_df),
            len(self.df)
        )

        self.assertFalse(encoded_df.empty)

    def test_save_encoder(self):
        """Test saving the encoder."""

        encoder = fit_encoder(self.df)

        with tempfile.TemporaryDirectory() as temp_dir:

            file_path = os.path.join(
                temp_dir,
                "encoder.pkl"
            )

            save_encoder(
                encoder,
                file_path
            )

            self.assertTrue(
                os.path.exists(file_path)
            )

    def test_load_encoder(self):
        """Test loading the encoder."""

        encoder = fit_encoder(self.df)

        with tempfile.TemporaryDirectory() as temp_dir:

            file_path = os.path.join(
                temp_dir,
                "encoder.pkl"
            )

            save_encoder(
                encoder,
                file_path
            )

            loaded_encoder = load_encoder(
                file_path
            )

            self.assertIsInstance(
                loaded_encoder,
                OneHotEncoder
            )

    def test_unseen_categories(self):
        """Test handling unseen categories."""

        encoder = fit_encoder(self.df)

        new_df = self.df.copy()

        new_df.loc[0, "protocol_type"] = "new_protocol"

        encoded_df = transform_features(
            encoder,
            new_df
        )

        self.assertEqual(
            len(encoded_df),
            len(new_df)
        )

        self.assertFalse(encoded_df.empty)

class TestScaler(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.df = load_dataset()

    def test_fit_scaler(self):
        scaler = fit_scaler(self.df)

        self.assertIsInstance(
            scaler,
            StandardScaler
        )

    def test_transform_features(self):
        scaler = fit_scaler(self.df)

        scaled_df = transform_scaled_features(
            scaler,
            self.df
        )

        self.assertIsInstance(
            scaled_df,
            pd.DataFrame
        )

        self.assertEqual(
            len(scaled_df),
            len(self.df)
        )

    def test_save_scaler(self):
        scaler = fit_scaler(self.df)

        with tempfile.TemporaryDirectory() as temp_dir:

            path = os.path.join(
                temp_dir,
                "scaler.pkl"
            )

            save_scaler(
                scaler,
                path
            )

            self.assertTrue(
                os.path.exists(path)
            )

    def test_load_scaler(self):
        scaler = fit_scaler(self.df)

        with tempfile.TemporaryDirectory() as temp_dir:

            path = os.path.join(
                temp_dir,
                "scaler.pkl"
            )

            save_scaler(
                scaler,
                path
            )

            loaded = load_scaler(
                path
            )

            self.assertIsInstance(
                loaded,
                StandardScaler
            )
class TestPreprocessingPipeline(unittest.TestCase):
    """Unit tests for the complete preprocessing pipeline."""

    @classmethod
    def setUpClass(cls):
        (
            cls.X_train,
            cls.X_test,
            cls.y_train,
            cls.y_test,
            cls.encoder,
            cls.scaler,
        ) = preprocess_dataset()

    def test_pipeline_returns_data(self):
        """Pipeline returns processed datasets."""

        self.assertIsInstance(self.X_train, pd.DataFrame)
        self.assertIsInstance(self.X_test, pd.DataFrame)

        self.assertIsInstance(self.y_train, pd.Series)
        self.assertIsInstance(self.y_test, pd.Series)

    def test_train_test_not_empty(self):
        """Training and test datasets should not be empty."""

        self.assertFalse(self.X_train.empty)
        self.assertFalse(self.X_test.empty)

        self.assertGreater(len(self.y_train), 0)
        self.assertGreater(len(self.y_test), 0)

    def test_feature_count_consistency(self):
        """Training and test feature counts must match."""

        self.assertEqual(
            self.X_train.shape[1],
            self.X_test.shape[1]
        )

    def test_target_count_matches_features(self):
        """Number of samples must match targets."""

        self.assertEqual(
            len(self.X_train),
            len(self.y_train)
        )

        self.assertEqual(
            len(self.X_test),
            len(self.y_test)
        )

    def test_encoder_created(self):
        """Pipeline returns a fitted encoder."""

        self.assertIsInstance(
            self.encoder,
            OneHotEncoder
        )

    def test_scaler_created(self):
        """Pipeline returns a fitted scaler."""

        self.assertIsInstance(
            self.scaler,
            StandardScaler
        )
class TestFeatureSelection(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        (
            cls.X_train,
            cls.X_test,
            cls.y_train,
            cls.y_test,
            _,
            _
        ) = preprocess_dataset()

    def test_feature_importance(self):
        importance = compute_feature_importance(
            self.X_train,
            self.y_train
        )

        self.assertIsInstance(
            importance,
            pd.DataFrame
        )

        self.assertFalse(
            importance.empty
        )

    def test_select_top_features(self):
        importance = compute_feature_importance(
            self.X_train,
            self.y_train
        )

        features = select_top_features(
            importance,
            top_n=20
        )

        self.assertEqual(
            len(features),
            20
        )

    def test_save_and_load_selected_features(self):
        importance = compute_feature_importance(
            self.X_train,
            self.y_train
        )

        features = select_top_features(
            importance,
            top_n=20
        )

        import tempfile
        import os

        with tempfile.TemporaryDirectory() as temp_dir:

            path = os.path.join(
                temp_dir,
                "selected_features.json"
            )

            save_selected_features(
                features,
                path
            )

            loaded = load_selected_features(
                path
            )

            self.assertEqual(
                features,
                loaded
            )
if __name__ == "__main__":
    unittest.main()