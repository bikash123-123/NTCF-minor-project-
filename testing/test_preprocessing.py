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
if __name__ == "__main__":
    unittest.main()