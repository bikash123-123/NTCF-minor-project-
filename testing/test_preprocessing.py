import unittest
import pandas as pd

from ml.preprocessing.data_loader import load_dataset


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


if __name__ == "__main__":
    unittest.main()