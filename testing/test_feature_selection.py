"""
Automated tests for NTCF feature selection.

Issue #30
"""

import json

import pandas as pd
import pytest

from ml.config.columns import (
    FEATURE_COLUMNS,
    TARGET_COLUMN,
)

from ml.feature_selection.feature_selection import (
    compute_feature_importance,
    load_selected_features,
    save_selected_features,
    select_top_features,
)


class TestFeatureImportance:
    """Tests for feature importance calculation."""

    def test_compute_feature_importance_returns_dataframe(self):
        """Feature importance should return a DataFrame."""

        X = pd.DataFrame(
            {
                "feature_a": [1, 2, 3, 4, 5, 6],
                "feature_b": [6, 5, 4, 3, 2, 1],
                "feature_c": [1, 1, 2, 2, 3, 3],
            }
        )

        y = pd.Series(
            [0, 0, 0, 1, 1, 1]
        )

        result = compute_feature_importance(X, y)

        assert isinstance(result, pd.DataFrame)

    def test_feature_importance_contains_required_columns(self):
        """Result should contain feature and importance columns."""

        X = pd.DataFrame(
            {
                "feature_a": [1, 2, 3, 4],
                "feature_b": [4, 3, 2, 1],
            }
        )

        y = pd.Series([0, 0, 1, 1])

        result = compute_feature_importance(X, y)

        assert "feature" in result.columns
        assert "importance" in result.columns

    def test_feature_importance_contains_all_input_features(self):
        """Every input feature should appear in the result."""

        X = pd.DataFrame(
            {
                "feature_a": [1, 2, 3, 4],
                "feature_b": [4, 3, 2, 1],
                "feature_c": [1, 2, 1, 2],
            }
        )

        y = pd.Series([0, 0, 1, 1])

        result = compute_feature_importance(X, y)

        assert set(result["feature"]) == set(X.columns)

    def test_feature_importance_is_sorted_descending(self):
        """Feature importance should be sorted highest first."""

        X = pd.DataFrame(
            {
                "feature_a": [1, 2, 3, 4, 5, 6],
                "feature_b": [6, 5, 4, 3, 2, 1],
                "feature_c": [1, 1, 1, 2, 2, 2],
            }
        )

        y = pd.Series([0, 0, 0, 1, 1, 1])

        result = compute_feature_importance(X, y)

        importance_values = result["importance"].tolist()

        assert importance_values == sorted(
            importance_values,
            reverse=True,
        )

    def test_feature_importance_values_are_non_negative(self):
        """Random Forest importance values cannot be negative."""

        X = pd.DataFrame(
            {
                "feature_a": [1, 2, 3, 4],
                "feature_b": [4, 3, 2, 1],
            }
        )

        y = pd.Series([0, 0, 1, 1])

        result = compute_feature_importance(X, y)

        assert (result["importance"] >= 0).all()


class TestSelectTopFeatures:
    """Tests for selecting the most important features."""

    def test_select_top_features_returns_list(self):
        """Selected features should be returned as a list."""

        feature_importance = pd.DataFrame(
            {
                "feature": [
                    "feature_a",
                    "feature_b",
                    "feature_c",
                ],
                "importance": [
                    0.8,
                    0.15,
                    0.05,
                ],
            }
        )

        result = select_top_features(
            feature_importance,
            top_n=2,
        )

        assert isinstance(result, list)

    def test_select_top_features_returns_requested_count(self):
        """The requested number of features should be returned."""

        feature_importance = pd.DataFrame(
            {
                "feature": [
                    "feature_a",
                    "feature_b",
                    "feature_c",
                    "feature_d",
                ],
                "importance": [
                    0.4,
                    0.3,
                    0.2,
                    0.1,
                ],
            }
        )

        result = select_top_features(
            feature_importance,
            top_n=3,
        )

        assert len(result) == 3

    def test_select_top_features_preserves_importance_order(self):
        """Features should retain their importance ranking."""

        feature_importance = pd.DataFrame(
            {
                "feature": [
                    "feature_a",
                    "feature_b",
                    "feature_c",
                ],
                "importance": [
                    0.8,
                    0.15,
                    0.05,
                ],
            }
        )

        result = select_top_features(
            feature_importance,
            top_n=2,
        )

        assert result == [
            "feature_a",
            "feature_b",
        ]

    def test_select_all_features(self):
        """Selecting more than available features should return all."""

        feature_importance = pd.DataFrame(
            {
                "feature": [
                    "feature_a",
                    "feature_b",
                ],
                "importance": [
                    0.7,
                    0.3,
                ],
            }
        )

        result = select_top_features(
            feature_importance,
            top_n=20,
        )

        assert result == [
            "feature_a",
            "feature_b",
        ]

    def test_select_zero_features(self):
        """Requesting zero features should return an empty list."""

        feature_importance = pd.DataFrame(
            {
                "feature": [
                    "feature_a",
                    "feature_b",
                ],
                "importance": [
                    0.7,
                    0.3,
                ],
            }
        )

        result = select_top_features(
            feature_importance,
            top_n=0,
        )

        assert result == []


class TestSelectedFeaturePersistence:
    """Tests for saving and loading selected features."""

    def test_save_selected_features(self, tmp_path):
        """Selected features should be saved successfully."""

        features = [
            "src_bytes",
            "dst_bytes",
            "count",
        ]

        file_path = (
            tmp_path / "selected_features.json"
        )

        save_selected_features(
            features,
            file_path,
        )

        assert file_path.exists()

    def test_saved_file_contains_json_list(self, tmp_path):
        """Saved feature file should contain a JSON list."""

        features = [
            "src_bytes",
            "dst_bytes",
            "count",
        ]

        file_path = (
            tmp_path / "selected_features.json"
        )

        save_selected_features(
            features,
            file_path,
        )

        with open(file_path, "r") as file:
            saved_data = json.load(file)

        assert isinstance(saved_data, list)
        assert saved_data == features

    def test_load_selected_features(self, tmp_path):
        """Saved features should be loaded correctly."""

        features = [
            "src_bytes",
            "dst_bytes",
            "count",
        ]

        file_path = (
            tmp_path / "selected_features.json"
        )

        save_selected_features(
            features,
            file_path,
        )

        result = load_selected_features(
            file_path,
        )

        assert result == features

    def test_save_and_load_preserves_feature_order(
        self,
        tmp_path,
    ):
        """Feature order should remain unchanged."""

        features = [
            "dst_bytes",
            "src_bytes",
            "count",
            "srv_count",
        ]

        file_path = (
            tmp_path / "selected_features.json"
        )

        save_selected_features(
            features,
            file_path,
        )

        result = load_selected_features(
            file_path,
        )

        assert result == features

    def test_missing_feature_file_raises_error(
        self,
        tmp_path,
    ):
        """Loading a missing feature file should fail clearly."""

        file_path = (
            tmp_path / "does_not_exist.json"
        )

        with pytest.raises(FileNotFoundError):
            load_selected_features(file_path)


class TestNTCFFeatureConfiguration:
    """Tests for the centralized NTCF feature configuration."""

    def test_target_column_is_not_a_feature(self):
        """The target column must not be used as an input feature."""

        assert TARGET_COLUMN not in FEATURE_COLUMNS

    def test_feature_columns_are_not_empty(self):
        """The NTCF feature list must contain features."""

        assert len(FEATURE_COLUMNS) > 0

    def test_feature_columns_are_unique(self):
        """Feature names should not be duplicated."""

        assert len(FEATURE_COLUMNS) == len(
            set(FEATURE_COLUMNS)
        )

    def test_feature_columns_are_strings(self):
        """Every feature name should be a string."""

        assert all(
            isinstance(feature, str)
            for feature in FEATURE_COLUMNS
        )