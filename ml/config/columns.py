"""
columns.py

Configuration for dataset column names used throughout the
Network Threat Cognition Framework (NTCF) preprocessing pipeline.
"""

# Categorical features that require encoding
CATEGORICAL_COLUMNS = [
    "protocol_type",
    "service",
    "flag",
]

# Target column
TARGET_COLUMN = "label"

# Columns that should not be encoded
EXCLUDED_COLUMNS = [
    TARGET_COLUMN,
    "difficulty",
]