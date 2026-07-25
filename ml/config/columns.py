"""
columns.py

Centralized column definitions for the NSL-KDD dataset.

This module defines all dataset columns used throughout the
Network Threat Cognition Framework (NTCF). The configuration
is shared across preprocessing, feature selection, model
training, and inference modules.
"""

# ---------------------------------------------------------------------
# Dataset Columns
# ---------------------------------------------------------------------

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

# ---------------------------------------------------------------------
# Target Column
# ---------------------------------------------------------------------

TARGET_COLUMN = "label"

# ---------------------------------------------------------------------
# Feature Columns
# ---------------------------------------------------------------------

FEATURE_COLUMNS = [
    column
    for column in ALL_COLUMNS
    if column not in ["label", "difficulty"]
]

# ---------------------------------------------------------------------
# Categorical Columns
# ---------------------------------------------------------------------

CATEGORICAL_COLUMNS = [
    "protocol_type",
    "service",
    "flag",
]

# ---------------------------------------------------------------------
# Numerical Columns
# ---------------------------------------------------------------------

NUMERICAL_COLUMNS = [
    column
    for column in FEATURE_COLUMNS
    if column not in CATEGORICAL_COLUMNS
]

# ---------------------------------------------------------------------
# Selected Features
# ---------------------------------------------------------------------

SELECTED_FEATURES = FEATURE_COLUMNS.copy()

# ---------------------------------------------------------------------
# Excluded Columns
# ---------------------------------------------------------------------

EXCLUDED_COLUMNS = [
    TARGET_COLUMN,
    "difficulty",
]