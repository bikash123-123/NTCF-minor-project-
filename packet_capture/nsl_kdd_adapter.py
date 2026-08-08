"""
nsl_kdd_adapter.py

Adapts live flow-level features into the 41-column
raw NSL-KDD feature schema expected by the NTCF
preprocessing pipeline.

This adapter maps values that can be derived from the
current live flow extractor and uses documented defaults
for NSL-KDD fields that are not currently available.
"""

import pandas as pd

from ml.config.columns import FEATURE_COLUMNS


# ---------------------------------------------------------------------
# Values that cannot currently be derived from the live extractor
# ---------------------------------------------------------------------

UNSUPPORTED_DEFAULTS = {
    "service": "unknown",
    "flag": "OTH",

    "land": 0,
    "wrong_fragment": 0,
    "urgent": 0,

    "hot": 0,
    "num_failed_logins": 0,
    "logged_in": 0,
    "num_compromised": 0,
    "root_shell": 0,
    "su_attempted": 0,
    "num_root": 0,
    "num_file_creations": 0,
    "num_shells": 0,
    "num_access_files": 0,
    "num_outbound_cmds": 0,
    "is_host_login": 0,
    "is_guest_login": 0,

    "count": 0,
    "srv_count": 0,
    "serror_rate": 0.0,
    "srv_serror_rate": 0.0,
    "rerror_rate": 0.0,
    "srv_rerror_rate": 0.0,
    "same_srv_rate": 0.0,
    "diff_srv_rate": 0.0,
    "srv_diff_host_rate": 0.0,

    "dst_host_count": 0,
    "dst_host_srv_count": 0,
    "dst_host_same_srv_rate": 0.0,
    "dst_host_diff_srv_rate": 0.0,
    "dst_host_same_src_port_rate": 0.0,
    "dst_host_srv_diff_host_rate": 0.0,
    "dst_host_serror_rate": 0.0,
    "dst_host_srv_serror_rate": 0.0,
    "dst_host_rerror_rate": 0.0,
    "dst_host_srv_rerror_rate": 0.0,
}


def adapt_flow_to_nsl_kdd(flow):
    """
    Convert one live flow into the 41-column raw
    NSL-KDD feature schema.

    Parameters
    ----------
    flow : dict or pandas.Series
        One row produced by flow_feature_extractor.py.

    Returns
    -------
    dict
        Exactly the FEATURE_COLUMNS schema.
    """

    if isinstance(flow, pd.Series):
        flow = flow.to_dict()

    if not isinstance(flow, dict):
        raise TypeError(
            "flow must be a dictionary or pandas Series."
        )

    features = {}

    # -------------------------------------------------------------
    # Directly mappable fields
    # -------------------------------------------------------------

    features["duration"] = flow.get(
        "flow_duration",
        0,
    )

    features["protocol_type"] = str(
        flow.get(
            "protocol",
            "unknown",
        )
    ).lower()

    features["src_bytes"] = flow.get(
        "total_bytes",
        0,
    )

    # The current flow extractor does not distinguish
    # source and destination byte counts.
    features["dst_bytes"] = 0

    # -------------------------------------------------------------
    # Fields that can be approximated from current flow statistics
    # -------------------------------------------------------------

    # NSL-KDD count represents a connection/traffic count.
    # For the current one-row-per-flow representation,
    # packet_count is the closest available value.
    features["count"] = flow.get(
        "packet_count",
        0,
    )

    features["srv_count"] = flow.get(
        "packet_count",
        0,
    )

    # -------------------------------------------------------------
    # Unsupported fields
    # -------------------------------------------------------------

    for column, default in UNSUPPORTED_DEFAULTS.items():

        # Preserve explicitly mapped values above.
        if column not in features:
            features[column] = default

    # -------------------------------------------------------------
    # Validate centralized schema
    # -------------------------------------------------------------

    missing = [
        column
        for column in FEATURE_COLUMNS
        if column not in features
    ]

    if missing:
        raise ValueError(
            "Adapter failed to create required features: "
            + ", ".join(missing)
        )

    # Return ONLY the centralized 41-column schema.
    return {
        column: features[column]
        for column in FEATURE_COLUMNS
    }


def adapt_flow_dataframe(flow_dataframe):
    """
    Convert a flow DataFrame into the raw NSL-KDD
    feature DataFrame.

    Parameters
    ----------
    flow_dataframe : pandas.DataFrame

    Returns
    -------
    pandas.DataFrame
        DataFrame with exactly 41 NSL-KDD columns.
    """

    if not isinstance(
        flow_dataframe,
        pd.DataFrame,
    ):
        raise TypeError(
            "flow_dataframe must be a pandas DataFrame."
        )

    adapted_rows = [
        adapt_flow_to_nsl_kdd(row)
        for _, row in flow_dataframe.iterrows()
    ]

    return pd.DataFrame(
        adapted_rows,
        columns=FEATURE_COLUMNS,
    )