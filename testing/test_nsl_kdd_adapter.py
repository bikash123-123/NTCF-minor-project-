import pandas as pd

from ml.config.columns import FEATURE_COLUMNS

from packet_capture.nsl_kdd_adapter import (
    adapt_flow_to_nsl_kdd,
    adapt_flow_dataframe,
)


def test_adapt_flow_to_nsl_kdd_returns_all_features():

    flow = {
        "flow_duration": 10,
        "packet_count": 5,
        "total_bytes": 500,
        "avg_packet_size": 100,
        "packet_rate": 0.5,
        "byte_rate": 50,
        "protocol": "TCP",
    }

    result = adapt_flow_to_nsl_kdd(flow)

    assert isinstance(result, dict)
    assert len(result) == 41
    assert list(result.keys()) == FEATURE_COLUMNS


def test_adapt_flow_maps_available_values():

    flow = {
        "flow_duration": 10,
        "packet_count": 5,
        "total_bytes": 500,
        "avg_packet_size": 100,
        "packet_rate": 0.5,
        "byte_rate": 50,
        "protocol": "TCP",
    }

    result = adapt_flow_to_nsl_kdd(flow)

    assert result["duration"] == 10
    assert result["src_bytes"] == 500
    assert result["protocol_type"] == "tcp"


def test_adapt_flow_dataframe_returns_41_columns():

    flow = pd.DataFrame(
        [
            {
                "flow_duration": 10,
                "packet_count": 5,
                "total_bytes": 500,
                "avg_packet_size": 100,
                "packet_rate": 0.5,
                "byte_rate": 50,
                "protocol": "TCP",
            }
        ]
    )

    result = adapt_flow_dataframe(flow)

    assert result.shape == (1, 41)
    assert list(result.columns) == FEATURE_COLUMNS