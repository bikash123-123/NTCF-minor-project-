"""
flow_feature_extractor.py

Convert parsed packets into flow-level features for the
Network Threat Cognition Framework (NTCF).

This module groups packets into network flows and calculates
flow statistics that can later be passed to the preprocessing
pipeline before ML inference.
"""

from collections import defaultdict

import pandas as pd


def extract_flow_features(parsed_packets):
    """
    Convert parsed packets into flow-level features.

    Parameters
    ----------
    parsed_packets : list
        List of packet dictionaries returned by packet_parser.py.

    Returns
    -------
    pandas.DataFrame
        DataFrame containing one row per flow.
    """

    flows = defaultdict(list)

    # ---------------------------------------------------------
    # Group packets by flow
    # ---------------------------------------------------------

    for packet in parsed_packets:

        flow_key = (
            packet["src_ip"],
            packet["dst_ip"],
            packet["src_port"],
            packet["dst_port"],
            packet["protocol"],
        )

        flows[flow_key].append(packet)

    flow_features = []

    # ---------------------------------------------------------
    # Calculate statistics for each flow
    # ---------------------------------------------------------

    for _, packets in flows.items():

        packets = sorted(
            packets,
            key=lambda packet: packet["timestamp"],
        )

        first_packet = packets[0]
        last_packet = packets[-1]

        # -----------------------------------------------------
        # Basic flow information
        # -----------------------------------------------------

        duration = (
            last_packet["timestamp"]
            - first_packet["timestamp"]
        )

        packet_count = len(packets)

        total_bytes = sum(
            packet["packet_length"]
            for packet in packets
        )

        avg_packet_size = (
            total_bytes / packet_count
            if packet_count > 0
            else 0
        )

        # -----------------------------------------------------
        # Rate calculations
        # -----------------------------------------------------

        if duration > 0:

            packet_rate = (
                packet_count / duration
            )

            byte_rate = (
                total_bytes / duration
            )

        else:

            packet_rate = 0

            byte_rate = 0

        # -----------------------------------------------------
        # Preserve service and TCP flag information
        #
        # These values are already produced by packet_parser /
        # live_capture, so we should not discard them here.
        # -----------------------------------------------------

        service = first_packet.get(
            "service",
            "unknown",
        )

        flag = first_packet.get(
            "flag",
            "OTH",
        )

        # -----------------------------------------------------
        # Build flow record
        # -----------------------------------------------------

        flow_features.append(
            {
                "src_ip": first_packet["src_ip"],

                "dst_ip": first_packet["dst_ip"],

                "src_port": first_packet["src_port"],

                "dst_port": first_packet["dst_port"],

                "protocol": first_packet["protocol"],

                "service": service,

                "flag": flag,

                "flow_duration": duration,

                "packet_count": packet_count,

                "total_bytes": total_bytes,

                "avg_packet_size": avg_packet_size,

                "packet_rate": packet_rate,

                "byte_rate": byte_rate,
            }
        )

    return pd.DataFrame(flow_features)


# -----------------------------------------------------------------
# Manual execution
# -----------------------------------------------------------------

if __name__ == "__main__":

    from packet_capture.live_capture import capture_packets

    print("\nCapturing packets...\n")

    packets = capture_packets(
        packet_count=10
    )

    print(
        f"Packets Captured: {len(packets)}"
    )

    print(
        "\nExtracting flow features...\n"
    )

    features = extract_flow_features(
        packets
    )

    print(
        "\nNumber of Flows:",
        len(features),
    )

    print(
        "\nExtracted Flow Features:\n"
    )

    print(
        features.to_string(
            index=False
        )
    )

    print(
        "\nExtraction Complete."
    )