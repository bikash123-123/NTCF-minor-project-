"""
ntcf_pipeline.py

Main runtime pipeline for the Network Threat Cognition
Framework (NTCF).

Pipeline:

Live Packet Capture
↓
Flow Feature Extraction
↓
NSL-KDD Adapter
↓
Preprocessing
↓
Threat Detection
↓
Decision Engine
↓
Response Action
↓
Firewall
↓
Event Logger
↓
Database
"""

from packet_capture.live_capture import (
    capture_packets,
)

from packet_capture.flow_feature_extractor import (
    extract_flow_features,
)

from packet_capture.nsl_kdd_adapter import (
    adapt_flow_dataframe,
)

from detection.preprocessing_service import (
    preprocess_features,
)

from detection.threat_detector import (
    ThreatDetector,
)

from decision_engine.decision_engine import (
    process_detection,
)

from database.connection import (
    SessionLocal,
    init_db,
)


def run_detection_pipeline(
    packet_count=20,
    persist_events=True,
):
    """
    Run the complete NTCF detection pipeline.

    Parameters
    ----------
    packet_count : int
        Number of packets to capture.

    persist_events : bool
        If True, detection events are stored in the
        NTCF database.

    Returns
    -------
    list
        Detection results for each extracted flow.
    """

    # ---------------------------------------------------------
    # Initialize database
    # ---------------------------------------------------------

    if persist_events:
        init_db()

    db = None

    if persist_events:
        db = SessionLocal()

    try:

        # -----------------------------------------------------
        # 1. Capture packets
        # -----------------------------------------------------

        print(
            "\n========================================"
        )

        print(
            "NTCF NETWORK THREAT DETECTION"
        )

        print(
            "========================================"
        )

        print(
            "\n[1/7] Capturing packets..."
        )

        packets = capture_packets(
            packet_count=packet_count
        )

        print(
            f"Packets captured: {len(packets)}"
        )

        if not packets:

            print(
                "No packets captured."
            )

            return []

        # -----------------------------------------------------
        # 2. Extract flow-level features
        # -----------------------------------------------------

        print(
            "\n[2/7] Extracting flow features..."
        )

        flows = extract_flow_features(
            packets
        )

        print(
            f"Flows extracted: {len(flows)}"
        )

        if flows.empty:

            print(
                "No flows extracted."
            )

            return []

        # -----------------------------------------------------
        # 3. Adapt to NSL-KDD schema
        # -----------------------------------------------------

        print(
            "\n[3/7] Adapting to NSL-KDD features..."
        )

        raw_features = adapt_flow_dataframe(
            flows
        )

        print(
            f"Raw feature shape: "
            f"{raw_features.shape}"
        )

        # -----------------------------------------------------
        # 4. Load threat detector
        # -----------------------------------------------------

        print(
            "\n[4/7] Loading threat detection model..."
        )

        detector = ThreatDetector(
            model_name="decision_tree"
        )

        # -----------------------------------------------------
        # 5. Run detection
        # -----------------------------------------------------

        print(
            "\n[5/7] Running threat detection..."
        )

        results = []

        for index, row in raw_features.iterrows():

            model_input = preprocess_features(
                row.to_dict()
            )

            detection = detector.detect(
                model_input
            )

            source_ip = (
                flows.iloc[index].get(
                    "src_ip"
                )
            )

            destination_ip = (
                flows.iloc[index].get(
                    "dst_ip"
                )
            )

            # -------------------------------------------------
            # 6. Decision engine + database
            # -------------------------------------------------

            decision = process_detection(
                prediction=detection[
                    "prediction"
                ],
                confidence_score=detection[
                    "confidence"
                ],
                ip_address=source_ip,
                destination_ip=destination_ip,
                db=db,
            )

            result = {
                "flow": index + 1,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                **decision,
            }

            results.append(
                result
            )

            print(
                f"\nFlow {index + 1}"
            )

            print(
                f"  Source IP  : "
                f"{source_ip}"
            )

            print(
                f"  Destination: "
                f"{destination_ip}"
            )

            print(
                f"  Prediction : "
                f"{decision['prediction']}"
            )

            print(
                f"  Confidence : "
                f"{decision['confidence_score']}"
            )

            print(
                f"  Level      : "
                f"{decision['confidence_level']}"
            )

            print(
                f"  Severity   : "
                f"{decision['severity']}"
            )

            print(
                f"  Action     : "
                f"{decision['action']}"
            )

            if "database" in decision:

                print(
                    "  Database   : "
                    f"ThreatEvent "
                    f"{decision['database']['threat_event_id']}"
                )

        # -----------------------------------------------------
        # 7. Completion
        # -----------------------------------------------------

        print(
            "\n[7/7] Pipeline complete."
        )

        print(
            f"Processed flows: "
            f"{len(results)}"
        )

        if persist_events:

            print(
                "Detection events have been "
                "stored in the NTCF database."
            )

        else:

            print(
                "Database persistence disabled."
            )

        return results

    finally:

        if db is not None:
            db.close()


if __name__ == "__main__":

    run_detection_pipeline(
        packet_count=20
    )