"""
ntcf_pipeline.py

Main runtime pipeline for the Network Threat Cognition
Framework (NTCF).

Supports:
    - One-shot detection
    - Continuous live detection
    - Batched packet processing

Pipeline:

Packet Capture
↓
Packet Parser
↓
Flow Feature Extraction
↓
NSL-KDD Adapter
↓
Preprocessing
↓
ML Prediction
↓
Confidence Calculation
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
↓
Backend API
↓
Dashboard
"""

from packet_capture.live_capture import capture_packets

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


# =========================================================
# Process One Packet Batch
# =========================================================

def process_packet_batch(
    packets,
    detector,
    db=None,
):
    """
    Process one captured packet batch through the
    complete NTCF detection pipeline.

    Returns
    -------
    list
        Detection results.
    """

    results = []

    if not packets:
        return results

    # -----------------------------------------------------
    # Flow Feature Extraction
    # -----------------------------------------------------

    print(
        "\n[2] Extracting flow features..."
    )

    flows = extract_flow_features(
        packets
    )

    print(
        f"Flows extracted: {len(flows)}"
    )

    if flows.empty:
        return results

    # -----------------------------------------------------
    # NSL-KDD Adapter
    # -----------------------------------------------------

    print(
        "[3] Adapting flows to NSL-KDD schema..."
    )

    raw_features = adapt_flow_dataframe(
        flows
    )

    print(
        f"Feature shape: {raw_features.shape}"
    )

    # -----------------------------------------------------
    # Detection
    # -----------------------------------------------------

    for index, row in raw_features.iterrows():

        try:

            # ---------------------------------------------
            # Preprocessing
            # ---------------------------------------------

            model_input = preprocess_features(
                row.to_dict()
            )

            # ---------------------------------------------
            # ML Prediction
            # ---------------------------------------------

            detection = detector.detect(
                model_input
            )

            source_ip = flows.iloc[index].get(
                "src_ip"
            )

            destination_ip = flows.iloc[index].get(
                "dst_ip"
            )

            # ---------------------------------------------
            # Decision Engine
            # ---------------------------------------------

            decision = process_detection(
                prediction=detection["prediction"],
                confidence_score=detection["confidence"],
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

            results.append(result)

            # ---------------------------------------------
            # Console Output
            # ---------------------------------------------

            print(
                "\n----------------------------------------"
            )

            print(
                f"Source       : {source_ip}"
            )

            print(
                f"Destination  : {destination_ip}"
            )

            print(
                f"Prediction   : "
                f"{decision.get('prediction')}"
            )

            print(
                f"Confidence   : "
                f"{decision.get('confidence_score')}"
            )

            print(
                f"Level        : "
                f"{decision.get('confidence_level')}"
            )

            print(
                f"Severity     : "
                f"{decision.get('severity')}"
            )

            print(
                f"Action       : "
                f"{decision.get('action')}"
            )

            if "database" in decision:

                print(
                    f"Database     : "
                    f"ThreatEvent "
                    f"{decision['database'].get('threat_event_id')}"
                )

        except Exception as error:

            print(
                f"[FLOW ERROR] {error}"
            )

    return results


# =========================================================
# One-Shot Pipeline
# =========================================================

def run_detection_pipeline(
    packet_count=20,
    persist_events=True,
):
    """
    Run one detection cycle.

    This preserves the original Issue #31 behavior.
    """

    if persist_events:
        init_db()

    db = None

    if persist_events:
        db = SessionLocal()

    try:

        print(
            "\n========================================"
        )

        print(
            "NTCF NETWORK THREAT DETECTION"
        )

        print(
            "========================================"
        )

        # -------------------------------------------------
        # Capture
        # -------------------------------------------------

        print(
            f"\n[1] Capturing {packet_count} packets..."
        )

        packets = capture_packets(
            packet_count=packet_count
        )

        print(
            f"Packets captured: {len(packets)}"
        )

        if not packets:
            print("No packets captured.")
            return []

        # -------------------------------------------------
        # Process
        # -------------------------------------------------

        detector = ThreatDetector(
            model_name="decision_tree"
        )

        results = process_packet_batch(
            packets,
            detector,
            db,
        )

        print(
            "\n========================================"
        )

        print(
            f"Pipeline complete."
        )

        print(
            f"Processed flows: {len(results)}"
        )

        print(
            "========================================"
        )

        return results

    finally:

        if db is not None:
            db.close()


# =========================================================
# Continuous Live Pipeline
# =========================================================

def run_live_detection(
    batch_size=50,
    persist_events=True,
):
    """
    Run the NTCF detection pipeline continuously.

    Packets are captured in bounded batches and each
    batch is immediately processed through the complete
    NTCF pipeline.

    Press CTRL+C to stop.
    """

    if persist_events:
        init_db()

    db = None

    if persist_events:
        db = SessionLocal()

    detector = ThreatDetector(
        model_name="decision_tree"
    )

    batch_number = 0
    total_packets = 0
    total_flows = 0

    print(
        "\n========================================"
    )

    print(
        "NTCF LIVE THREAT MONITORING"
    )

    print(
        "========================================"
    )

    print(
        f"Batch size : {batch_size}"
    )

    print(
        "Press CTRL+C to stop."
    )

    try:

        while True:

            batch_number += 1

            print(
                "\n========================================"
            )

            print(
                f"CAPTURE BATCH {batch_number}"
            )

            print(
                "========================================"
            )

            # -------------------------------------------------
            # Capture next batch
            # -------------------------------------------------

            packets = capture_packets(
                packet_count=batch_size
            )

            if not packets:

                print(
                    "No packets captured."
                )

                continue

            total_packets += len(packets)

            print(
                f"Captured: {len(packets)} packets"
            )

            # -------------------------------------------------
            # Process batch
            # -------------------------------------------------

            results = process_packet_batch(
                packets,
                detector,
                db,
            )

            total_flows += len(results)

            # -------------------------------------------------
            # Batch summary
            # -------------------------------------------------

            threats = [
                result
                for result in results
                if str(
                    result.get(
                        "prediction",
                        ""
                    )
                ).lower() != "normal"
            ]

            blocks = [
                result
                for result in results
                if str(
                    result.get(
                        "action",
                        ""
                    )
                ).lower() == "block"
            ]

            print(
                "\nBATCH SUMMARY"
            )

            print(
                f"Packets : {len(packets)}"
            )

            print(
                f"Flows   : {len(results)}"
            )

            print(
                f"Threats : {len(threats)}"
            )

            print(
                f"Blocks  : {len(blocks)}"
            )

            print(
                f"Total packets processed: "
                f"{total_packets}"
            )

            print(
                f"Total flows processed: "
                f"{total_flows}"
            )

    except KeyboardInterrupt:

        print(
            "\n\n========================================"
        )

        print(
            "NTCF LIVE MONITORING STOPPED"
        )

        print(
            "========================================"
        )

        print(
            f"Total packets: {total_packets}"
        )

        print(
            f"Total flows  : {total_flows}"
        )

    finally:

        if db is not None:
            db.close()


# =========================================================
# Main
# =========================================================

if __name__ == "__main__":

    # -----------------------------------------------------
    # Change this to True for continuous monitoring.
    # -----------------------------------------------------

    LIVE_MODE = True

    if LIVE_MODE:

        run_live_detection(
            batch_size=50,
            persist_events=True,
        )

    else:

        run_detection_pipeline(
            packet_count=20,
            persist_events=True,
        )