"""
testing/dashboard_threat_demo.py

Controlled NSL-KDD R2L/U2R demonstration for NTCF.

Purpose
-------
Find genuine R2L and U2R samples in the existing NSL-KDD dataset,
run them through the EXISTING NTCF preprocessing + detector,
and send successful detections through the EXISTING decision engine.

Important
---------
- Does NOT generate attack traffic.
- Does NOT modify packet capture.
- Does NOT retrain the model.
- Does NOT modify model artifacts.
- Does NOT modify the live detection pipeline.
- Does NOT change DoS/Probe detection.
- Uses the existing NTCF detector.
- Uses the existing NTCF decision engine.
- Uses the existing database when available.

Dataset
-------
The project already contains:

    data/raw/KDDTrain+.txt
    data/raw/KDDTest+.txt

The script automatically searches for these files.

Usage
-----

    python -m testing.dashboard_threat_demo

or:

    python -m testing.dashboard_threat_demo --r2l 3 --u2r 3

or:

    python -m testing.dashboard_threat_demo \
        --r2l 3 \
        --u2r 3 \
        --interval 1

Optional:

    python -m testing.dashboard_threat_demo \
        --csv data/raw/KDDTrain+.txt \
        --r2l 3 \
        --u2r 3
"""

from __future__ import annotations

import argparse
import csv
import time
from pathlib import Path
from typing import Any

import pandas as pd


# =====================================================================
# Project paths
# =====================================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"

DEFAULT_DATASETS = [
    RAW_DATA_DIR / "KDDTrain+.txt",
    RAW_DATA_DIR / "KDDTest+.txt",
]


# =====================================================================
# NSL-KDD schema
# =====================================================================

NSL_KDD_COLUMNS = [
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
]


# NSL-KDD has 41 features + attack label + difficulty level.
NSL_KDD_FULL_COLUMNS = NSL_KDD_COLUMNS + [
    "attack",
    "difficulty",
]


# =====================================================================
# Attack-family mapping
# =====================================================================

R2L_ATTACKS = {
    "guess_passwd",
    "ftp_write",
    "imap",
    "phf",
    "multihop",
    "warezmaster",
    "warezclient",
    "spy",
    "xlock",
    "xsnoop",
    "snmpguess",
    "snmpgetattack",
    "httptunnel",
    "sendmail",
    "named",
}

U2R_ATTACKS = {
    "buffer_overflow",
    "loadmodule",
    "perl",
    "rootkit",
    "ps",
    "sqlattack",
    "xterm",
}


# =====================================================================
# Console helpers
# =====================================================================

SEPARATOR = "=" * 70
SUB_SEPARATOR = "-" * 70


def print_header(title: str) -> None:
    print()
    print(SEPARATOR)
    print(title)
    print(SEPARATOR)


def print_subheader(title: str) -> None:
    print()
    print(SUB_SEPARATOR)
    print(title)
    print(SUB_SEPARATOR)


# =====================================================================
# Dataset discovery
# =====================================================================

def find_dataset(csv_path: str | None = None) -> Path:
    """
    Locate the existing NSL-KDD dataset.

    Priority:

    1. Explicit --csv argument.
    2. data/raw/KDDTrain+.txt
    3. data/raw/KDDTest+.txt
    4. Other .txt/.csv files under data/raw.

    Returns
    -------
    pathlib.Path
        Dataset path.
    """

    if csv_path:
        candidate = Path(csv_path)

        if not candidate.is_absolute():
            candidate = PROJECT_ROOT / candidate

        if not candidate.exists():
            raise FileNotFoundError(
                f"Specified dataset does not exist:\n{candidate}"
            )

        return candidate.resolve()

    for candidate in DEFAULT_DATASETS:

        if candidate.exists():
            return candidate.resolve()

    # Fallback search.
    if RAW_DATA_DIR.exists():

        candidates = sorted(
            list(RAW_DATA_DIR.glob("*.txt"))
            + list(RAW_DATA_DIR.glob("*.csv"))
        )

        for candidate in candidates:

            name = candidate.name.lower()

            if (
                "kddtrain" in name
                or "kddtest" in name
                or "nsl" in name
            ):
                return candidate.resolve()

        if candidates:
            return candidates[0].resolve()

    raise FileNotFoundError(
        "\nCould not locate an NSL-KDD dataset.\n\n"
        "Expected one of:\n"
        f"  {DEFAULT_DATASETS[0]}\n"
        f"  {DEFAULT_DATASETS[1]}\n\n"
        "Or provide one explicitly:\n"
        "  python -m testing.dashboard_threat_demo "
        "--csv data\\raw\\KDDTrain+.txt\n"
    )


# =====================================================================
# Dataset loading
# =====================================================================

def _looks_like_header(row: list[str]) -> bool:
    """
    Determine whether the first row appears to be a header.
    """

    if not row:
        return False

    normalized = {
        str(value).strip().lower()
        for value in row
    }

    return (
        "duration" in normalized
        or "protocol_type" in normalized
        or "protocol" in normalized
        or "attack" in normalized
        or "label" in normalized
    )


def load_nsl_kdd_dataset(path: Path) -> pd.DataFrame:
    """
    Load a raw NSL-KDD TXT/CSV file.

    Handles:

    - KDDTrain+.txt
    - KDDTest+.txt
    - comma-separated CSV
    - files with or without headers
    - optional difficulty column
    """

    print()
    print(f"Dataset path: {path}")

    # -------------------------------------------------------------
    # First attempt: normal CSV parsing.
    # -------------------------------------------------------------

    df = pd.read_csv(
        path,
        header=None,
        sep=",",
        engine="python",
    )

    # -------------------------------------------------------------
    # Remove completely empty columns.
    # -------------------------------------------------------------

    df = df.dropna(
        axis=1,
        how="all",
    )

    if df.empty:
        raise ValueError(
            f"Dataset is empty: {path}"
        )

    # -------------------------------------------------------------
    # Determine whether file already has a header.
    # -------------------------------------------------------------

    first_row = [
        str(value).strip()
        for value in df.iloc[0].tolist()
    ]

    if _looks_like_header(first_row):

        df = pd.read_csv(
            path,
            header=0,
            sep=",",
            engine="python",
        )

        df = df.dropna(
            axis=1,
            how="all",
        )

    # -------------------------------------------------------------
    # NSL-KDD normally contains 43 columns.
    #
    # 41 features
    # + attack label
    # + difficulty level
    # -------------------------------------------------------------

    if df.shape[1] == 43:

        df.columns = NSL_KDD_FULL_COLUMNS

    elif df.shape[1] == 42:

        # Some copies contain the attack label but omit
        # difficulty level.
        df.columns = NSL_KDD_COLUMNS + [
            "attack"
        ]

    elif df.shape[1] == 41:

        # If there are only 41 columns, the file cannot
        # provide attack labels independently.
        #
        # We still load it, but R2L/U2R searching will
        # correctly report that labels are unavailable.
        df.columns = NSL_KDD_COLUMNS

    else:

        raise ValueError(
            "\nUnexpected NSL-KDD column count.\n"
            f"File: {path}\n"
            f"Columns found: {df.shape[1]}\n"
            "Expected 41, 42, or 43 columns."
        )

    # -------------------------------------------------------------
    # Normalize string columns.
    # -------------------------------------------------------------

    for column in [
        "protocol_type",
        "service",
        "flag",
    ]:

        if column in df.columns:

            df[column] = (
                df[column]
                .astype(str)
                .str.strip()
            )

    if "attack" in df.columns:

        df["attack"] = (
            df["attack"]
            .astype(str)
            .str.strip()
            .str.lower()
            .str.rstrip(".")
        )

    print(
        f"Rows loaded: {len(df)}"
    )

    print(
        f"Columns loaded: {len(df.columns)}"
    )

    return df


# =====================================================================
# Attack-family detection
# =====================================================================

def get_attack_family(attack: str) -> str | None:
    """
    Map an NSL-KDD attack label to R2L/U2R.

    Returns
    -------
    str or None
        R2L, U2R, or None.
    """

    normalized = (
        str(attack)
        .strip()
        .lower()
        .rstrip(".")
    )

    if normalized in R2L_ATTACKS:
        return "R2L"

    if normalized in U2R_ATTACKS:
        return "U2R"

    return None


# =====================================================================
# Existing NTCF imports
# =====================================================================

def load_ntcf_components():
    """
    Load the existing NTCF detector, preprocessing service,
    decision engine and database.

    IMPORTANT:
    These imports intentionally use the actual project
    structure discovered in the project.
    """

    print()
    print("Loading existing NTCF detector...")

    from detection.preprocessing_service import (
        preprocess_features,
    )

    from detection.threat_detector import (
        ThreatDetector,
    )

    from decision_engine.decision_engine import (
        process_detection,
    )

    # Database imports are kept optional so the demonstration
    # can still perform ML detection if DB initialization has
    # an unrelated environment problem.
    try:

        from database.connection import (
            SessionLocal,
            init_db,
        )

    except Exception as exc:

        print(
            "Database components could not be imported:"
        )

        print(
            f"  {exc}"
        )

        SessionLocal = None
        init_db = None

    detector = ThreatDetector()

    print(
        "Detector loaded successfully."
    )

    return (
        detector,
        preprocess_features,
        process_detection,
        SessionLocal,
        init_db,
    )


# =====================================================================
# Model prediction
# =====================================================================

def predict_sample(
    sample: pd.Series,
    detector: Any,
    preprocess_features: Any,
) -> dict[str, Any]:
    """
    Run one NSL-KDD feature row through the EXISTING
    NTCF preprocessing and detector.

    No model training occurs here.
    """

    feature_dict = {}

    for column in NSL_KDD_COLUMNS:

        value = sample[column]

        # Convert numpy/pandas scalar values into normal
        # Python values where possible.
        if hasattr(value, "item"):

            try:
                value = value.item()

            except Exception:
                pass

        feature_dict[column] = value

    # -------------------------------------------------------------
    # Existing NTCF preprocessing
    # -------------------------------------------------------------

    model_input = preprocess_features(
        feature_dict
    )

    # -------------------------------------------------------------
    # Existing NTCF detector
    # -------------------------------------------------------------

    detection = detector.detect(
        model_input
    )

    if not isinstance(detection, dict):

        raise TypeError(
            "ThreatDetector.detect() must return a dictionary."
        )

    prediction = detection.get(
        "prediction"
    )

    confidence = detection.get(
        "confidence"
    )

    return {
        "prediction": prediction,
        "confidence": confidence,
        "raw_detection": detection,
    }


# =====================================================================
# Genuine detection search
# =====================================================================

def find_genuine_detections(
    dataframe: pd.DataFrame,
    family: str,
    requested_count: int,
    detector: Any,
    preprocess_features: Any,
) -> list[dict[str, Any]]:
    """
    Search the existing model's predictions for genuine
    R2L/U2R detections.

    A sample is accepted when:

        expected family == requested family
        AND
        model prediction is not normal

    Exact attack-label matches are tracked separately.
    """

    results = []

    if requested_count <= 0:
        return results

    if "attack" not in dataframe.columns:

        raise ValueError(
            "The dataset does not contain an attack label column."
        )

    family_df = dataframe[
        dataframe["attack"].apply(
            get_attack_family
        ) == family
    ].copy()

    print(
        f"{family} samples loaded: {len(family_df)}"
    )

    inspected = 0

    for index, sample in family_df.iterrows():

        if len(results) >= requested_count:
            break

        inspected += 1

        try:

            detection = predict_sample(
                sample=sample,
                detector=detector,
                preprocess_features=preprocess_features,
            )

        except Exception as exc:

            print(
                f"  SKIP | {family} | "
                f"Dataset row {index} | "
                f"Prediction error: {exc}"
            )

            continue

        prediction = detection["prediction"]

        confidence = detection["confidence"]

        normalized_prediction = (
            str(prediction)
            .strip()
            .lower()
            .rstrip(".")
        )

        expected_attack = (
            str(sample["attack"])
            .strip()
            .lower()
            .rstrip(".")
        )

        # ---------------------------------------------------------
        # Genuine family detection.
        #
        # We accept any malicious prediction for the expected
        # family, because the purpose here is to demonstrate
        # the model detecting the R2L/U2R family without
        # changing the model.
        # ---------------------------------------------------------

        if normalized_prediction == "normal":
            continue

        exact_match = (
            normalized_prediction
            == expected_attack
        )

        result = {
            "dataset_index": index,
            "family": family,
            "expected_attack": expected_attack,
            "prediction": prediction,
            "confidence": confidence,
            "exact_match": exact_match,
            "sample": sample.copy(),
        }

        results.append(
            result
        )

        print(
            f"  FOUND | {family} | "
            f"Expected: {expected_attack} | "
            f"Predicted: {prediction} | "
            f"Confidence: {confidence}"
        )

    print(
        f"  Inspected: {inspected} samples"
    )

    print(
        f"  Genuine detections found: "
        f"{len(results)} / {requested_count}"
    )

    return results


# =====================================================================
# Database helper
# =====================================================================

def create_database_session(
    SessionLocal: Any,
    init_db: Any,
):
    """
    Create the existing NTCF database session.

    Returns None if database initialization is unavailable.
    """

    if SessionLocal is None:
        return None

    try:

        if init_db is not None:
            init_db()

        db = SessionLocal()

        return db

    except Exception as exc:

        print()
        print(
            "WARNING: Could not open NTCF database."
        )

        print(
            f"Database error: {exc}"
        )

        print(
            "The ML demonstration will continue without "
            "database persistence."
        )

        return None


# =====================================================================
# Process one demonstration event
# =====================================================================

def process_demo_event(
    event: dict[str, Any],
    process_detection: Any,
    db: Any,
) -> dict[str, Any]:
    """
    Send a successful model detection through the existing
    NTCF decision engine.

    TEST-R2L and TEST-U2R are intentionally NOT used as
    IP addresses because the firewall expects valid IP
    addresses.

    Instead, deterministic documentation/test addresses
    are used.
    """

    family = event["family"]

    # RFC 5737 documentation addresses.
    if family == "R2L":
        source_ip = "192.0.2.10"
    else:
        source_ip = "198.51.100.10"

    destination_ip = "203.0.113.10"

    prediction = event["prediction"]

    confidence = event["confidence"]

    # -------------------------------------------------------------
    # Existing decision engine.
    # -------------------------------------------------------------

    decision = process_detection(
        prediction=prediction,
        confidence_score=confidence,
        ip_address=source_ip,
        destination_ip=destination_ip,
        db=db,
    )

    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        **decision,
    }


# =====================================================================
# Print event result
# =====================================================================

def print_event_result(
    event: dict[str, Any],
    decision: dict[str, Any],
) -> None:

    print()
    print(SUB_SEPARATOR)

    print(
        f"Source              : "
        f"{event['family']} TEST SAMPLE"
    )

    print(
        f"Expected category   : "
        f"{event['family']}"
    )

    print(
        f"Expected attack     : "
        f"{event['expected_attack']}"
    )

    print(
        f"Model prediction    : "
        f"{decision.get('prediction')}"
    )

    print(
        f"Model label         : "
        + (
            "Normal"
            if str(
                decision.get("prediction")
            ).lower()
            == "normal"
            else "Threat"
        )
    )

    print(
        f"Confidence          : "
        f"{decision.get('confidence_score')}"
    )

    print(
        f"Decision severity   : "
        f"{decision.get('severity')}"
    )

    print(
        f"Decision action     : "
        f"{decision.get('action')}"
    )

    print(
        f"Decision level      : "
        f"{decision.get('confidence_level')}"
    )

    firewall_result = decision.get(
        "firewall"
    )

    if firewall_result is not None:

        print(
            f"Firewall result     : "
            f"{firewall_result}"
        )

    print(
        "Exact attack match  : "
        + (
            "YES"
            if event["exact_match"]
            else "NO (different attack label)"
        )
    )

    if "database" in decision:

        print(
            "Database persisted  : YES"
        )

        print(
            f"Threat event ID     : "
            f"{decision['database'].get('threat_event_id')}"
        )

        print(
            f"Detection result ID : "
            f"{decision['database'].get('detection_result_id')}"
        )

    else:

        print(
            "Database persisted  : NO"
        )

    print(
        "Threat event logged : YES"
    )


# =====================================================================
# Main
# =====================================================================

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "Controlled NTCF R2L/U2R dashboard "
            "demonstration using existing NSL-KDD samples."
        )
    )

    parser.add_argument(
        "--r2l",
        type=int,
        default=3,
        help=(
            "Number of genuine R2L detections "
            "to search for."
        ),
    )

    parser.add_argument(
        "--u2r",
        type=int,
        default=3,
        help=(
            "Number of genuine U2R detections "
            "to search for."
        ),
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help=(
            "Seconds between dashboard demonstration events."
        ),
    )

    parser.add_argument(
        "--csv",
        type=str,
        default=None,
        help=(
            "Optional path to an NSL-KDD TXT/CSV dataset."
        ),
    )

    args = parser.parse_args()

    if args.r2l < 0:
        parser.error(
            "--r2l cannot be negative."
        )

    if args.u2r < 0:
        parser.error(
            "--u2r cannot be negative."
        )

    # -------------------------------------------------------------
    # Header
    # -------------------------------------------------------------

    print_header(
        "NTCF DASHBOARD THREAT DEMONSTRATION"
    )

    print(
        """
Purpose:
Demonstrate genuine R2L/U2R detections from the existing
NTCF ML model and pass them through the existing NTCF
decision/database pipeline.

Safety:
No attack traffic is generated.
No packet capture is modified.
No model is retrained.
No model artifact is modified.
Existing DoS/Probe detection is untouched.
"""
    )

    print(
        f"Requested R2L detections: {args.r2l}"
    )

    print(
        f"Requested U2R detections: {args.u2r}"
    )

    # -------------------------------------------------------------
    # Load existing NTCF components
    # -------------------------------------------------------------

    (
        detector,
        preprocess_features,
        process_detection,
        SessionLocal,
        init_db,
    ) = load_ntcf_components()

    # -------------------------------------------------------------
    # Locate dataset
    # -------------------------------------------------------------

    dataset_path = find_dataset(
        args.csv
    )

    print()
    print(
        f"Using NSL-KDD dataset:"
    )

    print(
        f"  {dataset_path}"
    )

    # -------------------------------------------------------------
    # Load dataset
    # -------------------------------------------------------------

    dataframe = load_nsl_kdd_dataset(
        dataset_path
    )

    # -------------------------------------------------------------
    # Search for R2L
    # -------------------------------------------------------------

    print_subheader(
        "Searching for genuine R2L detections "
        "from the existing model..."
    )

    r2l_events = find_genuine_detections(
        dataframe=dataframe,
        family="R2L",
        requested_count=args.r2l,
        detector=detector,
        preprocess_features=preprocess_features,
    )

    # -------------------------------------------------------------
    # Search for U2R
    # -------------------------------------------------------------

    print_subheader(
        "Searching for genuine U2R detections "
        "from the existing model..."
    )

    u2r_events = find_genuine_detections(
        dataframe=dataframe,
        family="U2R",
        requested_count=args.u2r,
        detector=detector,
        preprocess_features=preprocess_features,
    )

    # -------------------------------------------------------------
    # Search summary
    # -------------------------------------------------------------

    print_header(
        "MODEL DETECTION SEARCH COMPLETE"
    )

    print(
        f"R2L detections found: "
        f"{len(r2l_events)} / {args.r2l}"
    )

    print(
        f"U2R detections found: "
        f"{len(u2r_events)} / {args.u2r}"
    )

    # -------------------------------------------------------------
    # Stop if requested events weren't found.
    # -------------------------------------------------------------

    if (
        len(r2l_events) < args.r2l
        or len(u2r_events) < args.u2r
    ):

        print()
        print(
            "WARNING:"
        )

        print(
            "The existing model did not produce enough "
            "genuine R2L/U2R detections for the requested "
            "demonstration."
        )

        print()
        print(
            "No artificial predictions will be created."
        )

        print(
            "No model changes will be made."
        )

        # Continue with whatever genuine detections were found.
        # This is intentional.
        if not r2l_events and not u2r_events:

            print()
            print(
                "No genuine R2L/U2R detections were found."
            )

            return

    # -------------------------------------------------------------
    # Open database
    # -------------------------------------------------------------

    db = create_database_session(
        SessionLocal=SessionLocal,
        init_db=init_db,
    )

    # -------------------------------------------------------------
    # Controlled demonstration
    # -------------------------------------------------------------

    print_header(
        "STARTING CONTROLLED DASHBOARD DEMONSTRATION"
    )

    all_events = (
        r2l_events
        + u2r_events
    )

    successful = 0
    errors = 0
    threat_events = 0
    exact_matches = 0
    r2l_count = 0
    u2r_count = 0

    try:

        for event in all_events:

            try:

                decision = process_demo_event(
                    event=event,
                    process_detection=process_detection,
                    db=db,
                )

                print_event_result(
                    event=event,
                    decision=decision,
                )

                successful += 1

                if event["exact_match"]:
                    exact_matches += 1

                if event["family"] == "R2L":
                    r2l_count += 1

                elif event["family"] == "U2R":
                    u2r_count += 1

                if str(
                    decision.get("prediction")
                ).lower() != "normal":

                    threat_events += 1

                # -------------------------------------------------
                # Keep demonstration events visually separate in
                # the dashboard.
                # -------------------------------------------------

                if args.interval > 0:

                    time.sleep(
                        args.interval
                    )

            except Exception as exc:

                errors += 1

                print()
                print(
                    f"ERROR processing "
                    f"{event['family']} sample:"
                )

                print(
                    f"  {exc}"
                )

    finally:

        if db is not None:

            try:
                db.close()

            except Exception:
                pass

    # -------------------------------------------------------------
    # Final summary
    # -------------------------------------------------------------

    print_header(
        "NTCF DASHBOARD DEMONSTRATION COMPLETE"
    )

    print(
        f"Samples processed      : {len(all_events)}"
    )

    print(
        f"Successful             : {successful}"
    )

    print(
        f"Errors                 : {errors}"
    )

    print(
        f"Threat events logged   : {threat_events}"
    )

    print(
        f"Exact attack matches   : {exact_matches}"
    )

    print(
        f"R2L events             : {r2l_count}"
    )

    print(
        f"U2R events             : {u2r_count}"
    )

    print()
    print(
        "These events were sent through the existing "
        "NTCF decision engine."
    )

    print(
        "They were logged by the existing event logger."
    )

    print(
        "When database persistence is available, they "
        "are also stored in the existing NTCF database."
    )

    print()
    print(
        "Existing DoS/Probe detection was not modified."
    )

    print(
        "No attack traffic was generated."
    )

    print(
        "No model artifact was modified."
    )

    print()


# =====================================================================
# Entry point
# =====================================================================

if __name__ == "__main__":
    main()