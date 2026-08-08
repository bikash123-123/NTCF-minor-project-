"""
detection_service.py

Backend service for exposing NTCF threat detection.

This service:
    1. Validates the API payload.
    2. Preprocesses ML features.
    3. Runs the threat detector.
    4. Determines severity and response action.
    5. Persists the complete detection event.
    6. Returns an API-friendly response.
"""

from detection.preprocessing_service import (
    preprocess_features,
)

from detection.threat_detector import ThreatDetector

from database.connection import SessionLocal
from database.repositories import Repository


# ---------------------------------------------------------
# Helper functions
# ---------------------------------------------------------

def _get_confidence_level(confidence):
    """
    Convert a numerical confidence score into a
    human-readable confidence level.

    Rules:
        >= 0.80 -> high
        >= 0.60 -> medium
        <  0.60 -> low
    """

    if confidence >= 0.80:
        return "high"

    if confidence >= 0.60:
        return "medium"

    return "low"


def _get_severity(prediction, label, confidence):
    """
    Determine threat severity.

    Normal traffic is always low severity.

    Threat traffic:
        high confidence   -> high
        medium confidence -> medium
        low confidence    -> low
    """

    if str(label).lower() == "normal":
        return "low"

    if confidence >= 0.80:
        return "high"

    if confidence >= 0.60:
        return "medium"

    return "low"


def _get_action(label):
    """
    Determine the response action.

    Normal traffic:
        allow

    Threat traffic:
        block
    """

    if str(label).lower() == "normal":
        return "allow"

    return "block"


def _get_reason(label, confidence):
    """
    Generate the reason stored with the firewall action.
    """

    if str(label).lower() == "normal":
        return "Traffic classified as normal."

    if confidence >= 0.80:
        return "High confidence malicious traffic detected."

    if confidence >= 0.60:
        return "Potential malicious traffic detected."

    return "Low confidence threat classification."


# ---------------------------------------------------------
# Threat detection
# ---------------------------------------------------------

def detect_threat(payload):
    """
    Perform threat detection from API input.

    The function runs the ML detector and persists the
    complete detection event into the database.

    Expected payload:

        {
            "model_name": "decision_tree",
            "features": {
                ...
            }
        }
    """

    # -----------------------------------------------------
    # Validate payload
    # -----------------------------------------------------

    if not isinstance(payload, dict):

        return {
            "success": False,
            "status_code": 400,
            "message": "JSON object expected.",
        }

    # -----------------------------------------------------
    # Model name
    # -----------------------------------------------------

    model_name = payload.get(
        "model_name",
        "decision_tree",
    )

    if not isinstance(model_name, str) or not model_name.strip():

        return {
            "success": False,
            "status_code": 400,
            "message": "Invalid model_name.",
        }

    model_name = model_name.strip()

    # -----------------------------------------------------
    # Features
    # -----------------------------------------------------

    features = payload.get("features")

    if features is None:

        return {
            "success": False,
            "status_code": 400,
            "message": "Missing 'features' field.",
        }

    if not isinstance(features, dict):

        return {
            "success": False,
            "status_code": 400,
            "message": "'features' must be a JSON object.",
        }

    # -----------------------------------------------------
    # Preprocess features
    # -----------------------------------------------------

    try:

        dataframe = preprocess_features(
            features
        )

    except ValueError as error:

        return {
            "success": False,
            "status_code": 400,
            "message": str(error),
        }

    except Exception as error:

        return {
            "success": False,
            "status_code": 500,
            "message": str(error),
        }

    # -----------------------------------------------------
    # Run detector
    # -----------------------------------------------------

    try:

        detector = ThreatDetector(
            model_name=model_name
        )

        result = detector.detect(
            dataframe
        )

    except Exception as error:

        return {
            "success": False,
            "status_code": 500,
            "message": str(error),
        }

    # -----------------------------------------------------
    # Detector error
    # -----------------------------------------------------

    if result.get("status") != "success":

        return {
            "success": False,
            "status_code": 400,
            "message": result.get(
                "message",
                "Threat detection failed.",
            ),
        }

    # -----------------------------------------------------
    # Extract prediction result
    # -----------------------------------------------------

    prediction = str(
        result["prediction"]
    )

    label = str(
        result["label"]
    )

    confidence = float(
        result["confidence"]
    )

    # -----------------------------------------------------
    # Determine classification metadata
    # -----------------------------------------------------

    confidence_level = _get_confidence_level(
        confidence
    )

    severity = _get_severity(
        prediction,
        label,
        confidence,
    )

    action = _get_action(
        label
    )

    reason = _get_reason(
        label,
        confidence,
    )

    # -----------------------------------------------------
    # Extract network information
    #
    # The ML feature set itself does not contain source_ip
    # or destination_ip, therefore these are optional.
    #
    # They can be supplied alongside "features":
    #
    # {
    #     "source_ip": "...",
    #     "destination_ip": "...",
    #     "features": {...}
    # }
    # -----------------------------------------------------

    source_ip = payload.get(
        "source_ip"
    )

    destination_ip = payload.get(
        "destination_ip"
    )

    # -----------------------------------------------------
    # Persist detection event
    # -----------------------------------------------------

    db = SessionLocal()

    try:

        repository = Repository(db)

        saved_event = repository.save_detection_event(
            source_ip=source_ip,
            destination_ip=destination_ip,
            prediction=prediction,
            confidence=confidence,
            label=label,
            confidence_level=confidence_level,
            severity=severity,
            action=action,
            firewall_status="not_executed",
            reason=reason,
        )

        # -------------------------------------------------
        # Database objects were successfully created.
        # -------------------------------------------------

        threat_event = saved_event[
            "threat_event"
        ]

        detection_result = saved_event[
            "detection_result"
        ]

        firewall_action = saved_event[
            "firewall_action"
        ]

        # -------------------------------------------------
        # API response
        # -------------------------------------------------

        return {
            "success": True,
            "status_code": 200,

            "id": threat_event.id,

            "prediction": prediction,

            "label": label,

            "confidence": confidence,

            "confidence_level": confidence_level,

            "severity": severity,

            "action": action,

            "detection_id": (
                detection_result.id
                if detection_result
                else None
            ),

            "firewall_action_id": (
                firewall_action.id
                if firewall_action
                else None
            ),
        }

    except Exception as error:

        db.rollback()

        return {
            "success": False,
            "status_code": 500,
            "message": (
                "Failed to save detection event: "
                + str(error)
            ),
        }

    finally:

        db.close()