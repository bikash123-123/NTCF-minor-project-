"""
threat_service.py

Service layer for retrieving threat events from the
Network Threat Cognition Framework (NTCF).

Threat events are read from the NTCF database.
"""

from database.connection import SessionLocal
from database.models import (
    ThreatEvent,
    DetectionResult,
    FirewallAction,
)


def _serialize_threat_event(
    threat_event,
    detection_result=None,
    firewall_action=None,
):
    """
    Convert database threat information into an API-friendly
    dictionary.

    Parameters
    ----------
    threat_event : ThreatEvent
        Threat event database record.

    detection_result : DetectionResult, optional
        Associated detection result.

    firewall_action : FirewallAction, optional
        Associated firewall action.

    Returns
    -------
    dict
        Serialized threat event.
    """

    result = {
        "id": threat_event.id,
        "source_ip": threat_event.source_ip,
        "destination_ip": threat_event.destination_ip,
        "threat_type": threat_event.threat_type,
        "confidence": threat_event.confidence,
        "severity": threat_event.severity,
        "detected_at": (
            threat_event.detected_at.isoformat()
            if threat_event.detected_at
            else None
        ),
    }

    # ---------------------------------------------------------
    # Detection result
    # ---------------------------------------------------------

    if detection_result is not None:

        result["detection"] = {
            "id": detection_result.id,
            "prediction": detection_result.prediction,
            "confidence": detection_result.confidence,
            "confidence_level": detection_result.confidence_level,
            "label": detection_result.label,
            "created_at": (
                detection_result.created_at.isoformat()
                if detection_result.created_at
                else None
            ),
        }

    else:

        result["detection"] = None

    # ---------------------------------------------------------
    # Firewall action
    # ---------------------------------------------------------

    if firewall_action is not None:

        result["firewall"] = {
            "id": firewall_action.id,
            "action": firewall_action.action,
            "status": firewall_action.status,
            "reason": firewall_action.reason,
            "created_at": (
                firewall_action.created_at.isoformat()
                if firewall_action.created_at
                else None
            ),
        }

    else:

        result["firewall"] = None

    # ---------------------------------------------------------
    # Compatibility fields
    # ---------------------------------------------------------
    #
    # These fields keep compatibility with the existing
    # dashboard routes and API consumers.
    #

    if detection_result is not None:

        result["prediction"] = (
            detection_result.prediction
        )

        # IMPORTANT:
        # confidence is numeric
        # confidence_level is textual
        result["confidence_level"] = (
            detection_result.confidence_level
        )

    else:

        result["prediction"] = (
            threat_event.threat_type
        )

        result["confidence_level"] = None

    if firewall_action is not None:

        result["action"] = firewall_action.action

    else:

        result["action"] = None

    return result


def get_all_threats(
    prediction=None,
    confidence_level=None,
    action=None,
):
    """
    Retrieve threat events from the database.

    Optional filters are supported for compatibility with
    the existing threat API.

    Parameters
    ----------
    prediction : str, optional
        Filter by prediction.

    confidence_level : str, optional
        Filter by confidence level.

    action : str, optional
        Filter by response action.

    Returns
    -------
    dict
        API-ready response.
    """

    db = SessionLocal()

    try:

        # -----------------------------------------------------
        # Load threat events
        # -----------------------------------------------------

        threat_events = (
            db.query(ThreatEvent)
            .order_by(
                ThreatEvent.id.desc()
            )
            .all()
        )

        results = []

        # -----------------------------------------------------
        # Build API records
        # -----------------------------------------------------

        for threat_event in threat_events:

            detection_result = (
                db.query(DetectionResult)
                .filter(
                    DetectionResult.threat_event_id
                    == threat_event.id
                )
                .order_by(
                    DetectionResult.id.desc()
                )
                .first()
            )

            firewall_action = (
                db.query(FirewallAction)
                .filter(
                    FirewallAction.threat_event_id
                    == threat_event.id
                )
                .order_by(
                    FirewallAction.id.desc()
                )
                .first()
            )

            event = _serialize_threat_event(
                threat_event,
                detection_result,
                firewall_action,
            )

            # -------------------------------------------------
            # Prediction filter
            # -------------------------------------------------

            if prediction:

                event_prediction = str(
                    event.get(
                        "prediction",
                        "",
                    )
                ).lower()

                if (
                    event_prediction
                    != prediction.lower()
                ):
                    continue

            # -------------------------------------------------
            # Confidence-level filter
            # -------------------------------------------------

            if confidence_level:

                event_confidence_level = str(
                    event.get(
                        "confidence_level",
                        "",
                    )
                ).lower()

                if (
                    event_confidence_level
                    != confidence_level.lower()
                ):
                    continue

            # -------------------------------------------------
            # Action filter
            # -------------------------------------------------

            if action:

                event_action = str(
                    event.get(
                        "action",
                        "",
                    )
                ).lower()

                if (
                    event_action
                    != action.lower()
                ):
                    continue

            results.append(event)

        return {
            "success": True,
            "status_code": 200,
            "count": len(results),
            "data": results,
        }

    finally:

        db.close()


def get_threat(index):
    """
    Retrieve one threat event by zero-based API index.

    Parameters
    ----------
    index : int
        Zero-based index in descending database order.

    Returns
    -------
    dict
        API-ready response.
    """

    db = SessionLocal()

    try:

        threat_events = (
            db.query(ThreatEvent)
            .order_by(
                ThreatEvent.id.desc()
            )
            .all()
        )

        # -----------------------------------------------------
        # Validate index
        # -----------------------------------------------------

        if index < 0 or index >= len(threat_events):

            return {
                "success": False,
                "status_code": 404,
                "message": "Threat event not found.",
            }

        # -----------------------------------------------------
        # Get selected threat event
        # -----------------------------------------------------

        threat_event = threat_events[index]

        # -----------------------------------------------------
        # Get detection result
        # -----------------------------------------------------

        detection_result = (
            db.query(DetectionResult)
            .filter(
                DetectionResult.threat_event_id
                == threat_event.id
            )
            .order_by(
                DetectionResult.id.desc()
            )
            .first()
        )

        # -----------------------------------------------------
        # Get firewall action
        # -----------------------------------------------------

        firewall_action = (
            db.query(FirewallAction)
            .filter(
                FirewallAction.threat_event_id
                == threat_event.id
            )
            .order_by(
                FirewallAction.id.desc()
            )
            .first()
        )

        # -----------------------------------------------------
        # Serialize
        # -----------------------------------------------------

        event = _serialize_threat_event(
            threat_event,
            detection_result,
            firewall_action,
        )

        return {
            "success": True,
            "status_code": 200,
            "data": event,
        }

    finally:

        db.close()