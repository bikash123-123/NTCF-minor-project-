"""
database_service.py

Persists NTCF decision-engine results into the database.

This module is responsible only for database persistence.
It does not perform ML inference or firewall operations.
"""

from database.connection import SessionLocal

from database.models import (
    ThreatEvent,
    DetectionResult,
    FirewallAction,
)


def store_detection_result(
    prediction,
    confidence,
    source_ip=None,
    destination_ip=None,
    action=None,
    severity=None,
    firewall_result=None,
):
    """
    Store one complete NTCF detection event.

    Parameters
    ----------
    prediction : str
        Model prediction.

    confidence : float
        Model confidence.

    source_ip : str, optional
        Source IP address.

    destination_ip : str, optional
        Destination IP address.

    action : str, optional
        Decision-engine action.

    severity : str, optional
        Event severity.

    firewall_result : dict, optional
        Result returned by the firewall service.

    Returns
    -------
    dict
        Database record identifiers and status.
    """

    db = SessionLocal()

    try:

        # -------------------------------------------------
        # Create threat event
        # -------------------------------------------------

        threat_event = ThreatEvent(
            source_ip=source_ip,
            destination_ip=destination_ip,
            threat_type=prediction,
            confidence=confidence,
            severity=severity,
        )

        db.add(threat_event)
        db.flush()

        # -------------------------------------------------
        # Create detection result
        # -------------------------------------------------

        label = (
            "Normal"
            if str(prediction).lower() == "normal"
            else "Threat"
        )

        detection_result = DetectionResult(
            threat_event_id=threat_event.id,
            prediction=prediction,
            confidence=confidence,
            label=label,
        )

        db.add(detection_result)

        # -------------------------------------------------
        # Store firewall action when applicable
        # -------------------------------------------------

        if action is not None:

            firewall_status = "not_requested"

            reason = None

            if firewall_result:

                if firewall_result.get("success"):
                    firewall_status = "success"
                else:
                    firewall_status = "failed"

                reason = firewall_result.get(
                    "error"
                )

                if reason is None:
                    reason = firewall_result.get(
                        "result"
                    )

            firewall_action = FirewallAction(
                threat_event_id=threat_event.id,
                action=action,
                status=firewall_status,
                reason=str(reason) if reason else None,
            )

            db.add(firewall_action)

        # -------------------------------------------------
        # Commit transaction
        # -------------------------------------------------

        db.commit()

        return {
            "success": True,
            "threat_event_id": threat_event.id,
            "detection_result_id": detection_result.id,
        }

    except Exception:

        db.rollback()

        raise

    finally:

        db.close()