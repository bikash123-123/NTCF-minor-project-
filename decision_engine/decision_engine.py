"""
decision_engine.py

Main orchestration layer for the NTCF decision engine.

This module connects:

1. Model prediction
2. Confidence evaluation
3. Response action selection
4. Event logging
5. Database persistence

It does not perform machine-learning inference.
"""

from decision_engine.confidence_engine import (
    process_prediction,
)

from decision_engine.response_actions import (
    determine_response,
)

from decision_engine.event_logger import (
    log_event,
)


def _calculate_severity(
    prediction,
    confidence_level,
):
    """
    Determine event severity from the prediction
    and confidence level.

    Normal traffic is always low severity.

    High-confidence threats are high severity.

    Medium-confidence threats are medium severity.

    Low-confidence threats are low severity.
    """

    if str(prediction).lower() == "normal":
        return "low"

    if confidence_level == "high":
        return "high"

    if confidence_level == "medium":
        return "medium"

    return "low"


def _get_firewall_status(
    firewall_result,
):
    """
    Convert the firewall response into a database-friendly
    status value.
    """

    if firewall_result is None:
        return "not_executed"

    if not isinstance(
        firewall_result,
        dict,
    ):
        return "unknown"

    if firewall_result.get("success") is True:
        return "success"

    return "failed"


def process_detection(
    prediction,
    confidence_score,
    ip_address=None,
    destination_ip=None,
    db=None,
):
    """
    Process a model prediction through the complete NTCF
    decision engine.

    Parameters
    ----------
    prediction : str
        Prediction returned by the threat detector.

    confidence_score : float
        Confidence score returned by the model.

    ip_address : str, optional
        Source IP associated with the detection.

    destination_ip : str, optional
        Destination IP associated with the detection.

    db : SQLAlchemy Session, optional
        Database session.

        If supplied, the completed decision is stored in
        the NTCF database.

        If omitted, the decision engine continues to work
        exactly as before.

    Returns
    -------
    dict
        Complete decision result.
    """

    # ---------------------------------------------------------
    # 1. Evaluate confidence
    # ---------------------------------------------------------

    confidence_result = process_prediction(
        prediction=prediction,
        confidence_score=confidence_score,
    )

    confidence_level = confidence_result[
        "confidence_level"
    ]

    # ---------------------------------------------------------
    # 2. Determine response action
    # ---------------------------------------------------------

    response_result = determine_response(
        prediction=prediction,
        confidence_level=confidence_level,
        ip_address=ip_address,
    )

    # ---------------------------------------------------------
    # 3. Calculate severity
    # ---------------------------------------------------------

    severity = _calculate_severity(
        prediction=prediction,
        confidence_level=confidence_level,
    )

    # ---------------------------------------------------------
    # 4. Build decision result
    # ---------------------------------------------------------

    result = {
        "prediction": prediction,
        "confidence_score": confidence_score,
        "confidence_level": confidence_level,
        "action": response_result["action"],
        "message": response_result["message"],
        "severity": severity,
    }

    # ---------------------------------------------------------
    # 5. Include firewall information when available
    # ---------------------------------------------------------

    firewall_result = response_result.get(
        "firewall"
    )

    if firewall_result is not None:
        result["firewall"] = firewall_result

    # ---------------------------------------------------------
    # 6. Log completed decision
    # ---------------------------------------------------------

    log_event(result)

    # ---------------------------------------------------------
    # 7. Persist completed event when database is supplied
    # ---------------------------------------------------------

    if db is not None:

        from database.repositories import (
            Repository,
        )

        repository = Repository(db)

        firewall_status = _get_firewall_status(
            firewall_result
        )

        database_result = (
            repository.save_detection_event(
                source_ip=ip_address,
                destination_ip=destination_ip,
                prediction=prediction,
                confidence=confidence_score,
                label=(
                    "Normal"
                    if str(prediction).lower()
                    == "normal"
                    else "Threat"
                ),
                confidence_level=confidence_level,
                severity=severity,
                action=response_result["action"],
                firewall_status=firewall_status,
                reason=response_result["message"],
            )
        )

        result["database"] = {
            "threat_event_id": (
                database_result[
                    "threat_event"
                ].id
            ),
            "detection_result_id": (
                database_result[
                    "detection_result"
                ].id
            ),
        }

        if database_result[
            "firewall_action"
        ] is not None:

            result["database"][
                "firewall_action_id"
            ] = (
                database_result[
                    "firewall_action"
                ].id
            )

    return result