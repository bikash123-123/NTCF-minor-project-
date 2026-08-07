"""
Dashboard API endpoints.

Provides dashboard statistics for the
Network Threat Cognition Framework (NTCF).
"""

from collections import Counter

from flask import Blueprint
from flask import jsonify

from backend.services.firewall_service import (
    get_blocked_ips,
)

from backend.services.threat_service import (
    get_all_threats,
)

dashboard_bp = Blueprint(
    "dashboard",
    __name__,
    url_prefix="/api/dashboard",
)


@dashboard_bp.route("/health", methods=["GET"])
def dashboard_health():
    """
    Health check.
    """

    return jsonify(
        {
            "module": "dashboard",
            "status": "running",
        }
    )


@dashboard_bp.route("/statistics", methods=["GET"])
def dashboard_statistics():
    """
    Return dashboard statistics.
    """

    # ----------------------------------------
    # Threat Statistics
    # ----------------------------------------

    threat_response = get_all_threats()

    threats = threat_response.get(
        "data",
        [],
    )

    total_threats = len(threats)

    # ----------------------------------------
    # Detection Statistics
    # ----------------------------------------

    total_detections = total_threats

    # ----------------------------------------
    # Prediction Statistics
    # ----------------------------------------

    prediction_counter = Counter()

    confidence_counter = Counter()

    action_counter = Counter()

    for threat in threats:

        prediction = threat.get(
            "prediction",
            "unknown",
        )

        prediction_counter[prediction] += 1

        confidence = threat.get(
            "confidence_level",
            "unknown",
        )

        confidence_counter[confidence] += 1

        action = threat.get(
            "action",
            "none",
        )

        action_counter[action] += 1

    # ----------------------------------------
    # Firewall Statistics
    # ----------------------------------------

    firewall_response = get_blocked_ips()

    blocked_ips = firewall_response.get(
        "blocked_ips",
        {},
    )

    total_blocked_ips = len(blocked_ips)

    # ----------------------------------------
    # Final Response
    # ----------------------------------------

    return jsonify(

        {
            "success": True,

            "statistics":

            {

                "total_detections":
                    total_detections,

                "total_threats":
                    total_threats,

                "blocked_ips":
                    total_blocked_ips,
            },

            "threat_statistics":

            {

                "prediction_counts":
                    dict(prediction_counter),

                "confidence_levels":
                    dict(confidence_counter),

                "actions":
                    dict(action_counter),
            },

            "chart_data":

            {

                "predictions":
                    dict(prediction_counter),

                "confidence":
                    dict(confidence_counter),
            },

        }

    )