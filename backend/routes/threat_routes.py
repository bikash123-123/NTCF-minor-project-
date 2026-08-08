"""
Threat API endpoints.
"""

from flask import Blueprint
from flask import jsonify
from flask import request

from backend.services.threat_service import (
    get_all_threats,
    get_threat,
)

from backend.services.auth_service import (
    require_authentication,
)


# ---------------------------------------------------------
# Blueprint
# ---------------------------------------------------------

threat_bp = Blueprint(
    "threat",
    __name__,
    url_prefix="/api/threats",
)


# ---------------------------------------------------------
# Health check
# ---------------------------------------------------------

@threat_bp.route("/health", methods=["GET"])
def health():
    """
    Threat service health check.
    """

    return jsonify(
        {
            "module": "threat",
            "status": "running",
        }
    ), 200


# ---------------------------------------------------------
# Get all threats
# ---------------------------------------------------------

@threat_bp.route("", methods=["GET"])
@require_authentication
def retrieve_threats(username):
    """
    Retrieve all threat events.

    Authentication is required.
    """

    prediction = request.args.get(
        "prediction"
    )

    confidence_level = request.args.get(
        "confidence_level"
    )

    action = request.args.get(
        "action"
    )

    response = get_all_threats(
        prediction=prediction,
        confidence_level=confidence_level,
        action=action,
    )

    status_code = response.pop(
        "status_code",
        200,
    )

    return jsonify(response), status_code


# ---------------------------------------------------------
# Get one threat
# ---------------------------------------------------------

@threat_bp.route(
    "/<int:index>",
    methods=["GET"],
)
@require_authentication
def retrieve_threat(username, index):
    """
    Retrieve one threat event by zero-based index.

    Authentication is required.
    """

    response = get_threat(index)

    status_code = response.pop(
        "status_code",
        200,
    )

    return jsonify(response), status_code