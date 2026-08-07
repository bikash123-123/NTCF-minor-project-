"""
threat_routes.py

Threat API endpoints.
"""

from flask import Blueprint
from flask import jsonify
from flask import request

from backend.services.threat_service import (
    get_all_threats,
    get_threat,
)

threat_bp = Blueprint(
    "threat",
    __name__,
    url_prefix="/api/threats",
)


@threat_bp.route("/health", methods=["GET"])
def health():

    return jsonify(
        {
            "module": "threat",
            "status": "running",
        }
    )


@threat_bp.route("", methods=["GET"])
def retrieve_threats():

    prediction = request.args.get("prediction")

    confidence_level = request.args.get(
        "confidence_level"
    )

    action = request.args.get("action")

    response = get_all_threats(
        prediction=prediction,
        confidence_level=confidence_level,
        action=action,
    )

    status_code = response.pop("status_code")

    return jsonify(response), status_code


@threat_bp.route("/<int:index>", methods=["GET"])
def retrieve_threat(index):

    response = get_threat(index)

    status_code = response.pop("status_code")

    return jsonify(response), status_code