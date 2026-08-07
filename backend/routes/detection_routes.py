"""
Detection API endpoints.
"""

from flask import Blueprint
from flask import jsonify
from flask import request

from backend.services.detection_service import (
    detect_threat,
)

detection_bp = Blueprint(
    "detection",
    __name__,
    url_prefix="/api/detection",
)


@detection_bp.route("/health", methods=["GET"])
def health():

    return jsonify(
        {
            "module": "detection",
            "status": "running",
        }
    )


@detection_bp.route("/predict", methods=["POST"])
def predict():

    payload = request.get_json(silent=True)

    response = detect_threat(payload)

    status_code = response.pop("status_code")

    return jsonify(response), status_code