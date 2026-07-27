from flask import Blueprint, jsonify

detection_bp = Blueprint(
    "detection",
    __name__,
    url_prefix="/detection"
)


@detection_bp.route("/health", methods=["GET"])
def detection_health():
    return jsonify(
        {
            "module": "detection",
            "status": "running"
        }
    )