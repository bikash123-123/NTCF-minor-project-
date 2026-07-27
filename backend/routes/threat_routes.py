from flask import Blueprint, jsonify

threat_bp = Blueprint(
    "threat",
    __name__,
    url_prefix="/threat"
)


@threat_bp.route("/health", methods=["GET"])
def threat_health():
    return jsonify(
        {
            "module": "threat",
            "status": "running"
        }
    )