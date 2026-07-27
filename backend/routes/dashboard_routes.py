from flask import Blueprint, jsonify

dashboard_bp = Blueprint(
    "dashboard",
    __name__,
    url_prefix="/dashboard"
)


@dashboard_bp.route("/health", methods=["GET"])
def dashboard_health():
    return jsonify(
        {
            "module": "dashboard",
            "status": "running"
        }
    )