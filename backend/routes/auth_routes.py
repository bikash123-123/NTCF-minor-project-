from flask import Blueprint, jsonify

auth_bp = Blueprint(
    "auth",
    __name__,
    url_prefix="/auth"
)


@auth_bp.route("/health", methods=["GET"])
def auth_health():
    return jsonify(
        {
            "module": "authentication",
            "status": "running"
        }
    )