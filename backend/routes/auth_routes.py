from flask import Blueprint, jsonify, request

from backend.services.auth_service import AuthService

auth_bp = Blueprint(
    "auth",
    __name__,
    url_prefix="/auth"
)

auth_service = AuthService()


@auth_bp.route("/health", methods=["GET"])
def auth_health():
    return jsonify(
        {
            "module": "authentication",
            "status": "running"
        }
    )


@auth_bp.route("/login", methods=["POST"])
def login():

    data = request.get_json()

    if not data:
        return jsonify(
            {
                "message": "Request body is required."
            }
        ), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:

        return jsonify(
            {
                "message": "Username and password are required."
            }
        ), 400

    result = auth_service.login(
        username,
        password,
    )

    if not result["success"]:

        return jsonify(
            {
                "message": result["message"]
            }
        ), 401

    return jsonify(
        {
            "message": "Login successful",
            "token": result["token"]
        }
    ), 200