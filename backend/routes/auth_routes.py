"""
Authentication API endpoints.
"""

from flask import Blueprint
from flask import jsonify
from flask import request

from backend.services.auth_service import (
    authenticate_user,
    create_token,
    register_user,
    require_authentication,
    revoke_token,
)


auth_bp = Blueprint(
    "auth",
    __name__,
    url_prefix="/auth",
)


# ---------------------------------------------------------
# Health
# ---------------------------------------------------------

@auth_bp.route("/health", methods=["GET"])
def auth_health():
    """
    Authentication service health check.
    """

    return jsonify(
        {
            "module": "authentication",
            "status": "running",
        }
    ), 200


# ---------------------------------------------------------
# Register
# ---------------------------------------------------------

@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Register a new user.

    Expected JSON:

    {
        "username": "testuser",
        "password": "TestPassword123",
        "email": "testuser@example.com"
    }
    """

    payload = request.get_json(silent=True)

    # -----------------------------------------------------
    # Validate request body
    # -----------------------------------------------------

    if not isinstance(payload, dict):

        return jsonify(
            {
                "success": False,
                "error": "JSON object expected.",
            }
        ), 400

    # -----------------------------------------------------
    # Read fields
    # -----------------------------------------------------

    username = payload.get("username")
    password = payload.get("password")
    email = payload.get("email")

    # -----------------------------------------------------
    # Register user
    # -----------------------------------------------------

    result = register_user(
        username,
        password,
        email=email,
    )

    # -----------------------------------------------------
    # Registration failed
    # -----------------------------------------------------

    if not result["success"]:

        return jsonify(result), 400

    # -----------------------------------------------------
    # Registration successful
    # -----------------------------------------------------

    return jsonify(result), 201


# ---------------------------------------------------------
# Login
# ---------------------------------------------------------

@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Authenticate a user and return an access token.
    """

    payload = request.get_json(silent=True)

    # -----------------------------------------------------
    # Validate request body
    # -----------------------------------------------------

    if not isinstance(payload, dict):

        return jsonify(
            {
                "success": False,
                "error": "JSON object expected.",
            }
        ), 400

    username = payload.get("username")
    password = payload.get("password")

    # -----------------------------------------------------
    # Authenticate
    # -----------------------------------------------------

    result = authenticate_user(
        username,
        password,
    )

    # -----------------------------------------------------
    # Authentication failed
    # -----------------------------------------------------

    if not result["success"]:

        return jsonify(
            {
                "success": False,
                "error": "Invalid credentials.",
            }
        ), 401

    # -----------------------------------------------------
    # Generate token
    # -----------------------------------------------------

    token = create_token(username)

    return jsonify(
        {
            "success": True,
            "message": "Authentication successful.",
            "token": token,
        }
    ), 200


# ---------------------------------------------------------
# Logout
# ---------------------------------------------------------

@auth_bp.route("/logout", methods=["POST"])
@require_authentication
def logout(username):
    """
    Revoke the current authentication token.
    """

    authorization = request.headers.get(
        "Authorization",
        "",
    )

    token = authorization[7:].strip()

    revoke_token(token)

    return jsonify(
        {
            "success": True,
            "message": "Logout successful.",
        }
    ), 200


# ---------------------------------------------------------
# Current user
# ---------------------------------------------------------

@auth_bp.route("/me", methods=["GET"])
@require_authentication
def current_user(username):
    """
    Return the currently authenticated user.
    """

    return jsonify(
        {
            "success": True,
            "username": username,
        }
    ), 200
