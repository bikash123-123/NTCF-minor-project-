"""
Authentication API endpoints.
"""

from flask import Blueprint, jsonify, request

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


@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Register a new user.

    Expected JSON body:

    {
        "username": "testuser",
        "password": "TestPassword123",
        "email": "testuser@example.com"
    }
    """

    payload = request.get_json(silent=True)

    # ----------------------------------------
    # Validate JSON body
    # ----------------------------------------

    if not isinstance(payload, dict):
        return jsonify(
            {
                "success": False,
                "error": "JSON object expected.",
            }
        ), 400

    # ----------------------------------------
    # Read registration fields
    # ----------------------------------------

    username = payload.get("username")
    password = payload.get("password")
    email = payload.get("email")

    # ----------------------------------------
    # Register user
    # ----------------------------------------

    result = register_user(
        username,
        password,
        email=email,
    )

    # ----------------------------------------
    # Registration failed
    # ----------------------------------------

    if not result["success"]:
        return jsonify(result), 400

    # ----------------------------------------
    # Registration successful
    # ----------------------------------------

    return jsonify(result), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Authenticate a user and return an access token.

    Expected JSON body:

    {
        "username": "testuser",
        "password": "TestPassword123"
    }
    """

    payload = request.get_json(silent=True)

    # ----------------------------------------
    # Validate JSON body
    # ----------------------------------------

    if not isinstance(payload, dict):
        return jsonify(
            {
                "success": False,
                "error": "JSON object expected.",
            }
        ), 400

    # ----------------------------------------
    # Read login fields
    # ----------------------------------------

    username = payload.get("username")
    password = payload.get("password")

    # ----------------------------------------
    # Authenticate user
    # ----------------------------------------

    result = authenticate_user(
        username,
        password,
    )

    # ----------------------------------------
    # Authentication failed
    # ----------------------------------------

    if not result["success"]:
        return jsonify(
            {
                "success": False,
                "error": "Invalid credentials.",
            }
        ), 401

    # ----------------------------------------
    # Create authentication token
    # ----------------------------------------

    token = create_token(username)

    return jsonify(
        {
            "success": True,
            "message": "Authentication successful.",
            "token": token,
        }
    ), 200


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

    # Authorization is already validated by
    # require_authentication.
    token = authorization[7:].strip()

    revoke_token(token)

    return jsonify(
        {
            "success": True,
            "message": "Logout successful.",
        }
    ), 200


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