"""
Authentication API endpoints.
"""

<<<<<<< HEAD
from flask import Blueprint, jsonify, request
=======
from flask import Blueprint
from flask import jsonify
from flask import request
>>>>>>> 352303a (Implement database-backed authentication)

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


<<<<<<< HEAD
=======
# ---------------------------------------------------------
# Register
# ---------------------------------------------------------

>>>>>>> 352303a (Implement database-backed authentication)
@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Register a new user.

<<<<<<< HEAD
    Expected JSON body:
=======
    Expected JSON:
>>>>>>> 352303a (Implement database-backed authentication)

    {
        "username": "testuser",
        "password": "TestPassword123",
        "email": "testuser@example.com"
    }
    """

    payload = request.get_json(silent=True)

<<<<<<< HEAD
    # ----------------------------------------
    # Validate JSON body
    # ----------------------------------------

    if not isinstance(payload, dict):
=======
    # -----------------------------------------------------
    # Validate request body
    # -----------------------------------------------------

    if not isinstance(payload, dict):

>>>>>>> 352303a (Implement database-backed authentication)
        return jsonify(
            {
                "success": False,
                "error": "JSON object expected.",
            }
        ), 400

<<<<<<< HEAD
    # ----------------------------------------
    # Read registration fields
    # ----------------------------------------
=======
    # -----------------------------------------------------
    # Read fields
    # -----------------------------------------------------
>>>>>>> 352303a (Implement database-backed authentication)

    username = payload.get("username")
    password = payload.get("password")
    email = payload.get("email")

<<<<<<< HEAD
    # ----------------------------------------
    # Register user
    # ----------------------------------------
=======
    # -----------------------------------------------------
    # Register user
    # -----------------------------------------------------
>>>>>>> 352303a (Implement database-backed authentication)

    result = register_user(
        username,
        password,
        email=email,
    )

<<<<<<< HEAD
    # ----------------------------------------
    # Registration failed
    # ----------------------------------------

    if not result["success"]:
        return jsonify(result), 400

    # ----------------------------------------
    # Registration successful
    # ----------------------------------------
=======
    # -----------------------------------------------------
    # Registration failed
    # -----------------------------------------------------

    if not result["success"]:

        return jsonify(result), 400

    # -----------------------------------------------------
    # Registration successful
    # -----------------------------------------------------
>>>>>>> 352303a (Implement database-backed authentication)

    return jsonify(result), 201


<<<<<<< HEAD
=======
# ---------------------------------------------------------
# Login
# ---------------------------------------------------------

>>>>>>> 352303a (Implement database-backed authentication)
@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Authenticate a user and return an access token.
<<<<<<< HEAD

    Expected JSON body:

    {
        "username": "testuser",
        "password": "TestPassword123"
    }
=======
>>>>>>> 352303a (Implement database-backed authentication)
    """

    payload = request.get_json(silent=True)

<<<<<<< HEAD
    # ----------------------------------------
    # Validate JSON body
    # ----------------------------------------

    if not isinstance(payload, dict):
=======
    # -----------------------------------------------------
    # Validate request body
    # -----------------------------------------------------

    if not isinstance(payload, dict):

>>>>>>> 352303a (Implement database-backed authentication)
        return jsonify(
            {
                "success": False,
                "error": "JSON object expected.",
            }
        ), 400

<<<<<<< HEAD
    # ----------------------------------------
    # Read login fields
    # ----------------------------------------

    username = payload.get("username")
    password = payload.get("password")

    # ----------------------------------------
    # Authenticate user
    # ----------------------------------------
=======
    username = payload.get("username")
    password = payload.get("password")

    # -----------------------------------------------------
    # Authenticate
    # -----------------------------------------------------
>>>>>>> 352303a (Implement database-backed authentication)

    result = authenticate_user(
        username,
        password,
    )

<<<<<<< HEAD
    # ----------------------------------------
    # Authentication failed
    # ----------------------------------------

    if not result["success"]:
=======
    # -----------------------------------------------------
    # Authentication failed
    # -----------------------------------------------------

    if not result["success"]:

>>>>>>> 352303a (Implement database-backed authentication)
        return jsonify(
            {
                "success": False,
                "error": "Invalid credentials.",
            }
        ), 401

<<<<<<< HEAD
    # ----------------------------------------
    # Create authentication token
    # ----------------------------------------
=======
    # -----------------------------------------------------
    # Generate token
    # -----------------------------------------------------
>>>>>>> 352303a (Implement database-backed authentication)

    token = create_token(username)

    return jsonify(
        {
            "success": True,
            "message": "Authentication successful.",
            "token": token,
        }
    ), 200


<<<<<<< HEAD
=======
# ---------------------------------------------------------
# Logout
# ---------------------------------------------------------

>>>>>>> 352303a (Implement database-backed authentication)
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

<<<<<<< HEAD
    # Authorization is already validated by
    # require_authentication.
=======
>>>>>>> 352303a (Implement database-backed authentication)
    token = authorization[7:].strip()

    revoke_token(token)

    return jsonify(
        {
            "success": True,
            "message": "Logout successful.",
        }
    ), 200


<<<<<<< HEAD
=======
# ---------------------------------------------------------
# Current user
# ---------------------------------------------------------

>>>>>>> 352303a (Implement database-backed authentication)
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