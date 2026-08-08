"""
Authentication service for the NTCF backend.

Provides database-backed user registration,
authentication, password hashing, and token management.
"""

from functools import wraps
import secrets
import time

from flask import request
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)

from database.connection import SessionLocal
from database.models import User


# ---------------------------------------------------------
# Authentication token configuration
# ---------------------------------------------------------

_TOKENS = {}

TOKEN_EXPIRY_SECONDS = 3600


# ---------------------------------------------------------
# Helper
# ---------------------------------------------------------

def _normalize_email(email):
    """
    Normalize an optional email address.

    Returns:
        None if no email is supplied.
        Cleaned string otherwise.
    """

    if email is None:
        return None

    if not isinstance(email, str):
        return None

    email = email.strip()

    if not email:
        return None

    return email


# ---------------------------------------------------------
# Register user
# ---------------------------------------------------------

def register_user(username, password, email=None):
    """
    Register a new user in the database.
    """

    # -----------------------------------------------------
    # Validate username
    # -----------------------------------------------------

    if not isinstance(username, str) or not username.strip():
        return {
            "success": False,
            "error": "Username is required.",
        }

    username = username.strip()

    if len(username) < 3:
        return {
            "success": False,
            "error": "Username must contain at least 3 characters.",
        }

    # -----------------------------------------------------
    # Validate password
    # -----------------------------------------------------

    if not isinstance(password, str) or not password:
        return {
            "success": False,
            "error": "Password is required.",
        }

    if len(password) < 8:
        return {
            "success": False,
            "error": "Password must contain at least 8 characters.",
        }

    # -----------------------------------------------------
    # Validate email
    # -----------------------------------------------------

    if email is not None and not isinstance(email, str):
        return {
            "success": False,
            "error": "Email must be a string.",
        }

    email = _normalize_email(email)

    # -----------------------------------------------------
    # Open database session
    # -----------------------------------------------------

    db = SessionLocal()

    try:

        # -------------------------------------------------
        # Check existing username
        # -------------------------------------------------

        existing_user = (
            db.query(User)
            .filter(User.username == username)
            .first()
        )

        if existing_user is not None:
            return {
                "success": False,
                "error": "User already exists.",
            }

        # -------------------------------------------------
        # Check existing email
        # -------------------------------------------------

        if email is not None:

            existing_email = (
                db.query(User)
                .filter(User.email == email)
                .first()
            )

            if existing_email is not None:
                return {
                    "success": False,
                    "error": "Email already exists.",
                }

        # -------------------------------------------------
        # Hash password
        # -------------------------------------------------

        password_hash = generate_password_hash(password)

        # -------------------------------------------------
        # Create database user
        # -------------------------------------------------

        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
        )

        db.add(user)

        db.commit()

        db.refresh(user)

        return {
            "success": True,
            "message": "User registered successfully.",
        }

    except IntegrityError:

        # ---------------------------------------------
        # Roll back failed transaction
        # ---------------------------------------------

        db.rollback()

        return {
            "success": False,
            "error": "Username or email already exists.",
        }

    except SQLAlchemyError:

        # ---------------------------------------------
        # Roll back database transaction
        # ---------------------------------------------

        db.rollback()

        return {
            "success": False,
            "error": "Database error while registering user.",
        }

    finally:

        db.close()


# ---------------------------------------------------------
# Authenticate user
# ---------------------------------------------------------

def authenticate_user(username, password):
    """
    Authenticate a user using the database.
    """

    if not isinstance(username, str):
        return {
            "success": False,
            "error": "Invalid credentials.",
        }

    if not isinstance(password, str):
        return {
            "success": False,
            "error": "Invalid credentials.",
        }

    db = SessionLocal()

    try:

        user = (
            db.query(User)
            .filter(User.username == username)
            .first()
        )

        if user is None:
            return {
                "success": False,
                "error": "Invalid credentials.",
            }

        if not user.password_hash:
            return {
                "success": False,
                "error": "Invalid credentials.",
            }

        if not check_password_hash(
            user.password_hash,
            password,
        ):
            return {
                "success": False,
                "error": "Invalid credentials.",
            }

        return {
            "success": True,
            "username": user.username,
        }

    except SQLAlchemyError:

        return {
            "success": False,
            "error": "Database error during authentication.",
        }

    finally:

        db.close()


# ---------------------------------------------------------
# Create token
# ---------------------------------------------------------

def create_token(username):
    """
    Generate a cryptographically secure authentication token.
    """

    token = secrets.token_urlsafe(32)

    _TOKENS[token] = {
        "username": username,
        "expires_at": time.time() + TOKEN_EXPIRY_SECONDS,
    }

    return token


# ---------------------------------------------------------
# Validate token
# ---------------------------------------------------------

def validate_token(token):
    """
    Validate an authentication token.

    Returns:
        Username if the token is valid.
        None otherwise.
    """

    if not token:
        return None

    token_data = _TOKENS.get(token)

    if token_data is None:
        return None

    if time.time() >= token_data["expires_at"]:

        _TOKENS.pop(token, None)

        return None

    return token_data["username"]


# ---------------------------------------------------------
# Revoke token
# ---------------------------------------------------------

def revoke_token(token):
    """
    Revoke an authentication token.
    """

    if not token:
        return False

    return _TOKENS.pop(token, None) is not None


# ---------------------------------------------------------
# Authentication decorator
# ---------------------------------------------------------

def require_authentication(function):
    """
    Protect an API endpoint.

    Expected header:

        Authorization: Bearer <token>
    """

    @wraps(function)
    def decorated(*args, **kwargs):

        authorization = request.headers.get(
            "Authorization",
            "",
        )

        # ---------------------------------------------
        # Authorization header missing
        # ---------------------------------------------

        if not authorization.startswith("Bearer "):

            return {
                "success": False,
                "error": "Authentication required.",
            }, 401

        # ---------------------------------------------
        # Extract token
        # ---------------------------------------------

        token = authorization[7:].strip()

        if not token:

            return {
                "success": False,
                "error": "Authentication required.",
            }, 401

        # ---------------------------------------------
        # Validate token
        # ---------------------------------------------

        username = validate_token(token)

        if username is None:

            return {
                "success": False,
                "error": "Invalid or expired token.",
            }, 401

        # ---------------------------------------------
        # Call protected endpoint
        # ---------------------------------------------

        return function(
            username,
            *args,
            **kwargs,
        )

    return decorated
