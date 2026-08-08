"""
Authentication Service
"""

from datetime import datetime, timedelta

import jwt

from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)

SECRET_KEY = "CHANGE_THIS_SECRET_KEY"


class AuthService:

    def __init__(self):

        # Replace with database lookup later
        self.users = {

            "admin": {

                "password": generate_password_hash(
                    "admin123"
                )

            }

        }

    def login(
        self,
        username,
        password,
    ):

        user = self.users.get(username)

        if user is None:

            return {

                "success": False,

                "message": "Invalid username or password."

            }

        if not check_password_hash(
            user["password"],
            password,
        ):

            return {

                "success": False,

                "message": "Invalid username or password."

            }

        token = jwt.encode(

            {

                "username": username,

                "exp": datetime.utcnow() + timedelta(hours=1),

            },

            SECRET_KEY,

            algorithm="HS256",

        )

        return {

            "success": True,

            "token": token,

        }
