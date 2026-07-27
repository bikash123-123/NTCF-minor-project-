"""
Application configuration.
"""

import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    """
    Flask configuration.
    """

    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "development-secret-key"
    )

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "sqlite:///ntcf.db"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    DEBUG = os.getenv(
        "FLASK_ENV",
        "development"
    ) == "development"