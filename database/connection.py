"""
database/connection.py

Database connection and SQLAlchemy session management
for the NTCF application.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker


DATABASE_URL = "sqlite:///database/ntcf.db"


engine = create_engine(
    DATABASE_URL,
    echo=False,
)


SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


Base = declarative_base()


def get_db():
    """
    Provide a database session.

    Intended for use with the backend/API layer.
    """

    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()


def init_db():
    """
    Create all NTCF database tables.

    Importing models before create_all is important because
    SQLAlchemy must know about all model classes.
    """

    from database.models import (
        User,
        ThreatEvent,
        DetectionResult,
        FirewallAction,
    )

    # Prevent unused-import linting concerns while ensuring
    # SQLAlchemy registers all models with Base.metadata.
    _ = (
        User,
        ThreatEvent,
        DetectionResult,
        FirewallAction,
    )

    Base.metadata.create_all(
        bind=engine,
    )


if __name__ == "__main__":
    init_db()

    print(
        "NTCF database initialized successfully."
    )