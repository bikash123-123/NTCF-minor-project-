"""
Database connection.
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

    db = SessionLocal()

    try:

        yield db

    finally:

        db.close()

        # ------------------------------
# Create database tables
# ------------------------------
if __name__ == "__main__":
    from database.models import *

    Base.metadata.create_all(bind=engine)

    print("Database created successfully.")