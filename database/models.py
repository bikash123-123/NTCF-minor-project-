"""
Database models for the NTCF project.
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    DateTime,
    ForeignKey,
    Text,
)

from sqlalchemy.sql import func

from sqlalchemy.orm import relationship

from database.connection import Base


class User(Base):
    """
    Application user.
    """

    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
    )

    username = Column(
        String(100),
        unique=True,
        nullable=False,
    )

    email = Column(
        String(255),
        unique=True,
        nullable=True,
    )

    password_hash = Column(
        Text,
        nullable=False,
    )

    created_at = Column(
        DateTime,
        server_default=func.now(),
    )


class ThreatEvent(Base):
    """
    Represents a detected network threat event.
    """

    __tablename__ = "threat_events"

    id = Column(
        Integer,
        primary_key=True,
    )

    source_ip = Column(
        String(45),
        nullable=True,
    )

    destination_ip = Column(
        String(45),
        nullable=True,
    )

    threat_type = Column(
        String(100),
        nullable=False,
    )

    confidence = Column(
        Float,
        nullable=False,
    )

    severity = Column(
        String(20),
        nullable=False,
    )

    detected_at = Column(
        DateTime,
        server_default=func.now(),
    )

    # One threat event can have detection results.
    detection_results = relationship(
        "DetectionResult",
        back_populates="threat",
        cascade="all, delete-orphan",
    )

    # One threat event can have firewall actions.
    firewall_actions = relationship(
        "FirewallAction",
        back_populates="threat",
        cascade="all, delete-orphan",
    )

    @property
    def detection_result(self):
        """
        Return the first detection result associated
        with this threat event.

        This provides singular access for code/tests that
        expect:

            threat_event.detection_result
        """

        if not self.detection_results:
            return None

        return self.detection_results[0]


class DetectionResult(Base):
    """
    Stores the ML detection result associated with a threat event.

    The prediction is a textual ML class such as:
        normal
        buffer_overflow
        neptune
        attack

    The confidence level is:
        high
        medium
        low
    """

    __tablename__ = "detection_results"

    id = Column(
        Integer,
        primary_key=True,
    )

    threat_event_id = Column(
        Integer,
        ForeignKey("threat_events.id"),
        nullable=False,
    )

    prediction = Column(
        String(100),
        nullable=False,
    )

    confidence = Column(
        Float,
        nullable=False,
    )

    confidence_level = Column(
        String(20),
        nullable=False,
    )

    label = Column(
        String(30),
        nullable=False,
    )

    created_at = Column(
        DateTime,
        server_default=func.now(),
    )

    threat = relationship(
        "ThreatEvent",
        back_populates="detection_results",
    )


class FirewallAction(Base):
    """
    Stores the response action associated with a threat event.
    """

    __tablename__ = "firewall_actions"

    id = Column(
        Integer,
        primary_key=True,
    )

    threat_event_id = Column(
        Integer,
        ForeignKey("threat_events.id"),
        nullable=False,
    )

    action = Column(
        String(50),
        nullable=False,
    )

    status = Column(
        String(30),
        nullable=False,
    )

    reason = Column(
        Text,
        nullable=True,
    )

    created_at = Column(
        DateTime,
        server_default=func.now(),
    )

    threat = relationship(
        "ThreatEvent",
        back_populates="firewall_actions",
    )