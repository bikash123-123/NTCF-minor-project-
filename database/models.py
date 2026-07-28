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

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)

    username = Column(String(100), unique=True)

    email = Column(String(255), unique=True)

    password_hash = Column(Text)

    created_at = Column(
        DateTime,
        server_default=func.now(),
    )


class ThreatEvent(Base):

    __tablename__ = "threat_events"

    id = Column(Integer, primary_key=True)

    source_ip = Column(String(45))

    destination_ip = Column(String(45))

    threat_type = Column(String(100))

    confidence = Column(Float)

    severity = Column(String(20))

    detected_at = Column(
        DateTime,
        server_default=func.now(),
    )


class DetectionResult(Base):

    __tablename__ = "detection_results"

    id = Column(Integer, primary_key=True)

    threat_event_id = Column(
        Integer,
        ForeignKey("threat_events.id"),
    )

    prediction = Column(Integer)

    confidence = Column(Float)

    label = Column(String(30))

    created_at = Column(
        DateTime,
        server_default=func.now(),
    )

    threat = relationship("ThreatEvent")


class FirewallAction(Base):

    __tablename__ = "firewall_actions"

    id = Column(Integer, primary_key=True)

    threat_event_id = Column(
        Integer,
        ForeignKey("threat_events.id"),
    )

    action = Column(String(50))

    status = Column(String(30))

    reason = Column(Text)

    created_at = Column(
        DateTime,
        server_default=func.now(),
    )

    threat = relationship("ThreatEvent")