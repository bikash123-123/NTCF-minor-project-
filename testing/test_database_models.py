"""
Tests for the NTCF database models.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def create_test_database():
    """
    Create an isolated in-memory SQLite database.
    """

    from database.connection import Base

    engine = create_engine(
        "sqlite:///:memory:",
        echo=False,
    )

    Base.metadata.create_all(
        bind=engine
    )

    Session = sessionmaker(
        bind=engine
    )

    return engine, Session


def test_detection_result_prediction_is_string():
    """
    ML predictions must support string class names.
    """

    from database.models import (
        ThreatEvent,
        DetectionResult,
    )

    _, Session = create_test_database()

    db = Session()

    event = ThreatEvent(
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        threat_type="buffer_overflow",
        confidence=1.0,
        severity="high",
    )

    db.add(event)
    db.flush()

    result = DetectionResult(
        threat_event_id=event.id,
        prediction="buffer_overflow",
        confidence=1.0,
        label="Threat",
        confidence_level="high",
    )

    db.add(result)
    db.commit()

    saved = (
        db.query(DetectionResult)
        .first()
    )

    assert saved.prediction == "buffer_overflow"
    assert isinstance(
        saved.prediction,
        str,
    )

    db.close()


def test_complete_detection_event_can_be_stored():
    """
    Verify that one NTCF detection can be stored together
    with its decision and firewall action.
    """

    from database.models import (
        ThreatEvent,
        DetectionResult,
        FirewallAction,
    )

    _, Session = create_test_database()

    db = Session()

    event = ThreatEvent(
        source_ip="10.0.0.5",
        destination_ip="10.0.0.10",
        threat_type="buffer_overflow",
        confidence=1.0,
        severity="high",
    )

    db.add(event)
    db.flush()

    detection = DetectionResult(
        threat_event_id=event.id,
        prediction="buffer_overflow",
        confidence=1.0,
        label="Threat",
        confidence_level="high",
    )

    action = FirewallAction(
        threat_event_id=event.id,
        action="block",
        status="success",
        reason="High confidence attack",
    )

    db.add(detection)
    db.add(action)

    db.commit()

    saved_event = (
        db.query(ThreatEvent)
        .first()
    )

    assert saved_event is not None
    assert saved_event.threat_type == "buffer_overflow"

    assert (
        saved_event.detection_result.prediction
        == "buffer_overflow"
    )

    assert len(
        saved_event.firewall_actions
    ) == 1

    assert (
        saved_event.firewall_actions[0].action
        == "block"
    )

    db.close()