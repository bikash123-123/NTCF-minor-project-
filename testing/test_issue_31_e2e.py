"""
Issue #31 — Complete NTCF End-to-End Integration Test

Verifies:

    Packet capture
        ->
    Flow feature extraction
        ->
    NSL-KDD adapter
        ->
    Preprocessing
        ->
    ML prediction
        ->
    Confidence calculation
        ->
    Decision engine
        ->
    Firewall response
        ->
    Event logger
        ->
    Database persistence

No real packet capture or real firewall modification is performed.
"""

import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import ntcf_pipeline

from database.models import Base


# ---------------------------------------------------------------------
# Test database
# ---------------------------------------------------------------------


@pytest.fixture
def integration_database(tmp_path, monkeypatch):
    """
    Create an isolated SQLite database for the Issue #31 E2E test.

    The production pipeline normally uses the application's database.
    This fixture replaces it with a temporary database and creates the
    complete SQLAlchemy schema before the test starts.
    """

    database_path = tmp_path / "issue31_e2e.db"

    engine = create_engine(
        f"sqlite:///{database_path}",
    )

    # IMPORTANT:
    # Create all database tables in the temporary SQLite database.
    Base.metadata.create_all(
        bind=engine,
    )

    Session = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
    )

    # Prevent run_detection_pipeline() from initializing the
    # application's normal database.
    monkeypatch.setattr(
        ntcf_pipeline,
        "init_db",
        lambda: None,
    )

    # Make the pipeline use the isolated test database.
    monkeypatch.setattr(
        ntcf_pipeline,
        "SessionLocal",
        Session,
    )

    return Session


# ---------------------------------------------------------------------
# Deterministic packet input
# ---------------------------------------------------------------------


@pytest.fixture
def parsed_packets():
    """
    Deterministic parsed packets representing one network flow.
    """

    return [
        {
            "timestamp": 1.0,
            "src_ip": "192.168.1.100",
            "dst_ip": "192.168.1.10",
            "src_port": 12345,
            "dst_port": 80,
            "protocol": "tcp",
            "packet_length": 500,
            "service": "http",
            "flag": "S0",
        },
        {
            "timestamp": 2.0,
            "src_ip": "192.168.1.100",
            "dst_ip": "192.168.1.10",
            "src_port": 12345,
            "dst_port": 80,
            "protocol": "tcp",
            "packet_length": 500,
            "service": "http",
            "flag": "S0",
        },
        {
            "timestamp": 3.0,
            "src_ip": "192.168.1.100",
            "dst_ip": "192.168.1.10",
            "src_port": 12345,
            "dst_port": 80,
            "protocol": "tcp",
            "packet_length": 500,
            "service": "http",
            "flag": "S0",
        },
    ]


# ---------------------------------------------------------------------
# Complete Issue #31 E2E test
# ---------------------------------------------------------------------


def test_issue31_complete_ntcf_e2e(
    integration_database,
    parsed_packets,
    monkeypatch,
):
    """
    Verify the complete Issue #31 NTCF integration.

    The test starts at the packet-capture boundary and verifies
    that a parsed network flow reaches:

        ML prediction
        confidence decision
        response action
        firewall layer
        event logger
        database

    No real network capture or real firewall modification
    is performed.
    """

    # -------------------------------------------------------------
    # 1. Packet capture boundary
    # -------------------------------------------------------------

    monkeypatch.setattr(
        ntcf_pipeline,
        "capture_packets",
        lambda packet_count=20: parsed_packets[:packet_count],
    )

    # -------------------------------------------------------------
    # 1b. Isolate firewall layer
    #
    # The E2E test must not depend on persistent firewall state
    # from previous test runs.
    #
    # This simulates a successful dry-run firewall block.
    # No real firewall modification is performed.
    # -------------------------------------------------------------

    monkeypatch.setattr(
        "decision_engine.response_actions.block_ip_address",
        lambda ip_address, reason, dry_run: {
            "success": True,
            "ip_address": ip_address,
            "reason": reason,
            "dry_run": dry_run,
        },
    )

    # -------------------------------------------------------------
    # 2. Run the complete production pipeline
    # -------------------------------------------------------------

    results = ntcf_pipeline.run_detection_pipeline(
        packet_count=3,
        persist_events=True,
    )

    # -------------------------------------------------------------
    # 3. Verify that a flow was processed
    # -------------------------------------------------------------

    assert results, (
        "Issue #31 E2E pipeline returned no detection results."
    )

    assert len(results) == 1

    result = results[0]

    # -------------------------------------------------------------
    # 4. Packet -> flow extraction
    # -------------------------------------------------------------

    assert result["source_ip"] == "192.168.1.100"

    assert result["destination_ip"] == "192.168.1.10"

    # -------------------------------------------------------------
    # 5. ML prediction
    # -------------------------------------------------------------

    assert "prediction" in result

    assert result["prediction"]

    # -------------------------------------------------------------
    # 6. Confidence calculation
    # -------------------------------------------------------------

    assert "confidence_score" in result

    assert isinstance(
        result["confidence_score"],
        (int, float),
    )

    assert 0.0 <= result["confidence_score"] <= 1.0

    assert result["confidence_level"] in {
        "high",
        "medium",
        "low",
    }

    # -------------------------------------------------------------
    # 7. Decision engine
    # -------------------------------------------------------------

    assert "action" in result

    assert result["action"] in {
        "allow",
        "block",
        "monitor",
        "log",
    }

    assert "message" in result

    assert result["message"]

    assert "severity" in result

    assert result["severity"] in {
        "low",
        "medium",
        "high",
    }

    # -------------------------------------------------------------
    # 8. Firewall response
    #
    # For a high-confidence threat, the decision engine invokes
    # the firewall through the response-action layer.
    #
    # The firewall is mocked above and configured as a successful
    # dry-run operation, so no real operating-system firewall
    # modification occurs.
    # -------------------------------------------------------------

    if result["action"] == "block":

        assert "firewall" in result

        firewall_result = result["firewall"]

        assert firewall_result is not None

        assert firewall_result["success"] is True

        assert firewall_result["status"] == "success"

        assert (
            firewall_result["ip_address"]
            == "192.168.1.100"
        )

        assert (
            firewall_result["reason"]
            == "High confidence attack"
        )

        assert firewall_result["dry_run"] is True

    # -------------------------------------------------------------
    # 9. Database persistence
    # -------------------------------------------------------------

    assert "database" in result

    database_result = result["database"]

    assert "threat_event_id" in database_result

    assert database_result["threat_event_id"] is not None

    assert "detection_result_id" in database_result

    assert database_result["detection_result_id"] is not None

    # -------------------------------------------------------------
    # 10. Verify persisted records directly
    # -------------------------------------------------------------

    db = integration_database()

    try:
        from database.models import (
            ThreatEvent,
            DetectionResult,
        )

        threat_event = (
            db.query(ThreatEvent)
            .filter(
                ThreatEvent.id
                == database_result["threat_event_id"]
            )
            .first()
        )

        detection_result = (
            db.query(DetectionResult)
            .filter(
                DetectionResult.id
                == database_result["detection_result_id"]
            )
            .first()
        )

        # ---------------------------------------------------------
        # Threat event was persisted.
        # ---------------------------------------------------------

        assert threat_event is not None

        assert (
            threat_event.source_ip
            == "192.168.1.100"
        )

        assert (
            threat_event.destination_ip
            == "192.168.1.10"
        )

        assert (
            threat_event.threat_type
            == result["prediction"]
        )

        # ---------------------------------------------------------
        # Detection result was persisted.
        # ---------------------------------------------------------

        assert detection_result is not None

        assert (
            detection_result.prediction
            == result["prediction"]
        )

        assert (
            detection_result.confidence
            == result["confidence_score"]
        )

        assert (
            detection_result.confidence_level
            == result["confidence_level"]
        )

    finally:
        db.close()