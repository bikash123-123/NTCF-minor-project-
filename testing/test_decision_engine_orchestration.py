"""
Tests for the NTCF decision engine orchestration layer.
"""

from decision_engine.decision_engine import (
    process_detection,
)


class TestDecisionEngine:

    def test_normal_detection_is_allowed(
        self,
        monkeypatch,
    ):
        monkeypatch.setattr(
            "decision_engine.decision_engine.log_event",
            lambda event: None,
        )

        result = process_detection(
            prediction="normal",
            confidence_score=0.95,
        )

        assert result["prediction"] == "normal"
        assert result["confidence_score"] == 0.95
        assert result["confidence_level"] == "high"
        assert result["action"] == "allow"

    def test_high_confidence_attack_is_blocked(
        self,
        monkeypatch,
    ):
        monkeypatch.setattr(
            "decision_engine.decision_engine.log_event",
            lambda event: None,
        )

        result = process_detection(
            prediction="attack",
            confidence_score=0.95,
        )

        assert result["prediction"] == "attack"
        assert result["confidence_level"] == "high"
        assert result["action"] == "block"

    def test_medium_confidence_attack_is_monitored(
        self,
        monkeypatch,
    ):
        monkeypatch.setattr(
            "decision_engine.decision_engine.log_event",
            lambda event: None,
        )

        result = process_detection(
            prediction="attack",
            confidence_score=0.75,
        )

        assert result["confidence_level"] == "medium"
        assert result["action"] == "monitor"

    def test_low_confidence_attack_is_logged(
        self,
        monkeypatch,
    ):
        monkeypatch.setattr(
            "decision_engine.decision_engine.log_event",
            lambda event: None,
        )

        result = process_detection(
            prediction="attack",
            confidence_score=0.50,
        )

        assert result["confidence_level"] == "low"
        assert result["action"] == "log"

    def test_detection_event_is_logged(
        self,
        monkeypatch,
    ):
        captured_events = []

        monkeypatch.setattr(
            "decision_engine.decision_engine.log_event",
            lambda event: captured_events.append(event),
        )

        result = process_detection(
            prediction="attack",
            confidence_score=0.95,
        )

        assert len(captured_events) == 1

        event = captured_events[0]

        assert event["prediction"] == "attack"
        assert event["confidence_score"] == 0.95
        assert event["confidence_level"] == "high"
        assert event["action"] == "block"

        assert result == event