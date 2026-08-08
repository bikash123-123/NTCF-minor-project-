"""
Tests for the NTCF decision engine.
"""

import json

from decision_engine.confidence_engine import (
    evaluate_confidence,
    process_prediction,
)

from decision_engine.response_actions import (
    determine_response,
)

from decision_engine.event_logger import (
    log_event,
)


class TestConfidenceEngine:

    def test_high_confidence(self):
        assert evaluate_confidence(0.90) == "high"
        assert evaluate_confidence(0.95) == "high"
        assert evaluate_confidence(1.0) == "high"

    def test_medium_confidence(self):
        assert evaluate_confidence(0.70) == "medium"
        assert evaluate_confidence(0.80) == "medium"
        assert evaluate_confidence(0.89) == "medium"

    def test_low_confidence(self):
        assert evaluate_confidence(0.0) == "low"
        assert evaluate_confidence(0.50) == "low"
        assert evaluate_confidence(0.69) == "low"

    def test_process_prediction(self):
        result = process_prediction(
            "attack",
            0.95,
        )

        assert result["prediction"] == "attack"
        assert result["confidence_score"] == 0.95
        assert result["confidence_level"] == "high"

    def test_process_prediction_medium(self):
        result = process_prediction(
            "attack",
            0.75,
        )

        assert result["confidence_level"] == "medium"

    def test_process_prediction_low(self):
        result = process_prediction(
            "attack",
            0.50,
        )

        assert result["confidence_level"] == "low"


class TestResponseActions:

    def test_normal_traffic_is_allowed(self):
        result = determine_response(
            prediction="normal",
            confidence_level="high",
        )

        assert result["action"] == "allow"
        assert "normal" in result["message"].lower()

    def test_high_confidence_attack_is_blocked(self):
        result = determine_response(
            prediction="attack",
            confidence_level="high",
        )

        assert result["action"] == "block"
        assert "malicious" in result["message"].lower()

    def test_high_confidence_attack_with_ip(self, monkeypatch):
        def mock_block_ip_address(
            ip_address,
            reason,
            dry_run,
        ):
            return {
                "success": True,
                "ip_address": ip_address,
                "reason": reason,
                "dry_run": dry_run,
            }

        monkeypatch.setattr(
            "decision_engine.response_actions.block_ip_address",
            mock_block_ip_address,
        )

        result = determine_response(
            prediction="attack",
            confidence_level="high",
            ip_address="192.168.1.10",
        )

        assert result["action"] == "block"
        assert result["firewall"]["success"] is True
        assert result["firewall"]["ip_address"] == "192.168.1.10"
        assert result["firewall"]["dry_run"] is True

    def test_medium_confidence_attack_is_monitored(self):
        result = determine_response(
            prediction="attack",
            confidence_level="medium",
        )

        assert result["action"] == "monitor"
        assert "monitor" in result["message"].lower()

    def test_low_confidence_attack_is_logged(self):
        result = determine_response(
            prediction="attack",
            confidence_level="low",
        )

        assert result["action"] == "log"
        assert "logged" in result["message"].lower()

    def test_normal_prediction_is_case_insensitive(self):
        result = determine_response(
            prediction="NORMAL",
            confidence_level="low",
        )

        assert result["action"] == "allow"

    def test_high_confidence_without_ip(self):
        result = determine_response(
            prediction="attack",
            confidence_level="high",
        )

        assert result["action"] == "block"
        assert result["firewall"] is None


class TestEventLogger:

    def test_log_event_creates_file(
        self,
        tmp_path,
        monkeypatch,
    ):
        log_file = tmp_path / "detection_events.log"

        monkeypatch.setattr(
            "decision_engine.event_logger.LOG_FILE",
            log_file,
        )

        event = {
            "prediction": "attack",
            "confidence": 0.95,
        }

        log_event(event)

        assert log_file.exists()

    def test_log_event_writes_json(
        self,
        tmp_path,
        monkeypatch,
    ):
        log_file = tmp_path / "detection_events.log"

        monkeypatch.setattr(
            "decision_engine.event_logger.LOG_FILE",
            log_file,
        )

        event = {
            "prediction": "normal",
            "confidence": 0.95,
        }

        log_event(event)

        with open(
            log_file,
            "r",
            encoding="utf-8",
        ) as file:
            line = file.readline()

        data = json.loads(line)

        assert data["prediction"] == "normal"
        assert data["confidence"] == 0.95
        assert "timestamp" in data

    def test_log_event_appends_events(
        self,
        tmp_path,
        monkeypatch,
    ):
        log_file = tmp_path / "detection_events.log"

        monkeypatch.setattr(
            "decision_engine.event_logger.LOG_FILE",
            log_file,
        )

        log_event({"prediction": "attack"})
        log_event({"prediction": "normal"})

        with open(
            log_file,
            "r",
            encoding="utf-8",
        ) as file:
            lines = file.readlines()

        assert len(lines) == 2

        first = json.loads(lines[0])
        second = json.loads(lines[1])

        assert first["prediction"] == "attack"
        assert second["prediction"] == "normal"