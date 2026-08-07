"""
threat_service.py

Service layer for retrieving threat events from the
Network Threat Cognition Framework (NTCF).

Threat events are read from the detection event log.
"""

import json
from pathlib import Path


LOG_FILE = Path("logs/detection_events.log")


def _load_events():
    """
    Load all threat events from the log file.
    """

    if not LOG_FILE.exists():
        return []

    events = []

    with open(LOG_FILE, "r", encoding="utf-8") as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            try:
                events.append(json.loads(line))

            except json.JSONDecodeError:
                continue

    return events


def get_all_threats(
    prediction=None,
    confidence_level=None,
    action=None,
):
    """
    Retrieve all threat events with optional filtering.
    """

    events = _load_events()

    if prediction:

        events = [
            event
            for event in events
            if event.get("prediction", "").lower()
            == prediction.lower()
        ]

    if confidence_level:

        events = [
            event
            for event in events
            if event.get("confidence_level", "").lower()
            == confidence_level.lower()
        ]

    if action:

        events = [
            event
            for event in events
            if event.get("action", "").lower()
            == action.lower()
        ]

    return {
        "success": True,
        "status_code": 200,
        "count": len(events),
        "data": events,
    }


def get_threat(index):
    """
    Retrieve one threat event by index.
    """

    events = _load_events()

    if index < 0 or index >= len(events):

        return {
            "success": False,
            "status_code": 404,
            "message": "Threat event not found.",
        }

    return {
        "success": True,
        "status_code": 200,
        "data": events[index],
    }