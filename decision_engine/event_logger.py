"""
event_logger.py

Logging utilities for threat detection events.
"""

from datetime import datetime
import json
from pathlib import Path


LOG_FILE = Path("logs/detection_events.log")


def log_event(event):
    """
    Log a detection event.

    Parameters
    ----------
    event : dict
        Event information.
    """

    LOG_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        **event,
    }

    with open(
        LOG_FILE,
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            json.dumps(log_entry)
        )
        file.write("\n")