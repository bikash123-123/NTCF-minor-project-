"""
firewall_manager.py

Firewall management interface for the
Network Threat Cognition Framework (NTCF).

Connects IP blocking and unblocking into a single reusable
workflow: validate the IP -> check current state -> execute the
OS firewall command -> update persisted state -> log the action.

This is the module other parts of the system (backend routes,
decision_engine response_actions) should import from — ip_blocker
and ip_unblocker are low-level and not meant to be called directly
outside of this module.

SAFETY
------
Per issue #21, real OS firewall changes should only be made in an
isolated lab or controlled test environment. All public functions
here default to dry_run=True, which exercises the full pipeline
(validation, duplicate detection, state tracking, logging) without
touching the real firewall. Pass dry_run=False only once you are
ready to test against a real, isolated firewall.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from firewall.ip_blocker import (
    FirewallCommandError,
    execute_block,
    is_valid_ip,
)
from firewall.ip_unblocker import execute_unblock

STATE_FILE = Path("firewall/blocked_ips.json")
LOG_FILE = Path("firewall/firewall_actions.log")


class InvalidIPAddressError(ValueError):
    """Raised when an IP address fails validation."""


class DuplicateBlockError(Exception):
    """Raised when attempting to block an IP that is already blocked."""


class IPNotBlockedError(Exception):
    """Raised when attempting to unblock an IP that isn't currently blocked."""


# ---------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------

def load_blocked_ips(state_file=STATE_FILE):
    """
    Load the current set of blocked IPs from disk.

    Parameters
    ----------
    state_file : str or Path

    Returns
    -------
    dict
        Mapping of ip_address -> {"reason": str, "blocked_at": str}.
        Empty dict if no state file exists yet.
    """

    state_file = Path(state_file)

    if not state_file.exists():
        return {}

    with open(state_file, "r") as file:
        return json.load(file)


def save_blocked_ips(blocked_ips, state_file=STATE_FILE):
    """
    Persist the current set of blocked IPs to disk.

    Parameters
    ----------
    blocked_ips : dict
    state_file : str or Path
    """

    state_file = Path(state_file)
    state_file.parent.mkdir(parents=True, exist_ok=True)

    with open(state_file, "w") as file:
        json.dump(blocked_ips, file, indent=4)


def is_ip_blocked(ip_address, state_file=STATE_FILE):
    """
    Check whether an IP address is currently tracked as blocked.

    Parameters
    ----------
    ip_address : str
    state_file : str or Path

    Returns
    -------
    bool
    """

    return ip_address in load_blocked_ips(state_file)


def list_blocked_ips(state_file=STATE_FILE):
    """
    List all currently blocked IP addresses and their metadata.

    Parameters
    ----------
    state_file : str or Path

    Returns
    -------
    dict
        Mapping of ip_address -> {"reason": str, "blocked_at": str}.
    """

    return load_blocked_ips(state_file)


# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------

def log_firewall_action(
    action,
    ip_address,
    status,
    detail=None,
    log_file=LOG_FILE,
):
    """
    Append a structured log entry for a firewall action.

    Parameters
    ----------
    action : str
        "block" or "unblock".

    ip_address : str

    status : str
        "success", "duplicate", "not_blocked", "invalid_ip", or
        "error".

    detail : str, optional
        Extra context, e.g. an error message.

    log_file : str or Path

    Returns
    -------
    dict
        The log entry that was written.
    """

    log_file = Path(log_file)
    log_file.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "ip_address": ip_address,
        "status": status,
        "detail": detail,
    }

    with open(log_file, "a") as file:
        file.write(json.dumps(entry) + "\n")

    return entry


# ---------------------------------------------------------------------
# High-level management interface
# ---------------------------------------------------------------------

def block_ip(ip_address, reason=None, dry_run=True, state_file=STATE_FILE):
    """
    Block an IP address through the full managed workflow:
    validate -> check for duplicates -> execute -> persist -> log.

    Parameters
    ----------
    ip_address : str

    reason : str, optional
        Why this IP is being blocked (e.g. detected threat type).

    dry_run : bool
        If True (default), no real OS firewall change is made. See
        the safety note at the top of this module.

    state_file : str or Path

    Returns
    -------
    dict
        {
            "ip_address": str,
            "status": "success" or "duplicate",
            "dry_run": bool,
            "command": list of str,
        }

    Raises
    ------
    InvalidIPAddressError
        If ip_address is not a valid IPv4/IPv6 address.

    FirewallCommandError
        If the underlying OS firewall command fails.
    """

    if not is_valid_ip(ip_address):
        log_firewall_action(
            "block", ip_address, "invalid_ip",
            detail="Not a valid IPv4/IPv6 address.",
        )
        raise InvalidIPAddressError(
            f"'{ip_address}' is not a valid IP address."
        )

    blocked_ips = load_blocked_ips(state_file)

    if ip_address in blocked_ips:
        log_firewall_action(
            "block", ip_address, "duplicate",
            detail="IP is already blocked; no action taken.",
        )
        raise DuplicateBlockError(
            f"'{ip_address}' is already blocked."
        )

    try:
        result = execute_block(ip_address, dry_run=dry_run)
    except FirewallCommandError as error:
        log_firewall_action(
            "block", ip_address, "error", detail=str(error),
        )
        raise

    blocked_ips[ip_address] = {
        "reason": reason,
        "blocked_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
    }
    save_blocked_ips(blocked_ips, state_file)

    log_firewall_action(
        "block", ip_address, "success",
        detail=f"dry_run={dry_run}, reason={reason}",
    )

    return {
        "ip_address": ip_address,
        "status": "success",
        "dry_run": result["dry_run"],
        "command": result["command"],
    }


def unblock_ip(ip_address, dry_run=True, state_file=STATE_FILE):
    """
    Unblock an IP address through the full managed workflow:
    validate -> check it is currently blocked -> execute -> persist
    -> log.

    Parameters
    ----------
    ip_address : str

    dry_run : bool
        If True (default), no real OS firewall change is made. See
        the safety note at the top of this module.

    state_file : str or Path

    Returns
    -------
    dict
        {
            "ip_address": str,
            "status": "success",
            "dry_run": bool,
            "command": list of str,
        }

    Raises
    ------
    InvalidIPAddressError
        If ip_address is not a valid IPv4/IPv6 address.

    IPNotBlockedError
        If the IP is not currently tracked as blocked.

    FirewallCommandError
        If the underlying OS firewall command fails.
    """

    if not is_valid_ip(ip_address):
        log_firewall_action(
            "unblock", ip_address, "invalid_ip",
            detail="Not a valid IPv4/IPv6 address.",
        )
        raise InvalidIPAddressError(
            f"'{ip_address}' is not a valid IP address."
        )

    blocked_ips = load_blocked_ips(state_file)

    if ip_address not in blocked_ips:
        log_firewall_action(
            "unblock", ip_address, "not_blocked",
            detail="IP is not currently blocked; no action taken.",
        )
        raise IPNotBlockedError(
            f"'{ip_address}' is not currently blocked."
        )

    try:
        result = execute_unblock(ip_address, dry_run=dry_run)
    except FirewallCommandError as error:
        log_firewall_action(
            "unblock", ip_address, "error", detail=str(error),
        )
        raise

    del blocked_ips[ip_address]
    save_blocked_ips(blocked_ips, state_file)

    log_firewall_action(
        "unblock", ip_address, "success",
        detail=f"dry_run={dry_run}",
    )

    return {
        "ip_address": ip_address,
        "status": "success",
        "dry_run": result["dry_run"],
        "command": result["command"],
    }
