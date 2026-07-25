"""
firewall_service.py

Backend service layer for the Firewall API (issue #27).

Connects the backend to the firewall management module
(firewall.firewall_manager) and translates its results and
exceptions into structured responses the route layer can turn
into HTTP responses — without duplicating the validation, state
tracking, or logging that already lives in firewall_manager.
"""

from firewall.firewall_manager import (
    DuplicateBlockError,
    InvalidIPAddressError,
    IPNotBlockedError,
)
from firewall.firewall_manager import block_ip as manager_block_ip
from firewall.firewall_manager import list_blocked_ips as manager_list_blocked_ips
from firewall.firewall_manager import unblock_ip as manager_unblock_ip
from firewall.ip_blocker import FirewallCommandError


def _error_response(message, error_type, status_code):
    """
    Build a structured error response.

    Parameters
    ----------
    message : str
    error_type : str
        One of "invalid_request", "invalid_ip", "duplicate",
        "not_blocked", "firewall_error".
    status_code : int
        HTTP status code the route layer should return.

    Returns
    -------
    dict
    """

    return {
        "success": False,
        "status_code": status_code,
        "error": message,
        "error_type": error_type,
    }


def get_blocked_ips():
    """
    Retrieve all currently blocked IP addresses.

    Returns
    -------
    dict
        {
            "success": True,
            "status_code": 200,
            "blocked_ips": {ip_address: {"reason": ..., "blocked_at": ...}},
        }
    """

    blocked_ips = manager_list_blocked_ips()

    return {
        "success": True,
        "status_code": 200,
        "blocked_ips": blocked_ips,
    }


def block_ip_address(ip_address, reason=None, dry_run=True):
    """
    Block an IP address through the firewall manager.

    Parameters
    ----------
    ip_address : str
    reason : str, optional
    dry_run : bool
        Defaults to True. Only pass False when testing in an
        isolated lab or controlled test environment, per the
        firewall module's safety requirement.

    Returns
    -------
    dict
        On success:
            {"success": True, "status_code": 201, "result": {...}}
        On failure:
            {"success": False, "status_code": int, "error": str, "error_type": str}
    """

    if not ip_address or not isinstance(ip_address, str):
        return _error_response(
            "'ip_address' is required and must be a string.",
            "invalid_request",
            status_code=400,
        )

    try:
        result = manager_block_ip(
            ip_address,
            reason=reason,
            dry_run=dry_run,
        )

        return {
            "success": True,
            "status_code": 201,
            "result": result,
        }

    except InvalidIPAddressError as error:
        return _error_response(str(error), "invalid_ip", status_code=400)

    except DuplicateBlockError as error:
        return _error_response(str(error), "duplicate", status_code=409)

    except FirewallCommandError as error:
        return _error_response(str(error), "firewall_error", status_code=500)


def unblock_ip_address(ip_address, dry_run=True):
    """
    Unblock an IP address through the firewall manager.

    Parameters
    ----------
    ip_address : str
    dry_run : bool
        Defaults to True. Only pass False when testing in an
        isolated lab or controlled test environment, per the
        firewall module's safety requirement.

    Returns
    -------
    dict
        On success:
            {"success": True, "status_code": 200, "result": {...}}
        On failure:
            {"success": False, "status_code": int, "error": str, "error_type": str}
    """

    if not ip_address or not isinstance(ip_address, str):
        return _error_response(
            "'ip_address' is required and must be a string.",
            "invalid_request",
            status_code=400,
        )

    try:
        result = manager_unblock_ip(
            ip_address,
            dry_run=dry_run,
        )

        return {
            "success": True,
            "status_code": 200,
            "result": result,
        }

    except InvalidIPAddressError as error:
        return _error_response(str(error), "invalid_ip", status_code=400)

    except IPNotBlockedError as error:
        return _error_response(str(error), "not_blocked", status_code=404)

    except FirewallCommandError as error:
        return _error_response(str(error), "firewall_error", status_code=500)
