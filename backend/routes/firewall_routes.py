"""
firewall_routes.py

Firewall API endpoints for the Network Threat Cognition Framework
(NTCF), issue #27.

Exposes firewall management functionality (view / block / unblock
IPs) as a secure backend API. All request validation and error
translation is delegated to backend.services.firewall_service,
which in turn delegates to firewall.firewall_manager — this module
only handles the HTTP layer: reading requests and returning
responses.

SAFETY
------
Block and unblock requests default to dry_run=True (no real OS
firewall change), matching the safety requirement from issue #21.
A client must explicitly set "dry_run": false in the request body
to make a real change, and should only do so in an isolated lab or
controlled test environment.
"""

from flask import Blueprint, jsonify, request

from backend.services.firewall_service import (
    block_ip_address,
    get_blocked_ips,
    unblock_ip_address,
)

firewall_bp = Blueprint("firewall", __name__, url_prefix="/api/firewall")


@firewall_bp.route("/blocked", methods=["GET"])
def view_blocked_ips():
    """
    GET /api/firewall/blocked

    View all currently blocked IP addresses.
    """

    response = get_blocked_ips()
    status_code = response.pop("status_code")

    return jsonify(response), status_code


@firewall_bp.route("/block", methods=["POST"])
def block_ip_route():
    """
    POST /api/firewall/block

    Body (JSON)
    ------------
    ip_address : str (required)
    reason : str, optional
    dry_run : bool, optional (default True)
    """

    payload = request.get_json(silent=True) or {}

    ip_address = payload.get("ip_address")
    reason = payload.get("reason")
    dry_run = payload.get("dry_run", True)

    response = block_ip_address(ip_address, reason=reason, dry_run=dry_run)
    status_code = response.pop("status_code")

    return jsonify(response), status_code


@firewall_bp.route("/unblock", methods=["POST"])
def unblock_ip_route():
    """
    POST /api/firewall/unblock

    Body (JSON)
    ------------
    ip_address : str (required)
    dry_run : bool, optional (default True)
    """

    payload = request.get_json(silent=True) or {}

    ip_address = payload.get("ip_address")
    dry_run = payload.get("dry_run", True)

    response = unblock_ip_address(ip_address, dry_run=dry_run)
    status_code = response.pop("status_code")

    return jsonify(response), status_code
