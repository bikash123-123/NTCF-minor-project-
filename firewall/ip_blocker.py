"""
ip_blocker.py

Reusable, low-level IP blocking module for the
Network Threat Cognition Framework (NTCF).

This module is responsible for issuing the actual OS firewall
command that blocks an IP address. It does not track state
(that lives in firewall_manager.py) — it only knows how to build
and safely execute a block command for the current platform.

SAFETY
------
Blocking is only executed against the real OS firewall when
dry_run=False is explicitly passed. By default every function here
runs in dry-run mode, so this module is safe to exercise in
development without an isolated lab environment. Only disable
dry-run once you are testing in an isolated lab or controlled test
environment, as required by issue #21.
"""

import platform
import subprocess
from ipaddress import ip_address as parse_ip_address


class FirewallCommandError(Exception):
    """Raised when an OS-level firewall command fails or is unavailable."""


def is_valid_ip(ip_address):
    """
    Check whether a string is a valid IPv4 or IPv6 address.

    Parameters
    ----------
    ip_address : str

    Returns
    -------
    bool
    """

    if not isinstance(ip_address, str) or not ip_address.strip():
        return False

    try:
        parse_ip_address(ip_address.strip())
        return True
    except ValueError:
        return False


def build_block_command(ip_address, rule_name=None):
    """
    Build the OS-specific command used to block an IP address.

    Parameters
    ----------
    ip_address : str
        A validated IP address.

    rule_name : str, optional
        Name used for the firewall rule. Defaults to a name derived
        from the IP address.

    Returns
    -------
    list of str
        Command and arguments, suitable for subprocess.run().

    Raises
    ------
    FirewallCommandError
        If the current platform is not supported.
    """

    rule_name = rule_name or f"NTCF_BLOCK_{ip_address}"
    system = platform.system()

    if system == "Windows":
        return [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address}",
        ]

    if system == "Linux":
        return [
            "iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP",
        ]

    raise FirewallCommandError(
        f"Unsupported platform for firewall blocking: '{system}'."
    )


def execute_block(ip_address, rule_name=None, dry_run=True):
    """
    Execute the OS firewall command to block an IP address.

    Parameters
    ----------
    ip_address : str
        A validated IP address.

    rule_name : str, optional
        Name used for the firewall rule.

    dry_run : bool
        If True (default), the command is built and returned but
        NOT executed. This keeps the module safe to run outside an
        isolated lab environment. Set to False only when testing in
        an isolated lab or controlled test environment, per the
        safety requirement of issue #21.

    Returns
    -------
    dict
        {
            "success": bool,
            "dry_run": bool,
            "command": list of str,
            "output": str,
        }

    Raises
    ------
    FirewallCommandError
        If the command fails or the firewall binary is unavailable.
    """

    command = build_block_command(ip_address, rule_name=rule_name)

    if dry_run:
        return {
            "success": True,
            "dry_run": True,
            "command": command,
            "output": "Dry run: no OS firewall command was executed.",
        }

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
        )

        return {
            "success": True,
            "dry_run": False,
            "command": command,
            "output": result.stdout.strip(),
        }

    except FileNotFoundError as error:
        raise FirewallCommandError(
            f"Firewall utility not found for command {command}: {error}"
        ) from error

    except subprocess.CalledProcessError as error:
        raise FirewallCommandError(
            f"Failed to block {ip_address}: "
            f"{error.stderr.strip() or error}"
        ) from error
