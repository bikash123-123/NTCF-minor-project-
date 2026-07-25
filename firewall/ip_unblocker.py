"""
ip_unblocker.py

Reusable, low-level IP unblocking module for the
Network Threat Cognition Framework (NTCF).

Mirrors ip_blocker.py: this module only knows how to build and
safely execute the command that removes a firewall block for an
IP address. State tracking lives in firewall_manager.py.

SAFETY
------
Like ip_blocker.py, this only touches the real OS firewall when
dry_run=False is explicitly passed. See ip_blocker.py for details.
"""

import platform
import subprocess

from firewall.ip_blocker import FirewallCommandError, is_valid_ip  # noqa: F401


def build_unblock_command(ip_address, rule_name=None):
    """
    Build the OS-specific command used to remove a firewall block
    for an IP address.

    Parameters
    ----------
    ip_address : str
        A validated IP address.

    rule_name : str, optional
        Name of the firewall rule to remove. Defaults to the name
        that build_block_command() would have used for this IP.

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
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}",
        ]

    if system == "Linux":
        return [
            "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP",
        ]

    raise FirewallCommandError(
        f"Unsupported platform for firewall unblocking: '{system}'."
    )


def execute_unblock(ip_address, rule_name=None, dry_run=True):
    """
    Execute the OS firewall command to remove a block on an IP
    address.

    Parameters
    ----------
    ip_address : str
        A validated IP address.

    rule_name : str, optional
        Name of the firewall rule to remove.

    dry_run : bool
        If True (default), the command is built and returned but
        NOT executed. Set to False only when testing in an isolated
        lab or controlled test environment, per the safety
        requirement of issue #21.

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

    command = build_unblock_command(ip_address, rule_name=rule_name)

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
            f"Failed to unblock {ip_address}: "
            f"{error.stderr.strip() or error}"
        ) from error
