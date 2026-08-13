"""
packet_parser.py

Reusable packet parsing module for the
Network Threat Cognition Framework (NTCF).

This module extracts useful information
from captured IPv4 network packets.
"""

from scapy.layers.inet import IP, TCP, UDP


def _get_service(port):
    """
    Map common destination ports to NSL-KDD-style
    service names.

    Unknown ports are represented as 'other'.
    """

    services = {
        20: "ftp_data",
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "domain_u",
        80: "http",
        110: "pop_3",
        111: "sunrpc",
        119: "nntp",
        143: "imap4",
        443: "http_443",
        513: "login",
        514: "shell",
        587: "smtp",
        631: "printer",
        993: "imap4",
        995: "pop_3",
    }

    return services.get(port, "other")


def _get_tcp_flag(tcp_layer):
    """
    Convert Scapy TCP flags into an NSL-KDD-style flag.
    """

    flags = str(tcp_layer.flags)

    if "S" in flags and "A" not in flags:
        return "S0"

    if "S" in flags and "A" in flags:
        return "S1"

    if "R" in flags:
        return "REJ"

    if "F" in flags:
        return "SF"

    if "P" in flags:
        return "SF"

    return "OTH"


def parse_packet(packet):
    """
    Parse a Scapy IPv4 packet.

    Packets without an IPv4 layer are ignored because
    the NTCF flow pipeline requires source and destination
    IPv4 addresses.

    Returns
    -------
    dict or None
        Parsed packet information, or None when the packet
        is not an IPv4 packet.
    """

    # -----------------------------------------------------
    # Ignore non-IPv4 packets
    # -----------------------------------------------------

    if IP not in packet:
        return None

    ip_layer = packet[IP]

    packet_info = {
        "timestamp": packet.time,
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "protocol": None,
        "src_port": None,
        "dst_port": None,
        "service": "other",
        "flag": "OTH",
        "packet_length": len(packet),
    }

    # -----------------------------------------------------
    # TCP
    # -----------------------------------------------------

    if TCP in packet:

        tcp_layer = packet[TCP]

        packet_info["protocol"] = "TCP"
        packet_info["src_port"] = tcp_layer.sport
        packet_info["dst_port"] = tcp_layer.dport

        packet_info["service"] = _get_service(
            tcp_layer.dport
        )

        packet_info["flag"] = _get_tcp_flag(
            tcp_layer
        )

    # -----------------------------------------------------
    # UDP
    # -----------------------------------------------------

    elif UDP in packet:

        udp_layer = packet[UDP]

        packet_info["protocol"] = "UDP"
        packet_info["src_port"] = udp_layer.sport
        packet_info["dst_port"] = udp_layer.dport

        packet_info["service"] = _get_service(
            udp_layer.dport
        )

        packet_info["flag"] = "SF"

    # -----------------------------------------------------
    # Other IPv4 protocol
    # -----------------------------------------------------

    else:

        packet_info["protocol"] = str(
            ip_layer.proto
        )

    return packet_info