"""
packet_parser.py

Reusable packet parsing module for the
Network Threat Cognition Framework (NTCF).

This module extracts the required information
from captured network packets.
"""

from scapy.layers.inet import IP, TCP, UDP


def parse_packet(packet):
    """
    Parse a Scapy packet and extract useful information.

    Parameters
    ----------
    packet : scapy.packet.Packet
        Captured network packet.

    Returns
    -------
    dict
        Parsed packet information.
    """

    packet_info = {
        "timestamp": packet.time,
        "src_ip": None,
        "dst_ip": None,
        "protocol": None,
        "src_port": None,
        "dst_port": None,
        "packet_length": len(packet),
    }

    if IP in packet:

        ip_layer = packet[IP]

        packet_info["src_ip"] = ip_layer.src
        packet_info["dst_ip"] = ip_layer.dst

        if TCP in packet:

            tcp_layer = packet[TCP]

            packet_info["protocol"] = "TCP"
            packet_info["src_port"] = tcp_layer.sport
            packet_info["dst_port"] = tcp_layer.dport

        elif UDP in packet:

            udp_layer = packet[UDP]

            packet_info["protocol"] = "UDP"
            packet_info["src_port"] = udp_layer.sport
            packet_info["dst_port"] = udp_layer.dport

        else:

            packet_info["protocol"] = str(ip_layer.proto)

    return packet_info