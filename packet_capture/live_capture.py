"""
live_capture.py

Reusable packet capture module for the
Network Threat Cognition Framework (NTCF).

Requirements
------------
Windows
    - Install Npcap
    - Enable WinPcap Compatibility Mode
    - Run as Administrator

Linux
    - Install libpcap
    - Run using sudo

Python Dependency
-----------------
scapy
"""

import platform

from scapy.all import sniff

from packet_capture.packet_parser import parse_packet


SYSTEM = platform.system()


def capture_packets(
    packet_count=10,
    interface=None,
):
    """
    Capture live network packets.

    Parameters
    ----------
    packet_count : int, default=10
        Number of packets to capture.

    interface : str, optional
        Network interface to capture from.

    Returns
    -------
    list
        Parsed packet information.
    """

    parsed_packets = []

    def process_packet(packet):
        """
        Parse every captured packet.
        """

        parsed_packets.append(
            parse_packet(packet)
        )

    try:

        sniff(
            iface=interface,
            prn=process_packet,
            count=packet_count,
            store=False,
        )

    except PermissionError:

        if SYSTEM == "Windows":

            print(
                "Permission denied. Run PowerShell or Command Prompt as Administrator."
            )

        elif SYSTEM == "Linux":

            print(
                "Permission denied. Run the program using sudo."
            )

        else:

            print(
                "Permission denied."
            )

    except KeyboardInterrupt:

        print(
            "\nPacket capture interrupted by user."
        )

    except Exception as error:

        print(
            f"Packet capture failed: {error}"
        )

    return parsed_packets


if __name__ == "__main__":

    packets = capture_packets(packet_count=5)

    print(f"Captured {len(packets)} packets.\n")

    for packet in packets:

        print(packet)