"""
live_capture.py

Reusable packet capture module for the
Network Threat Cognition Framework (NTCF).

Supports:
    - Fixed-size packet capture
    - Continuous live packet capture
    - Optional capture timeout
    - Network interface selection
    - Graceful Ctrl+C interruption
    - Packet parsing
    - Safe error handling

Requirements
------------
Windows:
    - Install Npcap
    - Enable WinPcap Compatibility Mode
    - Run PowerShell as Administrator if required

Linux:
    - Install libpcap
    - Run using sudo if required

Python:
    - scapy
"""

import platform

from scapy.all import sniff

from packet_capture.packet_parser import parse_packet


SYSTEM = platform.system()


# =========================================================
# Packet Capture
# =========================================================

def capture_packets(
    packet_count=10,
    interface=None,
    continuous=False,
    timeout=None,
):
    """
    Capture and parse live network packets.

    Parameters
    ----------
    packet_count : int, optional
        Number of packets to capture when continuous=False.

    interface : str, optional
        Network interface to capture from.
        None uses Scapy's default interface.

    continuous : bool, optional
        If True, capture continuously until:
            - Ctrl+C is pressed, or
            - timeout expires.

    timeout : int or float, optional
        Maximum capture duration in seconds when
        continuous=True.

    Returns
    -------
    list
        List of parsed IPv4 packet dictionaries.

    Notes
    -----
    Non-IPv4 packets are ignored by the parser.

    Existing NTCF pipeline calls such as:

        capture_packets(packet_count=20)

    continue to work exactly as before.

    Continuous capture can be used with:

        capture_packets(
            continuous=True
        )
    """

    parsed_packets = []

    # =====================================================
    # Packet Callback
    # =====================================================

    def process_packet(packet):
        """
        Process each captured Scapy packet.
        """

        try:

            parsed = parse_packet(packet)

            # -------------------------------------------------
            # Ignore unsupported packets
            # -------------------------------------------------
            # packet_parser.py returns None for packets
            # that do not contain an IPv4 layer.
            #
            # This prevents None values from entering the
            # flow extraction and database pipeline.
            # -------------------------------------------------

            if parsed is None:
                return

            parsed_packets.append(parsed)

            print(
                "[CAPTURE] "
                f"{parsed.get('src_ip')} -> "
                f"{parsed.get('dst_ip')} | "
                f"{parsed.get('protocol')} | "
                f"{parsed.get('packet_length')} bytes"
            )

        except Exception as error:

            print(
                f"[PARSER ERROR] {error}"
            )

    # =====================================================
    # Capture
    # =====================================================

    try:

        # -------------------------------------------------
        # Continuous Mode
        # -------------------------------------------------

        if continuous:

            print(
                "\n========================================"
            )

            print(
                "NTCF LIVE PACKET CAPTURE"
            )

            print(
                "========================================"
            )

            print(
                f"Interface : "
                f"{interface or 'Default'}"
            )

            if timeout is not None:

                print(
                    f"Duration  : {timeout} seconds"
                )

            else:

                print(
                    "Duration  : Continuous"
                )

            print(
                "Press CTRL+C to stop."
            )

            print(
                "----------------------------------------"
            )

            sniff(
                iface=interface,
                prn=process_packet,
                store=False,
                timeout=timeout,
            )

        # -------------------------------------------------
        # Fixed Packet Mode
        # -------------------------------------------------

        else:

            if packet_count is None:

                raise ValueError(
                    "packet_count cannot be None "
                    "when continuous=False."
                )

            if not isinstance(
                packet_count,
                int,
            ):

                raise TypeError(
                    "packet_count must be an integer."
                )

            if packet_count <= 0:

                raise ValueError(
                    "packet_count must be greater than 0."
                )

            print(
                "\n========================================"
            )

            print(
                "NTCF PACKET CAPTURE"
            )

            print(
                "========================================"
            )

            print(
                f"Interface : "
                f"{interface or 'Default'}"
            )

            print(
                f"Packet count : {packet_count}"
            )

            print(
                "----------------------------------------"
            )

            sniff(
                iface=interface,
                prn=process_packet,
                count=packet_count,
                store=False,
            )

    # =====================================================
    # Permission Error
    # =====================================================

    except PermissionError:

        if SYSTEM == "Windows":

            print(
                "\n[ERROR] Permission denied."
            )

            print(
                "Run PowerShell as Administrator."
            )

            print(
                "Also verify that Npcap is installed."
            )

        elif SYSTEM == "Linux":

            print(
                "\n[ERROR] Permission denied."
            )

            print(
                "Run the program using sudo."
            )

        else:

            print(
                "\n[ERROR] Permission denied."
            )

    # =====================================================
    # Ctrl+C
    # =====================================================

    except KeyboardInterrupt:

        print(
            "\n\n[CAPTURE] "
            "Packet capture interrupted by user."
        )

    # =====================================================
    # Invalid Configuration
    # =====================================================

    except ValueError as error:

        print(
            f"\n[CAPTURE CONFIG ERROR] {error}"
        )

    except TypeError as error:

        print(
            f"\n[CAPTURE CONFIG ERROR] {error}"
        )

    # =====================================================
    # General Error
    # =====================================================

    except Exception as error:

        print(
            f"\n[CAPTURE ERROR] {error}"
        )

    # =====================================================
    # Summary
    # =====================================================

    print(
        "\n----------------------------------------"
    )

    print(
        f"Total IPv4 packets captured: "
        f"{len(parsed_packets)}"
    )

    print(
        "----------------------------------------"
    )

    return parsed_packets


# =========================================================
# Fixed Capture Test
# =========================================================

def test_fixed_capture():
    """
    Capture a small fixed number of packets.

    Useful for testing the packet capture layer
    without starting continuous monitoring.
    """

    packets = capture_packets(
        packet_count=5
    )

    print(
        f"\nCaptured {len(packets)} IPv4 packets."
    )

    for index, packet in enumerate(
        packets,
        start=1,
    ):

        print(
            f"\nPacket {index}"
        )

        print(packet)


# =========================================================
# Continuous Capture Test
# =========================================================

def test_continuous_capture():
    """
    Start continuous packet capture.

    Stop using CTRL+C.
    """

    packets = capture_packets(
        continuous=True
    )

    print(
        f"\nCaptured {len(packets)} IPv4 packets "
        "before stopping."
    )


# =========================================================
# Standalone Test
# =========================================================

if __name__ == "__main__":

    # -----------------------------------------------------
    # Change this to True if you want continuous capture.
    # -----------------------------------------------------

    CONTINUOUS_MODE = False

    if CONTINUOUS_MODE:

        test_continuous_capture()

    else:

        test_fixed_capture()