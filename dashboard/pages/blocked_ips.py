"""
NTCF Dashboard - Blocked IP Addresses

Issue #29
"""

import pandas as pd
import requests
import streamlit as st


FIREWALL_API = "http://127.0.0.1:5000/api/firewall"


def get_blocked_ips():

    try:

        response = requests.get(
            f"{FIREWALL_API}/blocked",
            timeout=5,
        )

        return response.status_code, response.json()

    except requests.RequestException as error:

        return None, {
            "success": False,
            "message": str(error),
        }

    except ValueError:

        return None, {
            "success": False,
            "message": "Invalid response from Firewall API.",
        }


def block_ip(ip_address, reason):

    payload = {
        "ip_address": ip_address,
        "reason": reason,
        "dry_run": True,
    }

    try:

        response = requests.post(
            f"{FIREWALL_API}/block",
            json=payload,
            timeout=5,
        )

        return response.status_code, response.json()

    except requests.RequestException as error:

        return None, {
            "success": False,
            "message": str(error),
        }

    except ValueError:

        return None, {
            "success": False,
            "message": "Invalid response from Firewall API.",
        }


def unblock_ip(ip_address):

    payload = {
        "ip_address": ip_address,
        "dry_run": True,
    }

    try:

        response = requests.post(
            f"{FIREWALL_API}/unblock",
            json=payload,
            timeout=5,
        )

        return response.status_code, response.json()

    except requests.RequestException as error:

        return None, {
            "success": False,
            "message": str(error),
        }

    except ValueError:

        return None, {
            "success": False,
            "message": "Invalid response from Firewall API.",
        }


def show_blocked_ips():

    st.title("🛡️ Blocked IP Addresses")

    st.caption(
        "View IP addresses managed by the NTCF firewall."
    )

    st.divider()

    status_code, data = get_blocked_ips()

    if status_code is None:

        st.error(
            "🔴 Unable to connect to the Firewall API."
        )

        st.info(
            "Make sure the Flask backend is running "
            "on http://127.0.0.1:5000."
        )

        return

    if status_code != 200:

        st.error(
            f"Firewall API returned HTTP {status_code}."
        )

        return

    blocked = data.get(
        "blocked_ips",
        {},
    )

    # =====================================================
    # Statistics
    # =====================================================

    st.metric(
        "🚫 Blocked IP Addresses",
        len(blocked),
    )

    st.divider()

    # =====================================================
    # Blocked IP Table
    # =====================================================

    st.subheader("📋 Current Block List")

    if not blocked:

        st.info(
            "No IP addresses are currently blocked."
        )

    else:

        rows = []

        for ip_address, info in blocked.items():

            if not isinstance(info, dict):
                info = {}

            rows.append(
                {
                    "IP Address": ip_address,
                    "Reason": info.get(
                        "reason",
                        "Not specified",
                    ),
                    "Blocked At": info.get(
                        "blocked_at",
                        "Unknown",
                    ),
                }
            )

        df = pd.DataFrame(rows)

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
        )

    # =====================================================
    # Firewall Actions
    # =====================================================

    st.divider()

    st.subheader("⚙️ Firewall Actions")

    block_column, unblock_column = st.columns(2)

    # =====================================================
    # Block
    # =====================================================

    with block_column:

        st.markdown("### 🚫 Block IP")

        ip_address = st.text_input(
            "IP Address",
            placeholder="192.168.1.100",
            key="block_ip_address",
        )

        reason = st.text_input(
            "Reason",
            placeholder="Suspicious activity",
            key="block_reason",
        )

        if st.button(
            "🚫 Block Address",
            use_container_width=True,
        ):

            if not ip_address.strip():

                st.warning(
                    "Enter an IP address."
                )

            else:

                status, result = block_ip(
                    ip_address.strip(),
                    reason.strip(),
                )

                if status is None:

                    st.error(
                        result.get(
                            "message",
                            "Firewall API unavailable.",
                        )
                    )

                elif status >= 400:

                    st.error(
                        result.get(
                            "message",
                            "Unable to block IP.",
                        )
                    )

                else:

                    st.success(
                        "Block request processed."
                    )

                    st.json(result)

    # =====================================================
    # Unblock
    # =====================================================

    with unblock_column:

        st.markdown("### ✅ Unblock IP")

        unblock_address = st.text_input(
            "IP Address",
            placeholder="192.168.1.100",
            key="unblock_ip_address",
        )

        if st.button(
            "✅ Unblock Address",
            use_container_width=True,
        ):

            if not unblock_address.strip():

                st.warning(
                    "Enter an IP address."
                )

            else:

                status, result = unblock_ip(
                    unblock_address.strip()
                )

                if status is None:

                    st.error(
                        result.get(
                            "message",
                            "Firewall API unavailable.",
                        )
                    )

                elif status >= 400:

                    st.error(
                        result.get(
                            "message",
                            "Unable to unblock IP.",
                        )
                    )

                else:

                    st.success(
                        "Unblock request processed."
                    )

                    st.json(result)