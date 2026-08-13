"""Firewall / blocked IP management page."""

import pandas as pd
import requests
import streamlit as st

from components.charts import category_bar_chart, timeline_chart, top_values_chart


FIREWALL_API = "http://127.0.0.1:5000/api/firewall"


def _request(method, endpoint, **kwargs):
    try:
        response = requests.request(
            method,
            f"{FIREWALL_API}{endpoint}",
            timeout=5,
            **kwargs,
        )
        try:
            return response.status_code, response.json()
        except ValueError:
            return response.status_code, {"message": response.text}
    except requests.RequestException as exc:
        return None, {"message": str(exc)}


def _blocked_dataframe(blocked):
    rows = []
    for ip, info in blocked.items():
        info = info if isinstance(info, dict) else {}
        rows.append(
            {
                "IP Address": ip,
                "Reason": info.get("reason", "Not specified"),
                "Blocked At": info.get("blocked_at", "Unknown"),
            }
        )
    return pd.DataFrame(rows)


def show_blocked_ips():
    st.caption("RESPONSE CONTROL")
    st.header("Blocked IP Addresses")
    st.caption("Review and manage addresses handled by the NTCF firewall service.")

    status, data = _request("GET", "/blocked")
    if status is None:
        st.error(f"Firewall API unavailable: {data.get('message')}")
        return
    if status != 200:
        st.error(f"Firewall API returned HTTP {status}.")
        return

    blocked = data.get("blocked_ips", {})
    df = _blocked_dataframe(blocked)

    st.metric("BLOCKED ADDRESSES", len(blocked))

    if not df.empty:
        st.divider()

        c1, c2 = st.columns(2)
        with c1:
            reason_counts = (
                df["Reason"]
                .fillna("Not specified")
                .value_counts()
                .to_dict()
            )
            category_bar_chart(
                reason_counts,
                "Reason",
                "Blocks by reason",
                "blocked_ip_reasons",
            )
        with c2:
            timeline_chart(
                df,
                "Blocked At",
                "Blocked addresses over time",
                "blocked_ip_timeline",
            )

        c3, c4 = st.columns(2)
        with c3:
            top_values_chart(
                df["IP Address"],
                "Most frequently blocked IPs",
                "IP Address",
                "blocked_ip_top_ips",
            )
        with c4:
            st.info(
                "Firewall success/failure is not charted because the current "
                "firewall API response does not expose per-event execution status."
            )

        st.subheader("Blocked Address Details")
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No IP addresses are currently blocked.")

    st.divider()
    block_col, unblock_col = st.columns(2)

    with block_col:
        with st.container(border=True):
            st.subheader("Block Address")
            ip = st.text_input(
                "IP address",
                placeholder="192.168.1.100",
                key="block_ip",
            )
            reason = st.text_input(
                "Reason",
                placeholder="Suspicious activity",
                key="block_reason",
            )
            if st.button(
                "🚫 Block IP",
                type="primary",
                use_container_width=True,
            ):
                if not ip.strip():
                    st.warning("Enter an IP address.")
                else:
                    code, result = _request(
                        "POST",
                        "/block",
                        json={
                            "ip_address": ip.strip(),
                            "reason": reason.strip(),
                            "dry_run": True,
                        },
                    )
                    if code and code < 400:
                        st.success("Block request processed.")
                        st.rerun()
                    else:
                        st.error(
                            result.get("message")
                            or result.get("error")
                            or "Unable to block IP."
                        )

    with unblock_col:
        with st.container(border=True):
            st.subheader("Unblock Address")
            ip = st.text_input(
                "IP address",
                placeholder="192.168.1.100",
                key="unblock_ip",
            )
            if st.button("✓ Unblock IP", use_container_width=True):
                if not ip.strip():
                    st.warning("Enter an IP address.")
                else:
                    code, result = _request(
                        "POST",
                        "/unblock",
                        json={"ip_address": ip.strip(), "dry_run": True},
                    )
                    if code and code < 400:
                        st.success("Unblock request processed.")
                        st.rerun()
                    else:
                        st.error(
                            result.get("message")
                            or result.get("error")
                            or "Unable to unblock IP."
                        )
