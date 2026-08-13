"""Threat event page using the existing authenticated Threat API."""

import pandas as pd
import requests
import streamlit as st

from components.threat_families import add_threat_family
from components.charts import (
    action_chart,
    category_bar_chart,
    confidence_chart,
    multi_timeline_chart,
    numeric_confidence_chart,
    prediction_chart,
    severity_chart,
    top_values_chart,
)

THREAT_API = "http://127.0.0.1:5000/api/threats"


def _headers():
    token = st.session_state.get("auth_token")
    return {"Authorization": f"Bearer {token}"} if token else None


def _flatten_events(data):
    rows = []
    for event in data:
        row = dict(event)
        detection = row.pop("detection", None) or {}
        firewall = row.pop("firewall", None) or {}
        for key, value in detection.items():
            row.setdefault(key, value)
        for key, value in firewall.items():
            row.setdefault(key, value)
        rows.append(row)
    return pd.DataFrame(rows)


def show_threats():
    st.caption("THREAT INTELLIGENCE")
    st.header("Threat Events")
    st.caption("Recorded events produced by the NTCF detection and decision pipeline.")

    headers = _headers()
    if not headers:
        st.error("Authentication required.")
        return

    try:
        response = requests.get(THREAT_API, headers=headers, timeout=5)
    except requests.RequestException as exc:
        st.error(f"Unable to connect to the Threat API: {exc}")
        return

    if response.status_code == 401:
        st.session_state.logged_in = False
        st.session_state.auth_token = None
        st.session_state.username = None
        st.rerun()
        return
    if response.status_code != 200:
        st.error(f"Threat API returned HTTP {response.status_code}.")
        return

    try:
        data = response.json().get("data", [])
    except ValueError:
        st.error("Threat API returned invalid JSON.")
        return

    df = _flatten_events(data)
    if df.empty:
        st.info("No threat events are currently available.")
        return

    df = add_threat_family(df)
    confidence = df.get("confidence_level", pd.Series(dtype=str)).astype(str).str.lower()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("EVENTS", len(df))
    c2.metric("HIGH CONFIDENCE", int((confidence == "high").sum()))
    c3.metric("MEDIUM CONFIDENCE", int((confidence == "medium").sum()))
    c4.metric("LOW CONFIDENCE", int((confidence == "low").sum()))

    st.divider()

    row1a, row1b = st.columns(2)
    with row1a:
        prediction_chart(
            df.get("prediction", pd.Series(dtype=str)).value_counts().to_dict(),
            key="threats_predictions",
        )
    with row1b:
        confidence_chart(
            confidence.value_counts().to_dict(),
            key="threats_confidence",
        )

    row2a, row2b = st.columns(2)
    with row2a:
        category_bar_chart(
            df.get("threat_family", pd.Series(dtype=str))
            .fillna("Unknown")
            .astype(str)
            .value_counts()
            .to_dict(),
            "Threat Family",
            "Threat family distribution",
            "threats_families",
        )
    with row2b:
        category_bar_chart(
            df.get("threat_type", pd.Series(dtype=str))
            .fillna("Unknown")
            .astype(str)
            .value_counts()
            .to_dict(),
            "Threat Type",
            "Threat type distribution",
            "threats_types",
        )

    row3a, row3b = st.columns(2)
    with row3a:
        severity_chart(
            df.get("severity", pd.Series(dtype=str))
            .fillna("Unknown")
            .astype(str)
            .value_counts()
            .to_dict(),
            key="threats_severity",
        )
    with row3b:
        action_chart(
            df.get("action", pd.Series(dtype=str))
            .fillna("none")
            .astype(str)
            .value_counts()
            .to_dict(),
            key="threats_actions",
        )

    row4a, row4b = st.columns(2)
    with row4a:
        numeric_confidence_chart(
            df.get("confidence", pd.Series(dtype=float)),
            key="threats_numeric_confidence",
        )
    with row4b:
        top_values_chart(
            df.get("source_ip", pd.Series(dtype=str)),
            "Top source IPs",
            "Source IP",
            "threats_source_ips",
        )

    multi_timeline_chart(
        df,
        "detected_at",
        "severity",
        "Threat activity over time by severity",
        "threats_timeline",
    )

    st.subheader("Top Destination IPs")
    top_values_chart(
        df.get("destination_ip", pd.Series(dtype=str)),
        "Top destination IPs",
        "Destination IP",
        "threats_destination_ips",
    )

    st.divider()
    st.subheader("Threat Event Details")

    search = st.text_input(
        "Search events",
        placeholder="IP address, prediction, severity, action...",
    )
    table_df = df.copy()
    if search:
        mask = table_df.astype(str).apply(
            lambda row: row.str.contains(search, case=False, na=False).any(),
            axis=1,
        )
        table_df = table_df[mask]

    st.dataframe(
        table_df,
        use_container_width=True,
        hide_index=True,
        height=520,
    )

    if st.button("↻ Refresh", use_container_width=True):
        st.rerun()
