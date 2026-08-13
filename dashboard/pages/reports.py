"""Security reports backed by the existing Threat API."""

import pandas as pd
import streamlit as st
import requests

from components.threat_families import add_threat_family
from components.charts import (
    action_chart,
    confidence_chart,
    category_bar_chart,
    multi_timeline_chart,
    numeric_confidence_chart,
    prediction_chart,
    top_values_chart,
    severity_chart,
)


THREAT_API = "http://127.0.0.1:5000/api/threats"


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


def show_reports():
    st.caption("REPORTING")
    st.header("Security Reports")
    st.caption("Filter, review and export recorded NTCF threat events.")

    token = st.session_state.get("auth_token")
    if not token:
        st.error("Authentication required.")
        return

    try:
        response = requests.get(
            THREAT_API,
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
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

    labels = df.get("label", pd.Series(dtype=str)).astype(str).str.lower()
    predictions = df.get("prediction", pd.Series(dtype=str)).astype(str).str.lower()
    confidence = df.get("confidence_level", pd.Series(dtype=str)).astype(str).str.lower()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("TOTAL EVENTS", len(df))
    c2.metric(
        "THREAT EVENTS",
        int(labels.isin(["threat", "attack", "malicious", "intrusion", "anomaly"]).sum()),
    )
    c3.metric("PREDICTIONS", len(predictions))
    c4.metric("HIGH CONFIDENCE", int((confidence == "high").sum()))

    st.divider()
    f1, f2, f3, f4 = st.columns(4)
    with f1:
        options = ["All"] + sorted(predictions.dropna().unique().tolist())
        selected_prediction = st.selectbox("Prediction", options)
    with f2:
        options = ["All"] + sorted(confidence.dropna().unique().tolist())
        selected_confidence = st.selectbox("Confidence", options)
    with f3:
        date_series = pd.to_datetime(df.get("detected_at"), errors="coerce")
        min_date = date_series.min().date() if date_series.notna().any() else None
        max_date = date_series.max().date() if date_series.notna().any() else None
        selected_start = st.date_input("From", value=min_date) if min_date else None
    with f4:
        selected_end = st.date_input("To", value=max_date) if max_date else None

    filtered = df.copy()
    if "detected_at" in filtered.columns:
        detected = pd.to_datetime(filtered["detected_at"], errors="coerce")
        if selected_start:
            filtered = filtered[detected.dt.date >= selected_start]
            detected = detected.loc[filtered.index]
        if selected_end:
            filtered = filtered[detected.dt.date <= selected_end]

    if selected_start and selected_end and selected_start > selected_end:
        st.error("The report start date must be on or before the end date.")
        return
    if selected_prediction != "All" and "prediction" in filtered.columns:
        filtered = filtered[
            filtered["prediction"].astype(str).str.lower() == selected_prediction
        ]
    if selected_confidence != "All" and "confidence_level" in filtered.columns:
        filtered = filtered[
            filtered["confidence_level"].astype(str).str.lower() == selected_confidence
        ]

    st.write(f"Showing **{len(filtered)}** of **{len(df)}** events.")

    # Charts use the filtered report dataset, so they always match the table below.
    # Charts use the filtered report dataset, so they always match the table below.
    chart_a, chart_b = st.columns(2)
    with chart_a:
        prediction_chart(
            filtered.get("prediction", pd.Series(dtype=str)).value_counts().to_dict(),
            key="reports_predictions",
        )
    with chart_b:
        confidence_chart(
            filtered.get("confidence_level", pd.Series(dtype=str)).value_counts().to_dict(),
            key="reports_confidence",
        )

    chart_c, chart_d = st.columns(2)
    with chart_c:
        category_bar_chart(
            filtered.get("threat_family", pd.Series(dtype=str)).fillna("Unknown").value_counts().to_dict(),
            "Threat Family",
            "Threat family distribution",
            "reports_threat_families",
        )
    with chart_d:
        severity_chart(
            filtered.get("severity", pd.Series(dtype=str)).fillna("Unknown").value_counts().to_dict(),
            key="reports_severity",
        )

    chart_e, chart_f = st.columns(2)
    with chart_e:
        action_chart(
            filtered.get("action", pd.Series(dtype=str)).fillna("none").value_counts().to_dict(),
            key="reports_actions",
        )
    with chart_f:
        numeric_confidence_chart(
            filtered.get("confidence", pd.Series(dtype=float)),
            key="reports_numeric_confidence",
        )

    multi_timeline_chart(
        filtered,
        "detected_at",
        "severity",
        "Threat activity over time by severity",
        "reports_timeline",
    )

    chart_g, chart_h = st.columns(2)
    with chart_g:
        top_values_chart(
            filtered.get("source_ip", pd.Series(dtype=str)),
            "Top source IPs",
            "Source IP",
            "reports_source_ips",
        )
    with chart_h:
        top_values_chart(
            filtered.get("destination_ip", pd.Series(dtype=str)),
            "Top destination IPs",
            "Destination IP",
            "reports_destination_ips",
        )

    st.divider()
    st.subheader("Report Details")
    st.dataframe(
        filtered,
        use_container_width=True,
        hide_index=True,
        height=500,
    )

    csv = filtered.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇  Download CSV Report",
        data=csv,
        file_name="ntcf_security_report.csv",
        mime="text/csv",
        use_container_width=True,
    )
