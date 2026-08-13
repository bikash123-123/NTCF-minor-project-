"""SOC overview page backed by the existing dashboard API."""

import requests
import streamlit as st

from components.threat_families import get_threat_family
from components.charts import (
    action_chart,
    category_bar_chart,
    confidence_chart,
    multi_timeline_chart,
    numeric_confidence_chart,
    prediction_chart,
    severity_chart,
)

DASHBOARD_API = "http://127.0.0.1:5000/api/dashboard"


def get_dashboard_statistics():
    try:
        response = requests.get(f"{DASHBOARD_API}/statistics", timeout=5)
        if response.status_code != 200:
            return None
        return response.json()
    except requests.RequestException:
        return None


def show_overview():
    st.caption("COMMAND CENTER")
    st.header("Security Overview")
    st.caption("Current security posture, detection activity and response status.")

    result = get_dashboard_statistics()
    if result is None:
        st.error("Unable to connect to the NTCF backend API.")
        st.info("Start the Flask backend on http://127.0.0.1:5000.")
        return

    stats = result.get("statistics", {})
    threat_stats = result.get("threat_statistics", {})
    confidence = threat_stats.get("confidence_levels", {})

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("TOTAL THREATS", stats.get("total_threats", 0), "Recorded events")
    c2.metric("DETECTIONS", stats.get("total_detections", 0), "Processed events")
    c3.metric("BLOCKED IPS", stats.get("blocked_ips", 0), "Firewall records")
    detection_total = stats.get("total_detections", 0) or 0
    threat_total = stats.get("total_threats", 0) or 0
    detection_rate = (threat_total / detection_total * 100) if detection_total else 0
    c4.metric("THREAT RATE", f"{detection_rate:.1f}%", "Threats / detections")

    st.divider()

    chart1, chart2 = st.columns(2)
    with chart1:
        st.subheader("Threat Predictions")
        prediction_chart(threat_stats.get("prediction_counts", {}), key="overview_predictions")
    with chart2:
        st.subheader("Threat Families")
        prediction_counts = threat_stats.get("prediction_counts", {})
        family_counts = {}
        for prediction, count in prediction_counts.items():
            family = get_threat_family(prediction)
            family_counts[family] = family_counts.get(family, 0) + int(count)
        category_bar_chart(
            family_counts,
            "Threat Family",
            "Threat family distribution",
            "overview_threat_families",
        )

    chart3, chart4 = st.columns(2)
    with chart3:
        st.subheader("Severity")
        severity_chart(threat_stats.get("severity_counts", {}), key="overview_severity")
    with chart4:
        st.subheader("Confidence Levels")
        confidence_chart(confidence, key="overview_confidence_levels")

    chart5, chart6 = st.columns(2)
    with chart5:
        st.subheader("Response Actions")
        action_chart(threat_stats.get("actions", {}), key="overview_actions")
    with chart6:
        st.subheader("Numeric Confidence")
        events = threat_stats.get("events", [])
        if events:
            import pandas as pd
            event_df = pd.DataFrame(events)
            numeric_confidence_chart(
                event_df.get("confidence", pd.Series(dtype=float)),
                key="overview_numeric_confidence",
            )
        else:
            st.info("Numeric confidence distribution is available on the Threats and Reports pages.")

    # If the current API response includes event-level records, use their real
    # timestamps for the overview timeline. Otherwise the API remains unchanged.
    events = threat_stats.get("events", [])
    if events:
        import pandas as pd
        event_df = pd.DataFrame(events)
        st.subheader("Threat Activity Over Time")
        multi_timeline_chart(
            event_df,
            "detected_at",
            "severity",
            "Threats over time by severity",
            "overview_timeline",
        )

    st.divider()
    left, right = st.columns([2, 1])
    with left:
        st.subheader("System Status")
        st.success("● Backend API  — Online")
        st.success("● Database     — Ready")
        st.success("● Dashboard    — Online")
        st.info("Use Live Monitoring to start packet capture.")
    with right:
        st.subheader("Data Notes")
        st.info("Threat families are derived from the model prediction labels; backend contracts are unchanged.")

    if st.button("↻ Refresh Dashboard", use_container_width=True):
        st.rerun()
