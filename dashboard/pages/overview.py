"""
NTCF Security Operations Center
Dashboard Overview Page

Issue #29
"""

import requests
import streamlit as st


# =========================================================
# Backend API
# =========================================================

DASHBOARD_API = "http://127.0.0.1:5000/api/dashboard"


# =========================================================
# API Request
# =========================================================

def get_dashboard_statistics():
    """Retrieve dashboard statistics from the backend."""

    try:

        response = requests.get(
            f"{DASHBOARD_API}/statistics",
            timeout=5,
        )

        if response.status_code != 200:
            return None

        return response.json()

    except requests.RequestException:
        return None


# =========================================================
# Overview Page
# =========================================================

def show_overview():
    """Display the NTCF SOC overview dashboard."""

    # -----------------------------------------------------
    # Header
    # -----------------------------------------------------

    st.title("🛡️ Security Operations Center")

    st.caption(
        "Network Threat Cognition Framework • "
        "Real-Time Network Threat Monitoring"
    )

    st.divider()

    # -----------------------------------------------------
    # Retrieve data
    # -----------------------------------------------------

    result = get_dashboard_statistics()

    if result is None:

        st.error(
            "Unable to connect to the NTCF backend API."
        )

        st.info(
            "Make sure the Flask backend is running "
            "on http://127.0.0.1:5000."
        )

        return

    # -----------------------------------------------------
    # Extract statistics
    # -----------------------------------------------------

    statistics = result.get(
        "statistics",
        {},
    )

    total_detections = statistics.get(
        "total_detections",
        0,
    )

    total_threats = statistics.get(
        "total_threats",
        0,
    )

    blocked_ips = statistics.get(
        "blocked_ips",
        0,
    )

    threat_statistics = result.get(
        "threat_statistics",
        {},
    )

    confidence_levels = threat_statistics.get(
        "confidence_levels",
        {},
    )

    high_confidence = confidence_levels.get(
        "high",
        0,
    )

    # -----------------------------------------------------
    # Security Metrics
    # -----------------------------------------------------

    st.subheader("Security Overview")

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            label="🚨 Total Threats",
            value=total_threats,
            help="Total recorded threat events.",
        )

    with col2:

        st.metric(
            label="🔎 Detections",
            value=total_detections,
            help="Total network detections processed.",
        )

    with col3:

        st.metric(
            label="🚫 Blocked IPs",
            value=blocked_ips,
            help="Currently blocked IP addresses.",
        )

    with col4:

        st.metric(
            label="⚠️ High Confidence",
            value=high_confidence,
            help="Threats classified with high confidence.",
        )

    st.divider()

    # -----------------------------------------------------
    # Threat Statistics
    # -----------------------------------------------------

    st.subheader("Threat Intelligence")

    prediction_counts = threat_statistics.get(
        "prediction_counts",
        {},
    )

    actions = threat_statistics.get(
        "actions",
        {},
    )

    col1, col2 = st.columns(2)

    # -----------------------------------------------------
    # Prediction Distribution
    # -----------------------------------------------------

    with col1:

        st.markdown("### 🎯 Threat Predictions")

        if prediction_counts:

            for prediction, count in prediction_counts.items():

                st.write(
                    f"**{prediction}** — {count}"
                )

        else:

            st.info(
                "No prediction data available."
            )

    # -----------------------------------------------------
    # Security Actions
    # -----------------------------------------------------

    with col2:

        st.markdown("### ⚡ Security Actions")

        if actions:

            for action, count in actions.items():

                st.write(
                    f"**{action}** — {count}"
                )

        else:

            st.info(
                "No security actions recorded."
            )

    st.divider()

    # -----------------------------------------------------
    # System Status
    # -----------------------------------------------------

    st.subheader("System Status")

    col1, col2, col3 = st.columns(3)

    with col1:

        st.success(
            "🟢 Backend API Online"
        )

    with col2:

        st.success(
            "🟢 Dashboard Online"
        )

    with col3:

        st.success(
            "🟢 Monitoring Ready"
        )

    # -----------------------------------------------------
    # Refresh
    # -----------------------------------------------------

    st.divider()

    if st.button(
        "🔄 Refresh Dashboard",
        use_container_width=True,
    ):

        st.rerun()