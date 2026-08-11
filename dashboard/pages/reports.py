"""
NTCF Dashboard - Reports

Issue #29

Displays recorded NTCF threat events and allows
the authenticated user to download a CSV report.
"""

import pandas as pd
import requests
import streamlit as st


# =========================================================
# Threat API
# =========================================================

THREAT_API = "http://127.0.0.1:5000/api/threats"


# =========================================================
# Authentication Helper
# =========================================================

def get_auth_headers():
    """
    Return authentication headers for backend API requests.
    """

    token = st.session_state.get("auth_token")

    if not token:
        return None

    return {
        "Authorization": f"Bearer {token}"
    }


# =========================================================
# Get Threat Data
# =========================================================

def get_threat_data():
    """
    Retrieve threat events from the authenticated backend API.

    Returns:
        tuple:
            data
            status_code
    """

    headers = get_auth_headers()

    if not headers:
        return None, 401

    try:

        response = requests.get(
            THREAT_API,
            headers=headers,
            timeout=5,
        )

    except requests.exceptions.ConnectionError:

        return None, None

    except requests.exceptions.Timeout:

        return None, "timeout"

    except requests.RequestException:

        return None, None

    # -----------------------------------------------------
    # Authentication failure
    # -----------------------------------------------------

    if response.status_code == 401:

        return None, 401

    # -----------------------------------------------------
    # Other API errors
    # -----------------------------------------------------

    if response.status_code != 200:

        return None, response.status_code

    # -----------------------------------------------------
    # Parse JSON
    # -----------------------------------------------------

    try:

        result = response.json()

    except ValueError:

        return None, "invalid_json"

    # -----------------------------------------------------
    # Extract data
    # -----------------------------------------------------

    data = result.get(
        "data",
        [],
    )

    if not isinstance(data, list):

        data = []

    return data, 200


# =========================================================
# Reports Page
# =========================================================

def show_reports():

    st.title("📄 Security Reports")

    st.caption(
        "Generate reports from recorded NTCF threat events."
    )

    st.divider()

    # =====================================================
    # Authentication
    # =====================================================

    token = st.session_state.get("auth_token")

    if not token:

        st.error(
            "🔐 Authentication required."
        )

        st.info(
            "Please log in again to access security reports."
        )

        return

    # =====================================================
    # Refresh
    # =====================================================

    col_refresh, col_space = st.columns(
        [1, 5]
    )

    with col_refresh:

        if st.button(
            "🔄 Refresh",
            use_container_width=True,
        ):

            st.rerun()

    # =====================================================
    # Retrieve Threat Data
    # =====================================================

    data, status_code = get_threat_data()

    # =====================================================
    # Backend Offline
    # =====================================================

    if status_code is None:

        st.error(
            "🔴 Unable to connect to the Threat API."
        )

        st.info(
            "Make sure the Flask backend is running on "
            "127.0.0.1:5000."
        )

        return

    # =====================================================
    # Timeout
    # =====================================================

    if status_code == "timeout":

        st.error(
            "⏱️ Threat API request timed out."
        )

        return

    # =====================================================
    # Invalid JSON
    # =====================================================

    if status_code == "invalid_json":

        st.error(
            "⚠️ The Threat API returned an invalid response."
        )

        return

    # =====================================================
    # Authentication Expired
    # =====================================================

    if status_code == 401:

        st.error(
            "🔐 Authentication expired or invalid."
        )

        st.session_state.logged_in = False
        st.session_state.auth_token = None
        st.session_state.username = None

        st.info(
            "Please log in again."
        )

        st.rerun()

        return

    # =====================================================
    # Other API Error
    # =====================================================

    if status_code != 200:

        st.error(
            f"Threat API returned HTTP {status_code}."
        )

        return

    # =====================================================
    # Empty Data
    # =====================================================

    if not data:

        st.info(
            "No threat events are currently available."
        )

        return

    # =====================================================
    # Convert to DataFrame
    # =====================================================

    df = pd.DataFrame(data)

    # =====================================================
    # Report Summary
    # =====================================================

    st.subheader("📊 Report Summary")

    total_events = len(df)

    # -----------------------------------------------------
    # Threat count
    # -----------------------------------------------------

    threat_count = 0

    if "label" in df.columns:

        labels = (
            df["label"]
            .astype(str)
            .str.lower()
            .str.strip()
        )

        threat_count = labels.isin(
            [
                "threat",
                "attack",
                "anomaly",
                "malicious",
                "intrusion",
            ]
        ).sum()

    # -----------------------------------------------------
    # Prediction count
    # -----------------------------------------------------

    prediction_count = 0

    if "prediction" in df.columns:

        prediction_values = (
            df["prediction"]
            .astype(str)
            .str.lower()
            .str.strip()
        )

        prediction_count = prediction_values.isin(
            [
                "1",
                "true",
                "threat",
                "attack",
                "anomaly",
                "malicious",
            ]
        ).sum()

    # -----------------------------------------------------
    # Confidence
    # -----------------------------------------------------

    high_confidence = 0

    if "confidence_level" in df.columns:

        confidence_values = (
            df["confidence_level"]
            .astype(str)
            .str.lower()
            .str.strip()
        )

        high_confidence = (
            confidence_values == "high"
        ).sum()

    # =====================================================
    # Metrics
    # =====================================================

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "📋 Total Events",
            total_events,
        )

    with col2:

        st.metric(
            "🚨 Threat Events",
            int(threat_count),
        )

    with col3:

        st.metric(
            "🎯 Predictions",
            int(prediction_count),
        )

    with col4:

        st.metric(
            "🔴 High Confidence",
            int(high_confidence),
        )

    st.divider()

    # =====================================================
    # Report Filters
    # =====================================================

    st.subheader("🔎 Report Filters")

    filtered_df = df.copy()

    filter_col1, filter_col2 = st.columns(2)

    # -----------------------------------------------------
    # Prediction Filter
    # -----------------------------------------------------

    with filter_col1:

        if "prediction" in df.columns:

            predictions = sorted(
                df["prediction"]
                .dropna()
                .astype(str)
                .unique()
                .tolist()
            )

            selected_prediction = st.selectbox(
                "Prediction",
                ["All"] + predictions,
            )

            if selected_prediction != "All":

                filtered_df = filtered_df[
                    filtered_df["prediction"]
                    .astype(str)
                    == selected_prediction
                ]

    # -----------------------------------------------------
    # Confidence Filter
    # -----------------------------------------------------

    with filter_col2:

        if "confidence_level" in df.columns:

            confidence_levels = sorted(
                df["confidence_level"]
                .dropna()
                .astype(str)
                .unique()
                .tolist()
            )

            selected_confidence = st.selectbox(
                "Confidence Level",
                ["All"] + confidence_levels,
            )

            if selected_confidence != "All":

                filtered_df = filtered_df[
                    filtered_df["confidence_level"]
                    .astype(str)
                    == selected_confidence
                ]

    st.write(
        f"Showing **{len(filtered_df)}** "
        f"of **{len(df)}** events."
    )

    # =====================================================
    # Threat Event Report
    # =====================================================

    st.subheader("📋 Threat Event Report")

    if filtered_df.empty:

        st.warning(
            "No events match the selected filters."
        )

    else:

        st.dataframe(
            filtered_df,
            use_container_width=True,
            hide_index=True,
        )

    # =====================================================
    # Report Statistics
    # =====================================================

    st.divider()

    st.subheader("📊 Report Statistics")

    chart_col1, chart_col2 = st.columns(2)

    # -----------------------------------------------------
    # Prediction Distribution
    # -----------------------------------------------------

    with chart_col1:

        if "prediction" in df.columns:

            st.caption(
                "Prediction Distribution"
            )

            prediction_counts = (
                df["prediction"]
                .astype(str)
                .value_counts()
            )

            st.bar_chart(
                prediction_counts,
                use_container_width=True,
            )

    # -----------------------------------------------------
    # Confidence Distribution
    # -----------------------------------------------------

    with chart_col2:

        if "confidence_level" in df.columns:

            st.caption(
                "Confidence Distribution"
            )

            confidence_counts = (
                df["confidence_level"]
                .astype(str)
                .value_counts()
            )

            st.bar_chart(
                confidence_counts,
                use_container_width=True,
            )

    # =====================================================
    # CSV Report
    # =====================================================

    st.divider()

    st.subheader("📥 Export Report")

    csv_data = filtered_df.to_csv(
        index=False
    )

    st.download_button(
        label="⬇️ Download CSV Report",
        data=csv_data,
        file_name="ntcf_threat_report.csv",
        mime="text/csv",
        use_container_width=True,
    )