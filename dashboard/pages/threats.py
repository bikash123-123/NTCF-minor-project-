"""
NTCF Dashboard - Threat Events
Issue #29

Displays threat events retrieved from the NTCF backend API.
"""

import requests
import pandas as pd
import streamlit as st


# =========================================================
# Backend API
# =========================================================

THREAT_API = "http://127.0.0.1:5000/api/threats"


# =========================================================
# Threat Page
# =========================================================

def show_threats():

    st.title("🚨 Threat Events")

    st.caption(
        "Network threat detections identified by the "
        "NTCF detection and decision pipeline."
    )

    # =====================================================
    # Authentication
    # =====================================================

    token = st.session_state.get("auth_token")

    if not token:

        st.error(
            "🔐 Authentication required."
        )

        st.info(
            "Please log in again."
        )

        return

    headers = {
        "Authorization": f"Bearer {token}"
    }

    # =====================================================
    # Refresh
    # =====================================================

    col_refresh, col_status = st.columns([1, 5])

    with col_refresh:

        refresh = st.button(
            "🔄 Refresh",
            use_container_width=True,
        )

    if refresh:
        st.rerun()

    # =====================================================
    # Retrieve Threats
    # =====================================================

    try:

        response = requests.get(
            THREAT_API,
            headers=headers,
            timeout=5,
        )

        # -------------------------------------------------
        # Authentication Error
        # -------------------------------------------------

        if response.status_code == 401:

            st.error(
                "🔐 Authentication expired or invalid."
            )

            st.session_state.logged_in = False
            st.session_state.pop("auth_token", None)
            st.session_state.pop("username", None)

            st.info(
                "Please log in again."
            )

            st.rerun()

            return

        # -------------------------------------------------
        # Other API Errors
        # -------------------------------------------------

        if response.status_code != 200:

            st.error(
                f"Threat API returned HTTP "
                f"{response.status_code}."
            )

            try:

                error_data = response.json()

                error_message = error_data.get(
                    "error",
                    error_data.get(
                        "message",
                        "Unknown API error.",
                    ),
                )

                st.caption(
                    str(error_message)
                )

            except ValueError:

                if response.text:

                    st.caption(
                        response.text
                    )

            return

        # -------------------------------------------------
        # Parse JSON
        # -------------------------------------------------

        try:

            result = response.json()

        except ValueError:

            st.error(
                "Threat API returned invalid JSON."
            )

            return

        # -------------------------------------------------
        # Extract Threat Data
        # -------------------------------------------------

        threats = result.get(
            "data",
            [],
        )

        # Support APIs that return the list directly
        # under "threats".

        if not threats:

            threats = result.get(
                "threats",
                [],
            )

    # =====================================================
    # Connection Errors
    # =====================================================

    except requests.exceptions.ConnectionError:

        st.error(
            "⚠️ Unable to connect to the NTCF backend."
        )

        st.info(
            "Make sure the Flask API is running on "
            "127.0.0.1:5000."
        )

        return

    except requests.exceptions.Timeout:

        st.error(
            "⏱️ Threat API request timed out."
        )

        return

    except requests.RequestException as error:

        st.error(
            f"Threat API request failed: {error}"
        )

        return

    except Exception as error:

        st.error(
            f"Unexpected error: {error}"
        )

        return

    # =====================================================
    # Empty State
    # =====================================================

    if not threats:

        st.info(
            "No threat events are currently available."
        )

        return

    # =====================================================
    # DataFrame
    # =====================================================

    df = pd.DataFrame(threats)

    if df.empty:

        st.info(
            "No threat events are currently available."
        )

        return

    # =====================================================
    # Metrics
    # =====================================================

    total_threats = len(df)

    high_confidence = 0
    medium_confidence = 0
    low_confidence = 0

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

        medium_confidence = (
            confidence_values == "medium"
        ).sum()

        low_confidence = (
            confidence_values == "low"
        ).sum()

    # =====================================================
    # Metric Cards
    # =====================================================

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "🚨 Total Threats",
            total_threats,
        )

    with col2:

        st.metric(
            "🔴 High Confidence",
            high_confidence,
        )

    with col3:

        st.metric(
            "🟠 Medium Confidence",
            medium_confidence,
        )

    with col4:

        st.metric(
            "🟢 Low Confidence",
            low_confidence,
        )

    st.divider()

    # =====================================================
    # Filters
    # =====================================================

    st.subheader(
        "🔎 Threat Filters"
    )

    filter_col1, filter_col2, filter_col3 = st.columns(3)

    filtered_df = df.copy()

    # =====================================================
    # Prediction Filter
    # =====================================================

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

    # =====================================================
    # Confidence Filter
    # =====================================================

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

    # =====================================================
    # Action Filter
    # =====================================================

    with filter_col3:

        if "action" in df.columns:

            actions = sorted(
                df["action"]
                .dropna()
                .astype(str)
                .unique()
                .tolist()
            )

            selected_action = st.selectbox(
                "Response Action",
                ["All"] + actions,
            )

            if selected_action != "All":

                filtered_df = filtered_df[
                    filtered_df["action"]
                    .astype(str)
                    == selected_action
                ]

    # =====================================================
    # Filter Result
    # =====================================================

    st.write(
        f"Showing **{len(filtered_df)}** "
        f"of **{len(df)}** threat events."
    )

    # =====================================================
    # Threat Event Table
    # =====================================================

    st.subheader(
        "📋 Threat Event Log"
    )

    if filtered_df.empty:

        st.warning(
            "No threats match the selected filters."
        )

    else:

        st.dataframe(
            filtered_df,
            use_container_width=True,
            hide_index=True,
        )

    # =====================================================
    # Threat Distribution
    # =====================================================

    st.divider()

    st.subheader(
        "📊 Threat Distribution"
    )

    chart_col1, chart_col2 = st.columns(2)

    # =====================================================
    # Prediction Chart
    # =====================================================

    with chart_col1:

        if "prediction" in df.columns:

            prediction_counts = (
                df["prediction"]
                .astype(str)
                .value_counts()
            )

            st.bar_chart(
                prediction_counts,
                use_container_width=True,
            )

        else:

            st.info(
                "Prediction data is not available."
            )

    # =====================================================
    # Confidence Chart
    # =====================================================

    with chart_col2:

        if "confidence_level" in df.columns:

            confidence_counts = (
                df["confidence_level"]
                .astype(str)
                .value_counts()
            )

            st.bar_chart(
                confidence_counts,
                use_container_width=True,
            )

        else:

            st.info(
                "Confidence data is not available."
            )