"""
NTCF Dashboard - Live Monitoring

Issue #29

Provides a dashboard interface for sending network
feature data to the NTCF Detection API.
"""

import json

import requests
import streamlit as st


# =========================================================
# Detection API
# =========================================================

DETECTION_API = "http://127.0.0.1:5000/api/detection"


# =========================================================
# API Request
# =========================================================

def send_detection(model_name, features):
    """
    Send feature data to the NTCF Detection API.
    """

    payload = {
        "model_name": model_name,
        "features": features,
    }

    try:

        response = requests.post(
            f"{DETECTION_API}/predict",
            json=payload,
            timeout=10,
        )

        try:
            data = response.json()

        except ValueError:

            data = {
                "success": False,
                "message": response.text,
            }

        return response.status_code, data

    except requests.RequestException as error:

        return None, {
            "success": False,
            "message": str(error),
        }


# =========================================================
# Live Monitoring Page
# =========================================================

def show_live_monitoring():

    st.title("📡 Live Threat Monitoring")

    st.caption(
        "Submit network feature data to the NTCF "
        "detection engine and view the prediction."
    )

    st.divider()

    # =====================================================
    # API Status
    # =====================================================

    try:

        health_response = requests.get(
            f"{DETECTION_API}/health",
            timeout=3,
        )

        if health_response.status_code == 200:

            st.success(
                "🟢 Detection API Online"
            )

        else:

            st.warning(
                "🟡 Detection API responded with an error."
            )

    except requests.RequestException:

        st.error(
            "🔴 Detection API Offline"
        )

        st.info(
            "Start the Flask backend before sending "
            "a detection request."
        )

    st.divider()

    # =====================================================
    # Model Selection
    # =====================================================

    st.subheader("🤖 Detection Model")

    model_name = st.selectbox(
        "Select ML Model",
        [
            "decision_tree",
            "random_forest",
            "svm",
        ],
        index=0,
    )

    st.caption(
        "Decision Tree is the default NTCF detection model."
    )

    st.divider()

    # =====================================================
    # Feature Input
    # =====================================================

    st.subheader("📥 Network Feature Input")

    st.write(
        "Enter the network features as JSON. "
        "The same feature structure should be used "
        "for all supported ML models."
    )

    default_features = {
        "feature_1": 0,
        "feature_2": 0,
        "feature_3": 0,
    }

    feature_text = st.text_area(
        "Features (JSON)",
        value=json.dumps(
            default_features,
            indent=4,
        ),
        height=220,
        help=(
            "Enter the feature values expected by "
            "your trained NTCF model."
        ),
    )

    # =====================================================
    # Detection Button
    # =====================================================

    if st.button(
        "🔍 Analyze Network Traffic",
        use_container_width=True,
        type="primary",
    ):

        # -------------------------------------------------
        # Parse JSON
        # -------------------------------------------------

        try:

            features = json.loads(
                feature_text
            )

        except json.JSONDecodeError as error:

            st.error(
                f"Invalid JSON: {error}"
            )

            return

        # -------------------------------------------------
        # Validate JSON object
        # -------------------------------------------------

        if not isinstance(features, dict):

            st.error(
                "Features must be a JSON object."
            )

            return

        if not features:

            st.error(
                "Feature data cannot be empty."
            )

            return

        # -------------------------------------------------
        # Send Detection Request
        # -------------------------------------------------

        with st.spinner(
            "Analyzing network traffic..."
        ):

            status_code, result = send_detection(
                model_name,
                features,
            )

        # -------------------------------------------------
        # Connection Error
        # -------------------------------------------------

        if status_code is None:

            st.error(
                "🔴 Unable to connect to the Detection API."
            )

            st.info(
                "Make sure the backend is running on "
                "http://127.0.0.1:5000"
            )

            return

        # -------------------------------------------------
        # API Error
        # -------------------------------------------------

        if status_code >= 400:

            st.error(
                result.get(
                    "message",
                    "Detection request failed.",
                )
            )

            return

        # -------------------------------------------------
        # Successful Prediction
        # -------------------------------------------------

        st.success(
            "✅ Detection completed successfully."
        )

        st.divider()

        st.subheader(
            "🎯 Detection Result"
        )

        # -------------------------------------------------
        # Result Metrics
        # -------------------------------------------------

        col1, col2, col3 = st.columns(3)

        with col1:

            st.metric(
                "Prediction",
                str(
                    result.get(
                        "prediction",
                        "Unknown",
                    )
                ),
            )

        with col2:

            st.metric(
                "Classification",
                str(
                    result.get(
                        "label",
                        "Unknown",
                    )
                ),
            )

        with col3:

            confidence = result.get(
                "confidence",
                0,
            )

            try:
                confidence_value = float(
                    confidence
                )

            except (
                TypeError,
                ValueError,
            ):
                confidence_value = 0.0

            st.metric(
                "Confidence",
                f"{confidence_value:.2%}",
            )

        # -------------------------------------------------
        # Raw API Response
        # -------------------------------------------------

        with st.expander(
            "🔎 View API Response"
        ):

            st.json(result)