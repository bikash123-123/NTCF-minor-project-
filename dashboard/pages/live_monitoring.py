"""
NTCF Dashboard - Live Monitoring

Issue #29

Provides a dashboard interface for sending network
feature data to the NTCF Detection API.

The dashboard uses the complete NSL-KDD feature set
defined in ml.config.columns.
"""

import json

import requests
import streamlit as st

from ml.config.columns import (
    FEATURE_COLUMNS,
    CATEGORICAL_COLUMNS,
)


# =========================================================
# Detection API
# =========================================================

DETECTION_API = "http://127.0.0.1:5000/api/detection"


# =========================================================
# Default NSL-KDD Features
# =========================================================

def build_default_features():
    """
    Build a complete default NSL-KDD feature dictionary.

    Categorical features receive realistic default values.
    Numerical features receive zero.
    """

    features = {}

    for column in FEATURE_COLUMNS:

        if column in CATEGORICAL_COLUMNS:

            if column == "protocol_type":
                features[column] = "tcp"

            elif column == "service":
                features[column] = "http"

            elif column == "flag":
                features[column] = "SF"

            else:
                features[column] = ""

        else:
            features[column] = 0

    return features


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
        "Submit NSL-KDD network feature data to the "
        "NTCF detection engine and view the prediction."
    )

    st.divider()

    # =====================================================
    # API Status
    # =====================================================

    st.subheader("🔌 Detection API Status")

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
        "Enter the complete NSL-KDD feature set as JSON."
    )

    default_features = build_default_features()

    feature_text = st.text_area(
        "Features (JSON)",
        value=json.dumps(
            default_features,
            indent=4,
        ),
        height=450,
        help=(
            "Use the feature names defined in "
            "ml.config.columns."
        ),
    )

    st.caption(
        f"Expected features: {len(FEATURE_COLUMNS)}"
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
        # Validate feature names
        # -------------------------------------------------

        missing_features = [
            column
            for column in FEATURE_COLUMNS
            if column not in features
        ]

        if missing_features:

            st.error(
                "Missing required features:"
            )

            st.code(
                json.dumps(
                    missing_features,
                    indent=4,
                )
            )

            return

        # -------------------------------------------------
        # Detect unexpected features
        # -------------------------------------------------

        unexpected_features = [
            column
            for column in features
            if column not in FEATURE_COLUMNS
        ]

        if unexpected_features:

            st.warning(
                "The following unexpected features "
                "will be sent to the API:"
            )

            st.code(
                json.dumps(
                    unexpected_features,
                    indent=4,
                )
            )

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

            message = result.get(
                "message",
                result.get(
                    "error",
                    "Detection request failed.",
                ),
            )

            st.error(
                f"Detection API error "
                f"(HTTP {status_code}): {message}"
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

            # Support both 0.85 and 85 formats.
            if confidence_value > 1:
                confidence_value /= 100

            st.metric(
                "Confidence",
                f"{confidence_value:.2%}",
            )

        # -------------------------------------------------
        # Additional Result Information
        # -------------------------------------------------

        st.divider()

        st.subheader(
            "📊 Detection Details"
        )

        result_col1, result_col2 = st.columns(2)

        with result_col1:

            st.write(
                "**Model:**",
                result.get(
                    "model_name",
                    model_name,
                ),
            )

            st.write(
                "**Prediction:**",
                result.get(
                    "prediction",
                    "Unknown",
                ),
            )

        with result_col2:

            st.write(
                "**Label:**",
                result.get(
                    "label",
                    "Unknown",
                ),
            )

            st.write(
                "**Confidence Level:**",
                result.get(
                    "confidence_level",
                    "Unknown",
                ),
            )

        # -------------------------------------------------
        # Raw API Response
        # -------------------------------------------------

        with st.expander(
            "🔎 View API Response"
        ):

            st.json(result)