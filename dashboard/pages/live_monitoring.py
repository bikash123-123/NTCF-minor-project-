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

        if column == "protocol_type":
            features[column] = "tcp"

        elif column == "service":
            features[column] = "http"

        elif column == "flag":
            features[column] = "S0"

        else:
            features[column] = 0

    return features


# =========================================================
# API Request
# =========================================================

def send_detection(model_name, features):
    """
    Send feature data to the NTCF Detection API.

    Returns:
        tuple:
            (HTTP status code, response dictionary)

        If the API cannot be reached:
            (None, error dictionary)
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
# Validate Features
# =========================================================

def validate_features(features):
    """
    Validate that all required NSL-KDD features are present.

    Returns:
        list of missing feature names.
    """

    missing_features = [
        feature
        for feature in FEATURE_COLUMNS
        if feature not in features
    ]

    return missing_features


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
        "Enter the complete NSL-KDD feature set as JSON. "
        "The NTCF detection API requires all "
        f"{len(FEATURE_COLUMNS)} model features."
    )

    # -----------------------------------------------------
    # Required Feature Information
    # -----------------------------------------------------

    st.info(
        f"Required model features: {len(FEATURE_COLUMNS)}"
    )

    # -----------------------------------------------------
    # Default Features
    # -----------------------------------------------------

    default_features = build_default_features()

    feature_text = st.text_area(
        "Features (JSON)",
        value=json.dumps(
            default_features,
            indent=4,
        ),
        height=420,
        help=(
            "Enter all 41 NSL-KDD model features. "
            "Categorical values include protocol_type, "
            "service, and flag."
        ),
    )

    # -----------------------------------------------------
    # Show Feature Categories
    # -----------------------------------------------------

    with st.expander("📋 Required Feature List"):

        st.write(
            f"**Total features: {len(FEATURE_COLUMNS)}**"
        )

        st.write(
            "### Categorical Features"
        )

        st.code(
            ", ".join(CATEGORICAL_COLUMNS)
        )

        st.write(
            "### All Model Features"
        )

        st.code(
            "\n".join(FEATURE_COLUMNS)
        )

    st.divider()

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
        # Validate JSON Object
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
        # Validate Required Features
        # -------------------------------------------------

        missing_features = validate_features(
            features
        )

        if missing_features:

            st.error(
                "Missing required features:"
            )

            st.code(
                "\n".join(missing_features)
            )

            st.warning(
                f"{len(missing_features)} feature(s) "
                "are missing. Please provide the "
                "complete NSL-KDD feature set."
            )

            return

        # -------------------------------------------------
        # Optional Warning for Extra Features
        # -------------------------------------------------

        extra_features = [
            key
            for key in features
            if key not in FEATURE_COLUMNS
        ]

        if extra_features:

            st.warning(
                "The following extra fields will be "
                "sent to the API:"
            )

            st.code(
                "\n".join(extra_features)
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

            st.error(
                result.get(
                    "message",
                    "Detection request failed.",
                )
            )

            # Show full response for debugging.
            with st.expander(
                "🔎 View API Error Response"
            ):

                st.json(result)

            return

        # -------------------------------------------------
        # Check API Success
        # -------------------------------------------------

        if result.get("success") is False:

            st.error(
                result.get(
                    "message",
                    "Detection failed.",
                )
            )

            with st.expander(
                "🔎 View API Response"
            ):

                st.json(result)

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

        # =================================================
        # Result Metrics
        # =================================================

        col1, col2, col3 = st.columns(3)

        # -------------------------------------------------
        # Prediction
        # -------------------------------------------------

        with col1:

            prediction = result.get(
                "prediction",
                "Unknown",
            )

            st.metric(
                "Prediction",
                str(prediction),
            )

        # -------------------------------------------------
        # Classification
        # -------------------------------------------------

        with col2:

            classification = result.get(
                "label",
                "Unknown",
            )

            st.metric(
                "Classification",
                str(classification),
            )

        # -------------------------------------------------
        # Confidence
        # -------------------------------------------------

        with col3:

            confidence = result.get(
                "confidence",
                result.get(
                    "confidence_score",
                    0,
                ),
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

            # Handle APIs returning 100 instead of 1.0.
            if confidence_value > 1.0:

                confidence_value /= 100.0

            confidence_value = max(
                0.0,
                min(
                    confidence_value,
                    1.0,
                ),
            )

            st.metric(
                "Confidence",
                f"{confidence_value:.2%}",
            )

        # =================================================
        # Confidence Level
        # =================================================

        confidence_level = result.get(
            "confidence_level",
            "unknown",
        )

        st.info(
            f"Confidence level: {confidence_level}"
        )

        # =================================================
        # Recommended Action
        # =================================================

        action = result.get(
            "action",
            "unknown",
        )

        st.write(
            f"**Recommended action:** `{action}`"
        )

        # =================================================
        # Severity
        # =================================================

        severity = result.get(
            "severity",
            "unknown",
        )

        st.write(
            f"**Severity:** `{severity}`"
        )

        # =================================================
        # Firewall Result
        # =================================================

        firewall_result = result.get(
            "firewall"
        )

        if firewall_result:

            st.divider()

            st.subheader(
                "🛡️ Firewall Response"
            )

            firewall_success = firewall_result.get(
                "success",
                False,
            )

            if firewall_success:

                st.success(
                    "Firewall action completed successfully."
                )

            else:

                st.error(
                    "Firewall action failed."
                )

            firewall_col1, firewall_col2 = st.columns(2)

            with firewall_col1:

                st.write(
                    "**IP Address:**"
                )

                st.code(
                    str(
                        firewall_result.get(
                            "ip_address",
                            "Unknown",
                        )
                    )
                )

            with firewall_col2:

                st.write(
                    "**Status:**"
                )

                st.code(
                    str(
                        firewall_result.get(
                            "status",
                            "Unknown",
                        )
                    )
                )

            if firewall_result.get(
                "reason"
            ):

                st.write(
                    "**Reason:** "
                    + str(
                        firewall_result.get(
                            "reason"
                        )
                    )
                )

            if "dry_run" in firewall_result:

                st.write(
                    "**Dry Run:** "
                    + str(
                        firewall_result.get(
                            "dry_run"
                        )
                    )
                )

        # =================================================
        # Database Result
        # =================================================

        database_result = result.get(
            "database"
        )

        if database_result:

            st.divider()

            st.subheader(
                "💾 Database Persistence"
            )

            threat_event_id = database_result.get(
                "threat_event_id"
            )

            detection_result_id = database_result.get(
                "detection_result_id"
            )

            if threat_event_id is not None:

                st.write(
                    f"Threat Event ID: `{threat_event_id}`"
                )

            if detection_result_id is not None:

                st.write(
                    f"Detection Result ID: "
                    f"`{detection_result_id}`"
                )

        # =================================================
        # Raw API Response
        # =================================================

        with st.expander(
            "🔎 View API Response"
        ):

            st.json(result)