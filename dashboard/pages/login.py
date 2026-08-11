"""
NTCF Dashboard Login Page
Issue #29
"""

import requests
import streamlit as st


# =========================================================
# Authentication API
# =========================================================

AUTH_API = "http://127.0.0.1:5000/auth"


# =========================================================
# Login Page
# =========================================================

def show_login():
    """Display the NTCF Security Operations Center login page."""

    # =====================================================
    # Header
    # =====================================================

    st.markdown(
        """
        # 🛡️ NTCF Security Operations Center
        ### Network Threat Cognition Framework
        **Secure Network Threat Monitoring Platform**
        """
    )

    st.divider()

    # =====================================================
    # Login Section
    # =====================================================

    st.subheader("🔐 Dashboard Login")

    st.caption(
        "Authenticate to access the Security Operations Center."
    )

    # =====================================================
    # Login Form
    # =====================================================

    username = st.text_input(
        "Username",
        placeholder="Enter username",
    )

    password = st.text_input(
        "Password",
        type="password",
        placeholder="Enter password",
    )

    login_button = st.button(
        "🔐 Sign In",
        use_container_width=True,
        type="primary",
    )

    # =====================================================
    # Authentication
    # =====================================================

    if login_button:

        if not username or not password:

            st.error(
                "Username and password are required."
            )

            return

        try:

            response = requests.post(
                f"{AUTH_API}/login",
                json={
                    "username": username,
                    "password": password,
                },
                timeout=5,
            )

        except requests.exceptions.ConnectionError:

            st.error(
                "🔴 Unable to connect to the backend. "
                "Make sure Flask is running on port 5000."
            )

            return

        except requests.exceptions.Timeout:

            st.error(
                "⏱️ Authentication request timed out."
            )

            return

        except requests.RequestException as error:

            st.error(
                f"Authentication request failed: {error}"
            )

            return

        # =================================================
        # Parse Response
        # =================================================

        try:

            result = response.json()

        except ValueError:

            result = {}

        # =================================================
        # Successful Login
        # =================================================

        if (
            response.status_code == 200
            and result.get("success") is True
            and result.get("token")
        ):

            st.session_state.logged_in = True

            st.session_state.username = username

            st.session_state.auth_token = result["token"]

            st.success(
                "Authentication successful."
            )

            st.rerun()

        # =================================================
        # Failed Login
        # =================================================

        else:

            error_message = result.get(
                "error",
                result.get(
                    "message",
                    "Invalid username or password.",
                ),
            )

            st.error(
                error_message
            )

    # =====================================================
    # Footer
    # =====================================================

    st.caption(
        "NTCF Security Operations Center • "
        "Authorized Access Only"
    )