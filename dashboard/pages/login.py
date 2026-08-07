"""
NTCF Dashboard Login Page
Issue #29
"""

import streamlit as st


def show_login():
    """Display the NTCF Security Operations Center login page."""

    # ======================================================
    # Header
    # ======================================================

    st.markdown(
        """
        # 🛡️ NTCF Security Operations Center
        ### Network Threat Cognition Framework
        **Secure Network Threat Monitoring Platform**
        """
    )

    st.divider()

    # ======================================================
    # Login Section
    # ======================================================

    st.subheader("🔐 Dashboard Login")

    st.caption(
        "Authenticate to access the Security Operations Center."
    )

    # ======================================================
    # Login Form
    # ======================================================

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

    # ======================================================
    # Authentication
    # ======================================================

    if login_button:

        if username == "admin" and password == "admin":

            st.session_state.logged_in = True

            st.success(
                "Authentication successful."
            )

            st.rerun()

        else:

            st.error(
                "Invalid username or password."
            )

    # ======================================================
    # Footer
    # ======================================================

    st.caption(
        "NTCF Security Operations Center • Authorized Access Only"
    )