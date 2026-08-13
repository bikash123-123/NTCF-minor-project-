"""NTCF SOC authentication screen."""

import requests
import streamlit as st

AUTH_API = "http://127.0.0.1:5000/auth"


def show_login():
    st.markdown("# 🛡️ NTCF SECURITY OPERATIONS CENTER")
    st.caption("NETWORK THREAT COGNITION FRAMEWORK • AUTHORIZED ACCESS ONLY")
    st.divider()

    left, center, right = st.columns([1, 1.5, 1])
    with center:
        with st.container(border=True):
            st.subheader("Secure Sign In")
            st.caption("Authenticate to access the Security Operations Center.")

            with st.form("login_form"):
                username = st.text_input("Username", placeholder="Enter username")
                password = st.text_input("Password", type="password", placeholder="Enter password")
                submitted = st.form_submit_button("🔐  Sign In", use_container_width=True)

            if submitted:
                if not username or not password:
                    st.error("Username and password are required.")
                    return
                try:
                    response = requests.post(
                        f"{AUTH_API}/login",
                        json={"username": username, "password": password},
                        timeout=5,
                    )
                except requests.RequestException as exc:
                    st.error(f"Unable to connect to the authentication service: {exc}")
                    return

                try:
                    result = response.json()
                except ValueError:
                    result = {}

                if response.status_code == 200 and result.get("success") and result.get("token"):
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.session_state.auth_token = result["token"]
                    st.rerun()
                else:
                    st.error(result.get("error", result.get("message", "Invalid username or password.")))

        st.caption("NTCF Security Operations Center • Authorized Access Only")
