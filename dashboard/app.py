"""
NTCF Security Operations Center
Main Streamlit Dashboard

Issue #29
"""

from pathlib import Path

import streamlit as st

from pages.login import show_login
from pages.overview import show_overview
from pages.threats import show_threats
from pages.live_monitoring import show_live_monitoring
from pages.blocked_ips import show_blocked_ips
from pages.reports import show_reports


# =========================================================
# Page Configuration
# =========================================================

st.set_page_config(
    page_title="NTCF Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# =========================================================
# Load CSS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent

CSS_PATH = BASE_DIR / "assets" / "style.css"

if CSS_PATH.exists():

    css = CSS_PATH.read_text(
        encoding="utf-8"
    )

    st.markdown(
        f"<style>{css}</style>",
        unsafe_allow_html=True,
    )


# =========================================================
# Session State
# =========================================================

if "logged_in" not in st.session_state:

    st.session_state.logged_in = False


# =========================================================
# Login
# =========================================================

if not st.session_state.logged_in:

    show_login()

    st.stop()


# =========================================================
# Sidebar
# =========================================================

with st.sidebar:

    st.title("🛡️ NTCF SOC")

    st.caption(
        "Network Threat Cognition Framework"
    )

    st.divider()

    page = st.radio(
        "Navigation",
        [
            "Overview",
            "Threats",
            "Live Monitoring",
            "Blocked IPs",
            "Reports",
        ],
    )

    st.divider()

    st.caption("System Status")

    st.success("Dashboard Online")

    st.divider()

    if st.button(
        "🚪 Logout",
        use_container_width=True,
    ):

        st.session_state.logged_in = False

        st.rerun()


# =========================================================
# Page Routing
# =========================================================

if page == "Overview":

    show_overview()


elif page == "Threats":

    show_threats()


elif page == "Live Monitoring":

    show_live_monitoring()


elif page == "Blocked IPs":

    show_blocked_ips()


elif page == "Reports":

    show_reports()