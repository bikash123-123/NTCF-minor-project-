"""
NTCF Security Operations Center dashboard shell.

Presentation-only dashboard changes live under this folder.
The packet capture, detection, decision engine, database and backend
implementations remain in the project and are imported rather than copied.
"""

from pathlib import Path
import sys

import streamlit as st

# Make the project root importable regardless of whether Streamlit is
# launched from the project root or from inside dashboard/.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pages.login import show_login
from pages.overview import show_overview
from pages.threats import show_threats
from pages.live_monitoring import show_live_monitoring
from pages.blocked_ips import show_blocked_ips
from pages.reports import show_reports

st.set_page_config(
    page_title="NTCF Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

css_path = Path(__file__).resolve().parent / "assets" / "style.css"
if css_path.exists():
    st.markdown(f"<style>{css_path.read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)

for key, default in (
    ("logged_in", False),
    ("auth_token", None),
    ("username", None),
):
    if key not in st.session_state:
        st.session_state[key] = default

if not st.session_state.logged_in:
    show_login()
    st.stop()

# ---------- Sidebar ----------
with st.sidebar:
    st.markdown("## 🛡️ NTCF SOC")
    st.caption("NETWORK THREAT COGNITION FRAMEWORK")
    st.divider()

    st.caption("MAIN MENU")
    page = st.radio(
        "Navigation",
        ["Overview", "Threats", "Live Monitoring", "Blocked IPs", "Reports"],
        format_func={
            "Overview": "▦  Overview",
            "Threats": "⚠  Threats",
            "Live Monitoring": "⌁  Live Monitoring",
            "Blocked IPs": "▣  Blocked IPs",
            "Reports": "▤  Reports",
        }.get,
        label_visibility="collapsed",
    )

    st.divider()
    st.caption("SYSTEM")
    st.success("●  API STATUS     Online")
    st.success("●  DATABASE       Ready")

    st.divider()
    st.caption("ACCOUNT")
    username = st.session_state.username or "Administrator"
    st.markdown(f"**{username}**")
    st.caption("Security Administrator")

    if st.button("↪  Logout", use_container_width=True):
        st.session_state.logged_in = False
        st.session_state.auth_token = None
        st.session_state.username = None
        st.rerun()

# ---------- Top application header ----------
left, right = st.columns([4.8, 2], vertical_alignment="center")
with left:
    st.markdown("# NTCF SECURITY OPERATIONS CENTER")
    st.caption("REAL-TIME NETWORK THREAT MONITORING & RESPONSE")

with right:
    st.metric("SYSTEM STATUS", "OPERATIONAL", "●")

st.divider()

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
