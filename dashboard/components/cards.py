"""Reusable SOC dashboard components."""

import streamlit as st


def metric_card(title, value, subtitle="", icon=""):
    st.metric(
        label=f"{icon} {title}".strip(),
        value=value,
        help=subtitle or None,
    )


def section_header(title, subtitle=None):
    st.subheader(title)
    if subtitle:
        st.caption(subtitle)


def status_card(title, value, state="online"):
    if state == "online":
        st.success(f"● {title}\n\n**{value}**")
    elif state == "warning":
        st.warning(f"● {title}\n\n**{value}**")
    else:
        st.error(f"● {title}\n\n**{value}**")
