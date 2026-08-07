"""
Reusable dashboard metric cards.
"""

import streamlit as st


def metric_card(
    title,
    value,
    subtitle="",
    icon="📊",
):
    """
    Display a reusable SOC metric card.
    """

    st.markdown(
        f"""
        <div class="metric-card">

            <div class="metric-card-top">

                <div>
                    <div class="metric-title">
                        {title}
                    </div>

                    <div class="metric-value">
                        {value}
                    </div>

                    <div class="metric-subtitle">
                        {subtitle}
                    </div>
                </div>

                <div class="metric-icon">
                    {icon}
                </div>

            </div>

        </div>
        """,
        unsafe_allow_html=True,
    )