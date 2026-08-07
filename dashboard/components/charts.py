"""
Reusable Plotly charts for the NTCF dashboard.
"""

import plotly.express as px
import streamlit as st


def prediction_chart(data):

    if not data:
        st.info("No prediction data available.")
        return

    chart_data = {
        "Prediction": list(data.keys()),
        "Count": list(data.values()),
    }

    figure = px.bar(
        chart_data,
        x="Prediction",
        y="Count",
        title="Threat Predictions",
    )

    figure.update_layout(
        template="plotly_dark",
        height=350,
        margin=dict(
            l=20,
            r=20,
            t=50,
            b=20,
        ),
    )

    st.plotly_chart(
        figure,
        use_container_width=True,
    )


def confidence_chart(data):

    if not data:
        st.info("No confidence data available.")
        return

    chart_data = {
        "Confidence": list(data.keys()),
        "Count": list(data.values()),
    }

    figure = px.pie(
        chart_data,
        names="Confidence",
        values="Count",
        title="Confidence Distribution",
        hole=0.45,
    )

    figure.update_layout(
        template="plotly_dark",
        height=350,
    )

    st.plotly_chart(
        figure,
        use_container_width=True,
    )


def action_chart(data):

    if not data:
        st.info("No response action data available.")
        return

    chart_data = {
        "Action": list(data.keys()),
        "Count": list(data.values()),
    }

    figure = px.bar(
        chart_data,
        x="Action",
        y="Count",
        title="Response Actions",
    )

    figure.update_layout(
        template="plotly_dark",
        height=350,
    )

    st.plotly_chart(
        figure,
        use_container_width=True,
    )