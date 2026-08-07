"""
NTCF Dashboard - Reports

Issue #29
"""

import pandas as pd
import requests
import streamlit as st


THREAT_API = "http://127.0.0.1:5000/api/threats"


def get_threat_data():

    try:

        response = requests.get(
            THREAT_API,
            timeout=5,
        )

        if response.status_code != 200:

            return None, response.status_code

        data = response.json()

        return data.get(
            "data",
            [],
        ), 200

    except requests.RequestException:

        return None, None

    except ValueError:

        return None, None


def show_reports():

    st.title("📄 Security Reports")

    st.caption(
        "Generate a report from recorded NTCF threat events."
    )

    st.divider()

    data, status_code = get_threat_data()

    if status_code is None:

        st.error(
            "🔴 Unable to connect to the Threat API."
        )

        st.info(
            "Make sure the Flask backend is running."
        )

        return

    if status_code != 200:

        st.error(
            f"Threat API returned HTTP {status_code}."
        )

        return

    if not data:

        st.info(
            "No threat events are currently available."
        )

        return

    df = pd.DataFrame(data)

    # =====================================================
    # Summary
    # =====================================================

    st.subheader("📊 Report Summary")

    total_events = len(df)

    threat_count = 0

    if "label" in df.columns:

        threat_count = (
            df["label"]
            .astype(str)
            .str.lower()
            .eq("threat")
            .sum()
        )

    col1, col2 = st.columns(2)

    with col1:

        st.metric(
            "Total Events",
            total_events,
        )

    with col2:

        st.metric(
            "Threat Events",
            int(threat_count),
        )

    st.divider()

    # =====================================================
    # Event Table
    # =====================================================

    st.subheader("📋 Threat Event Report")

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
    )

    # =====================================================
    # CSV Download
    # =====================================================

    csv_data = df.to_csv(
        index=False
    )

    st.download_button(
        label="⬇️ Download CSV Report",
        data=csv_data,
        file_name="ntcf_threat_report.csv",
        mime="text/csv",
        use_container_width=True,
    )