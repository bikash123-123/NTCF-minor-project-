"""Reusable dashboard tables."""

import pandas as pd
import streamlit as st


def searchable_table(dataframe, search_column=None, key="table_search"):
    if dataframe is None:
        st.info("No records available.")
        return

    df = dataframe if isinstance(dataframe, pd.DataFrame) else pd.DataFrame(dataframe)
    if df.empty:
        st.info("No records available.")
        return

    query = st.text_input("Search", placeholder="Search records...", key=key)
    if query:
        if search_column and search_column in df.columns:
            mask = df[search_column].astype(str).str.contains(query, case=False, na=False)
        else:
            mask = df.astype(str).apply(
                lambda row: row.str.contains(query, case=False, na=False).any(),
                axis=1,
            )
        df = df[mask]

    st.dataframe(df, use_container_width=True, hide_index=True)
