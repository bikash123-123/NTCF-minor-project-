"""
Reusable tables for the NTCF dashboard.
"""

import pandas as pd
import streamlit as st


def searchable_table(
    dataframe,
    search_column=None,
):

    if dataframe is None:
        st.info("No data available.")
        return

    if not isinstance(
        dataframe,
        pd.DataFrame,
    ):
        dataframe = pd.DataFrame(
            dataframe
        )

    if dataframe.empty:

        st.info(
            "No records available."
        )

        return

    search = st.text_input(
        "🔎 Search",
        placeholder="Search records...",
    )

    if search:

        if search_column and search_column in dataframe.columns:

            mask = (
                dataframe[
                    search_column
                ]
                .astype(str)
                .str.contains(
                    search,
                    case=False,
                    na=False,
                )
            )

        else:

            mask = dataframe.astype(
                str
            ).apply(
                lambda row:
                row.str.contains(
                    search,
                    case=False,
                    na=False,
                ).any(),
                axis=1,
            )

        dataframe = dataframe[mask]

    st.dataframe(
        dataframe,
        use_container_width=True,
        hide_index=True,
    )