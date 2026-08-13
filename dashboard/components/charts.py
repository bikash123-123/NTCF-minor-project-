"""Reusable SOC charts for dashboard pages.

All charts are built from data already returned by the NTCF APIs or the
existing live packet-processing pipeline. No synthetic security data is
created here.
"""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st


_LAYOUT = dict(
    template="plotly_dark",
    height=300,
    margin=dict(l=20, r=20, t=48, b=20),
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#c8d5df"),
    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
)


def _show(fig, key: str):
    fig.update_layout(**_LAYOUT)
    st.plotly_chart(
        fig,
        use_container_width=True,
        config={"displayModeBar": False},
        key=key,
    )


def _counts(data, name="Category", value="Events"):
    if not data:
        return pd.DataFrame(columns=[name, value])
    return pd.DataFrame(
        [{name: str(k), value: int(v)} for k, v in data.items()]
    ).sort_values(value, ascending=False)


def _bar(df, x, y, title, key, horizontal=False):
    if df.empty:
        st.info("No data available for this chart.")
        return
    if horizontal:
        fig = px.bar(
            df.sort_values(y),
            x=y,
            y=x,
            orientation="h",
            labels={x: x, y: "Events"},
            title=title,
        )
    else:
        fig = px.bar(
            df,
            x=x,
            y=y,
            labels={x: x, y: "Events"},
            title=title,
        )
    _show(fig, key)


def prediction_chart(data, key="prediction_chart"):
    df = _counts(data, "Prediction", "Events")
    _bar(df, "Prediction", "Events", "Detection predictions", key, horizontal=len(df) > 5)


def numeric_confidence_chart(series, key="numeric_confidence_chart"):
    """Show the distribution of numeric confidence scores from API records."""
    if series is None:
        st.info("No numeric confidence data available.")
        return
    if not isinstance(series, pd.Series):
        series = pd.Series(series)
    values = pd.to_numeric(series, errors="coerce").dropna()
    if values.empty:
        st.info("No numeric confidence data available.")
        return
    # Normalize percentages returned as 0-100 to the 0-1 scale.
    if values.max() > 1:
        values = values / 100.0
    fig = px.histogram(
        values,
        x=values,
        nbins=10,
        labels={"x": "Confidence Score"},
        title="Confidence Score Distribution",
    )
    fig.update_xaxes(
        range=[0, 1],
        tickformat=".0%",
        title="Confidence Score",
    )
    _show(fig, key)


def confidence_chart(data, key="confidence_chart"):
    """Show categorical confidence-level distribution.

    The function name remains ``confidence_chart`` for compatibility with
    existing dashboard pages. Only the user-visible chart terminology is
    changed to distinguish confidence level from numeric confidence score.
    """
    df = _counts(data, "Confidence Level", "Events")
    if df.empty:
        st.info("No confidence level data available.")
        return

    df["Confidence Level"] = (
        df["Confidence Level"]
        .astype(str)
        .str.strip()
        .str.title()
    )

    level_order = ["Low", "Medium", "High"]
    if set(df["Confidence Level"]).intersection(level_order):
        df["Confidence Level"] = pd.Categorical(
            df["Confidence Level"],
            categories=level_order,
            ordered=True,
        )
        df = df.sort_values("Confidence Level")

    fig = px.pie(
        df,
        names="Confidence Level",
        values="Events",
        hole=0.58,
        title="Confidence Level Distribution",
    )
    _show(fig, key)


def action_chart(data, key="action_chart"):
    df = _counts(data, "Action", "Events")
    _bar(df, "Action", "Events", "Response actions", key)


def category_bar_chart(data, category_label, title, key):
    df = _counts(data, category_label, "Events")
    _bar(df, category_label, "Events", title, key, horizontal=len(df) > 5)


def severity_chart(data, key="severity_chart"):
    df = _counts(data, "Severity", "Events")
    _bar(df, "Severity", "Events", "Severity distribution", key)


def label_chart(data, key="label_chart"):
    df = _counts(data, "Label", "Events")
    _bar(df, "Label", "Events", "Classification labels", key)


def top_values_chart(series, title, category_label, key, top_n=10):
    if series is None:
        st.info("No data available for this chart.")
        return
    if not isinstance(series, pd.Series):
        series = pd.Series(series)
    series = series.dropna().astype(str)
    if series.empty:
        st.info("No data available for this chart.")
        return
    counts = series.value_counts().head(top_n).sort_values()
    df = counts.rename_axis(category_label).reset_index(name="Events")
    _bar(df, category_label, "Events", title, key, horizontal=True)


def timeline_chart(df, time_col, title, key, value_name="Events"):
    """Plot event counts over time using timestamps already present in df."""
    if df is None or df.empty or time_col not in df.columns:
        st.info("No timestamp data available for this chart.")
        return

    work = df[[time_col]].copy()
    work[time_col] = pd.to_datetime(work[time_col], errors="coerce")
    work = work.dropna(subset=[time_col])
    if work.empty:
        st.info("No timestamp data available for this chart.")
        return

    # Use minute buckets for dense live/security event data.
    work["Time"] = work[time_col].dt.floor("min")
    grouped = work.groupby("Time").size().reset_index(name=value_name)

    fig = px.line(
        grouped,
        x="Time",
        y=value_name,
        markers=True,
        labels={"Time": "Time", value_name: value_name},
        title=title,
    )
    _show(fig, key)


def multi_timeline_chart(df, time_col, group_col, title, key):
    """Plot event volume over time split by a categorical field."""
    if df is None or df.empty or time_col not in df.columns or group_col not in df.columns:
        st.info("No time-series data available for this chart.")
        return

    work = df[[time_col, group_col]].copy()
    work[time_col] = pd.to_datetime(work[time_col], errors="coerce")
    work[group_col] = work[group_col].fillna("Unknown").astype(str)
    work = work.dropna(subset=[time_col])
    if work.empty:
        st.info("No time-series data available for this chart.")
        return

    work["Time"] = work[time_col].dt.floor("min")
    grouped = (
        work.groupby(["Time", group_col])
        .size()
        .reset_index(name="Events")
    )
    fig = px.line(
        grouped,
        x="Time",
        y="Events",
        color=group_col,
        markers=True,
        title=title,
        labels={"Time": "Time", "Events": "Events"},
    )
    _show(fig, key)


def live_metrics_chart(history, key="live_metrics_chart"):
    """Plot packet/flow/threat counters collected by the live worker."""
    if not history:
        st.info("Waiting for the first completed capture batch.")
        return

    df = pd.DataFrame(history)
    if df.empty or "batch" not in df.columns:
        st.info("Waiting for live capture data.")
        return

    value_cols = [c for c in ("packets", "flows", "threats") if c in df.columns]
    if not value_cols:
        st.info("Waiting for live capture data.")
        return

    long = df[["batch", *value_cols]].melt(
        id_vars="batch",
        var_name="Metric",
        value_name="Count",
    )
    fig = px.line(
        long,
        x="batch",
        y="Count",
        color="Metric",
        markers=True,
        title="Live processing activity by capture batch",
        labels={"batch": "Capture batch", "Count": "Count"},
    )
    _show(fig, key)
