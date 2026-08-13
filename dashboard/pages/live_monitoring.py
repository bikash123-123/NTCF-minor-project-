"""
Live SOC monitoring.

The dashboard reuses the project's existing packet capture and pipeline.
It runs bounded capture batches in a background thread and displays the
results without changing the backend or packet-capture implementation.
"""

from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
import sys
import threading
import time

import pandas as pd
import requests
import streamlit as st

# Make the project root importable when this page is imported directly
# or when Streamlit changes the working directory.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.connection import SessionLocal, init_db
from components.charts import (
    action_chart,
    confidence_chart,
    live_metrics_chart,
    prediction_chart,
    severity_chart,
    top_values_chart,
)
from detection.threat_detector import ThreatDetector
from ntcf_pipeline import process_packet_batch
from packet_capture.live_capture import capture_packets

BACKEND = "http://127.0.0.1:5000"


@dataclass
class LiveState:
    lock: threading.Lock = field(default_factory=threading.Lock)
    stop_event: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None
    rows: deque = field(default_factory=lambda: deque(maxlen=100))
    history: deque = field(default_factory=lambda: deque(maxlen=60))
    packets: int = 0
    flows: int = 0
    threats: int = 0
    batches: int = 0
    started: float | None = None
    error: str | None = None


def _get_state():
    if "live_state" not in st.session_state:
        st.session_state.live_state = LiveState()
    return st.session_state.live_state


def _running(state):
    return bool(state.thread and state.thread.is_alive())


def _worker(state, batch_size, interface, model_name):
    try:
        init_db()
        db = SessionLocal()
        detector = ThreatDetector(model_name=model_name)

        try:
            while not state.stop_event.is_set():
                packets = capture_packets(
                    packet_count=batch_size,
                    interface=interface or None,
                )

                if state.stop_event.is_set():
                    break

                if not packets:
                    continue

                results = process_packet_batch(packets, detector, db)

                rows = [
                    {
                        "Source": result.get("source_ip", "—"),
                        "Destination": result.get("destination_ip", "—"),
                        "Prediction": result.get("prediction", "—"),
                        "Confidence": result.get("confidence_score", "—"),
                        "Level": result.get("confidence_level", "—"),
                        "Severity": result.get("severity", "—"),
                        "Action": result.get("action", "—"),
                    }
                    for result in results
                ]

                threat_count = sum(
                    str(result.get("prediction", "")).lower() != "normal"
                    for result in results
                )

                with state.lock:
                    state.packets += len(packets)
                    state.flows += len(results)
                    state.threats += threat_count
                    state.batches += 1
                    state.history.append(
                        {
                            "batch": state.batches,
                            "packets": state.packets,
                            "flows": state.flows,
                            "threats": state.threats,
                        }
                    )
                    for row in reversed(rows):
                        state.rows.appendleft(row)

        finally:
            db.close()

    except Exception as exc:
        with state.lock:
            state.error = f"{type(exc).__name__}: {exc}"

    finally:
        with state.lock:
            state.thread = None


def _start(state, batch_size, interface, model_name):
    if _running(state):
        return

    state.stop_event = threading.Event()
    with state.lock:
        state.rows.clear()
        state.history.clear()
        state.packets = 0
        state.flows = 0
        state.threats = 0
        state.batches = 0
        state.started = time.time()
        state.error = None

    state.thread = threading.Thread(
        target=_worker,
        args=(state, batch_size, interface.strip(), model_name),
        name="ntcf-dashboard-live-capture",
        daemon=True,
    )
    state.thread.start()


def _stop(state):
    state.stop_event.set()


def _backend_health():
    try:
        response = requests.get(f"{BACKEND}/api/dashboard/health", timeout=2)
        return response.status_code == 200
    except requests.RequestException:
        return False


def _snapshot(state):
    with state.lock:
        return {
            "packets": state.packets,
            "flows": state.flows,
            "threats": state.threats,
            "batches": state.batches,
            "started": state.started,
            "error": state.error,
            "rows": list(state.rows),
            "history": list(state.history),
        }


def show_live_monitoring():
    state = _get_state()
    running = _running(state)

    st.caption("LIVE OPERATIONS")
    st.header("Live Threat Monitoring")
    st.caption(
        "Continuous packet capture → flow processing → ML detection → decision engine."
    )

    with st.container(border=True):
        st.subheader("Capture Controls")
        c1, c2, c3 = st.columns([1, 1, 2])

        with c1:
            batch_size = st.selectbox(
                "Batch size",
                [5, 10, 20, 50, 100],
                index=2,
                disabled=running,
                key="live_batch_size",
            )

        with c2:
            model_name = st.selectbox(
                "Detection model",
                ["decision_tree", "random_forest", "svm"],
                disabled=running,
                key="live_model",
            )

        with c3:
            interface = st.text_input(
                "Network interface (optional)",
                placeholder="Blank = Scapy default interface",
                disabled=running,
                key="live_interface",
            )

        b1, b2, b3 = st.columns(3)
        with b1:
            if st.button(
                "▶  START CONTINUOUS CAPTURE",
                type="primary",
                use_container_width=True,
                disabled=running,
            ):
                _start(state, batch_size, interface, model_name)
                st.rerun()

        with b2:
            if st.button(
                "■  STOP CAPTURE",
                use_container_width=True,
                disabled=not running,
            ):
                _stop(state)
                st.rerun()

        with b3:
            if _backend_health():
                st.success("Backend API • Online")
            else:
                st.error("Backend API • Offline")

    snap = _snapshot(state)

    if snap["error"]:
        st.error(f"Live pipeline error: {snap['error']}")

    # The whole live section refreshes independently while capture is running.
    if running and hasattr(st, "fragment"):
        @st.fragment(run_every="2s")
        def live_view():
            current = _snapshot(state)
            st.divider()

            a, b, c, d = st.columns(4)
            a.metric("CAPTURE STATUS", "RUNNING")
            b.metric("PACKETS CAPTURED", current["packets"])
            c.metric("PROCESSED FLOWS", current["flows"])
            d.metric("THREATS DETECTED", current["threats"])

            st.subheader("Live Processing Activity")
            live_metrics_chart(current["history"], key="live_batch_metrics")

            live_df = pd.DataFrame(current["rows"])
            if not live_df.empty:
                st.subheader("Live Detection Analytics")
                chart_a, chart_b = st.columns(2)
                with chart_a:
                    prediction_chart(
                        live_df["Prediction"].astype(str).value_counts().to_dict(),
                        key="live_predictions",
                    )
                with chart_b:
                    confidence_chart(
                        live_df["Level"].astype(str).value_counts().to_dict(),
                        key="live_confidence",
                    )

                chart_c, chart_d = st.columns(2)
                with chart_c:
                    severity_chart(
                        live_df["Severity"].astype(str).value_counts().to_dict(),
                        key="live_severity",
                    )
                with chart_d:
                    action_chart(
                        live_df["Action"].astype(str).value_counts().to_dict(),
                        key="live_actions",
                    )

                chart_e, chart_f = st.columns(2)
                with chart_e:
                    top_values_chart(
                        live_df["Source"],
                        "Top active source IPs",
                        "Source IP",
                        "live_source_ips",
                    )
                with chart_f:
                    top_values_chart(
                        live_df["Destination"],
                        "Top active destination IPs",
                        "Destination IP",
                        "live_destination_ips",
                    )

                st.subheader("Live Detection Stream")
                st.dataframe(
                    live_df,
                    use_container_width=True,
                    hide_index=True,
                    height=430,
                )
            else:
                st.info("Capture is running. Waiting for the first processed batch...")

            st.caption(
                f"Batch cycles completed: {current['batches']} • "
                "Live refresh: every 2 seconds"
            )

        live_view()
    else:
        st.divider()
        a, b, c, d = st.columns(4)
        a.metric("CAPTURE STATUS", "RUNNING" if running else "STOPPED")
        b.metric("PACKETS CAPTURED", snap["packets"])
        c.metric("PROCESSED FLOWS", snap["flows"])
        d.metric("THREATS DETECTED", snap["threats"])

        st.subheader("Live Processing Activity")
        live_metrics_chart(snap["history"], key="live_batch_metrics_static")

        live_df = pd.DataFrame(snap["rows"])
        if not live_df.empty:
            st.subheader("Live Detection Analytics")
            chart_a, chart_b = st.columns(2)
            with chart_a:
                prediction_chart(
                    live_df["Prediction"].astype(str).value_counts().to_dict(),
                    key="live_predictions_static",
                )
            with chart_b:
                confidence_chart(
                    live_df["Level"].astype(str).value_counts().to_dict(),
                    key="live_confidence_static",
                )
            chart_c, chart_d = st.columns(2)
            with chart_c:
                severity_chart(
                    live_df["Severity"].astype(str).value_counts().to_dict(),
                    key="live_severity_static",
                )
            with chart_d:
                action_chart(
                    live_df["Action"].astype(str).value_counts().to_dict(),
                    key="live_actions_static",
                )

            st.subheader("Live Detection Stream")
            st.dataframe(
                live_df,
                use_container_width=True,
                hide_index=True,
                height=430,
            )
        else:
            st.info(
                "No processed flows yet. Start continuous capture to populate the stream."
            )

    st.divider()
    st.caption(
        "This page reuses the project's existing packet_capture.live_capture "
        "and ntcf_pipeline.process_packet_batch implementations. "
        "Capture is bounded by batch size so the dashboard remains responsive."
    )
