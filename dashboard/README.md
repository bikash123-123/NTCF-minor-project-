# NTCF SOC Dashboard

This folder is a presentation/integration layer for the existing NTCF project.

## Important

The dashboard does **not** replace the project's packet capture, parser, flow feature extraction, detection, decision engine, database, or backend API.

Live Monitoring uses the existing:

- `packet_capture.live_capture.capture_packets`
- `ntcf_pipeline.process_packet_batch`
- `detection.threat_detector.ThreatDetector`
- `database.connection.SessionLocal`

The dashboard worker captures bounded batches in a background thread so Streamlit stays responsive.

## Run

From the project root:

```powershell
streamlit run dashboard/app.py
```

Start the Flask backend as required by the project before logging in.

### Continuous monitoring

Open **Live Monitoring**, choose the batch size/model/interface, then press **START CONTINUOUS CAPTURE**.

The worker repeatedly:

1. captures a bounded packet batch;
2. sends it through the existing `process_packet_batch`;
3. persists decisions using the existing database session;
4. places the latest processed results in the dashboard stream.

Stop is checked between capture batches.

## Requirements

No new Python dependency is introduced by this dashboard folder beyond the dependencies already used by the project.


## Threat family visualization

The dashboard derives an NSL-KDD threat family from the model's existing
prediction label without changing the backend or ML pipeline. The families
shown are:

- Normal
- DoS
- Probe
- R2L
- U2R
- Unknown (only when a prediction is not in the supported mapping)

Threat family charts are available on the Overview, Threats, and Reports
pages. The original prediction, severity, confidence, and detailed tables
remain available.
