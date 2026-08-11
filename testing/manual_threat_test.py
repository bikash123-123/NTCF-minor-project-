import pandas as pd
import requests

API_URL = "http://127.0.0.1:5000/api/detection/predict"

COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "label",
    "difficulty",
]

df = pd.read_csv(
    "data/raw/KDDTest+.txt",
    names=COLUMNS,
)

# Select a known controlled threat
row = df[df["label"].astype(str).str.startswith("neptune")].iloc[0]

features = row.drop(
    labels=["label", "difficulty"]
).to_dict()

payload = {
    "model_name": "decision_tree",
    "source_ip": "192.168.1.100",
    "destination_ip": "192.168.1.200",
    "features": features,
}

response = requests.post(
    API_URL,
    json=payload,
    timeout=10,
)

print("HTTP status:", response.status_code)
print("Response:")
print(response.json())
