"""NSL-KDD attack-family mapping used only for dashboard presentation.

The mapping is derived from the attack labels produced by the NTCF/NSL-KDD
pipeline. It does not alter model predictions, API payloads, or backend data.
"""

from __future__ import annotations

ATTACK_FAMILY_MAP = {
    # Legitimate traffic
    "normal": "Normal",

    # Denial of Service (DoS)
    "apache2": "DoS",
    "back": "DoS",
    "land": "DoS",
    "mailbomb": "DoS",
    "neptune": "DoS",
    "pod": "DoS",
    "processtable": "DoS",
    "smurf": "DoS",
    "teardrop": "DoS",
    "udpstorm": "DoS",
    "worm": "DoS",

    # Probe / reconnaissance
    "ipsweep": "Probe",
    "mscan": "Probe",
    "nmap": "Probe",
    "portsweep": "Probe",
    "saint": "Probe",
    "satan": "Probe",

    # Remote-to-Local (R2L)
    "ftp_write": "R2L",
    "guess_passwd": "R2L",
    "imap": "R2L",
    "multihop": "R2L",
    "named": "R2L",
    "phf": "R2L",
    "sendmail": "R2L",
    "snmpgetattack": "R2L",
    "snmpguess": "R2L",
    "spy": "R2L",
    "warezclient": "R2L",
    "warezmaster": "R2L",
    "xlock": "R2L",
    "xsnoop": "R2L",

    # User-to-Root (U2R)
    "buffer_overflow": "U2R",
    "httptunnel": "U2R",
    "loadmodule": "U2R",
    "perl": "U2R",
    "ps": "U2R",
    "rootkit": "U2R",
    "sqlattack": "U2R",
    "xterm": "U2R",
}

# Allow an API/model to return an already-grouped family without changing it.
KNOWN_FAMILIES = {"normal", "dos", "probe", "r2l", "u2r"}


def get_threat_family(prediction) -> str:
    """Map an individual NSL-KDD prediction to its attack family."""
    if prediction is None:
        return "Unknown"

    value = str(prediction).strip().lower()
    if not value:
        return "Unknown"

    if value in KNOWN_FAMILIES:
        return "DoS" if value == "dos" else value.upper() if value in {"r2l", "u2r"} else value.title()

    return ATTACK_FAMILY_MAP.get(value, "Unknown")


def add_threat_family(df, prediction_column="prediction"):
    """Return a copy of a DataFrame with a derived ``threat_family`` column."""
    result = df.copy()
    if prediction_column in result.columns:
        result["threat_family"] = result[prediction_column].map(get_threat_family)
    else:
        result["threat_family"] = "Unknown"
    return result
