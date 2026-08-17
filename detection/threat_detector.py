"""
threat_detector.py

Threat detection engine for NTCF.

The detector uses the existing PredictionService and existing
ML model. No model training or model artifact modification is
performed here.

NSL-KDD attack categories supported:
    - DoS
    - Probe
    - R2L
    - U2R
    - Normal
    - Other
"""

from detection.prediction_service import PredictionService


# ---------------------------------------------------------------------
# NSL-KDD attack categories
# ---------------------------------------------------------------------

# Denial of Service attacks.
DOS_ATTACKS = {
    "back",
    "land",
    "neptune",
    "pod",
    "smurf",
    "teardrop",
    "apache2",
    "udpstorm",
    "processtable",
    "mailbomb",
}


# Probe / reconnaissance attacks.
PROBE_ATTACKS = {
    "satan",
    "ipsweep",
    "nmap",
    "portsweep",
    "mscan",
    "saint",
}


# Remote-to-Local attacks.
R2L_ATTACKS = {
    "guess_passwd",
    "warezmaster",
    "warezclient",
    "ftp_write",
    "imap",
    "phf",
    "multihop",
    "spy",
}


# User-to-Root attacks.
U2R_ATTACKS = {
    "buffer_overflow",
    "rootkit",
    "perl",
    "loadmodule",
}


# ---------------------------------------------------------------------
# Threat Detector
# ---------------------------------------------------------------------

class ThreatDetector:

    def __init__(
        self,
        model_name="decision_tree",
    ):
        self.predictor = PredictionService(
            model_name=model_name
        )

    def detect(
        self,
        features,
    ):
        """
        Predict a network event and classify the predicted
        NSL-KDD attack label into its threat family.

        Returns
        -------
        dict
            prediction
            category
            label
            confidence
            status
        """

        try:

            # ---------------------------------------------------------
            # Use the existing prediction pipeline.
            # No model is retrained or modified.
            # ---------------------------------------------------------

            prediction, confidence = (
                self.predictor.predict(
                    features
                )
            )

            prediction_str = str(
                prediction
            )

            prediction_lower = (
                prediction_str.lower()
            )

            # ---------------------------------------------------------
            # Determine threat category.
            # ---------------------------------------------------------

            if prediction_lower == "normal":

                label = "Normal"
                category = "Normal"

            elif prediction_lower in DOS_ATTACKS:

                label = "Threat"
                category = "DoS"

            elif prediction_lower in PROBE_ATTACKS:

                label = "Threat"
                category = "Probe"

            elif prediction_lower in R2L_ATTACKS:

                label = "Threat"
                category = "R2L"

            elif prediction_lower in U2R_ATTACKS:

                label = "Threat"
                category = "U2R"

            else:

                # Preserve the original behavior:
                # any non-normal prediction remains a Threat.
                label = "Threat"
                category = "Other"

            # ---------------------------------------------------------
            # Return detector result.
            # ---------------------------------------------------------

            return {
                "prediction": prediction_str,
                "category": category,
                "label": label,
                "confidence": round(
                    confidence,
                    4,
                ),
                "status": "success",
            }

        except Exception as error:

            return {
                "status": "error",
                "message": str(error),
            }