"""
response_actions.py

Determine response actions based on model predictions
and confidence levels.
"""

from backend.services.firewall_service import block_ip_address


def determine_response(
    prediction,
    confidence_level,
    ip_address=None,
):
    """
    Determine the appropriate response action.

    Parameters
    ----------
    prediction : str
        Model prediction.

    confidence_level : str
        high, medium or low.

    ip_address : str, optional
        Source IP address.

    Returns
    -------
    dict
        Response information.
    """

    prediction = prediction.lower()

    # Benign traffic
    if prediction == "normal":
        return {
            "action": "allow",
            "message": "Traffic classified as normal."
        }

    # High confidence attack
    if confidence_level == "high":

        firewall_result = None

        if ip_address is not None:
            firewall_result = block_ip_address(
                ip_address=ip_address,
                reason="High confidence attack",
                dry_run=True,
            )

        return {
            "action": "block",
            "message": "High confidence malicious traffic detected.",
            "firewall": firewall_result,
        }

    # Medium confidence attack
    if confidence_level == "medium":
        return {
            "action": "monitor",
            "message": "Monitor traffic for further analysis."
        }

    # Low confidence attack
    return {
        "action": "log",
        "message": "Low confidence prediction. Event logged only."
    }