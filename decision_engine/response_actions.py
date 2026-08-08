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

    prediction = str(prediction).lower()

    # ---------------------------------------------------------
    # Benign traffic
    # ---------------------------------------------------------

    if prediction == "normal":
        return {
            "action": "allow",
            "message": "Traffic classified as normal.",
        }

    # ---------------------------------------------------------
    # High confidence attack
    # ---------------------------------------------------------

    if confidence_level == "high":

        firewall_result = None

        if ip_address is not None:

            firewall_result = block_ip_address(
                ip_address=ip_address,
                reason="High confidence attack",
                dry_run=True,
            )

            # -------------------------------------------------
            # Normalize firewall service response.
            #
            # Supports both:
            #
            # Direct response:
            # {
            #     "success": True,
            #     "ip_address": "...",
            #     "reason": "...",
            #     "dry_run": True,
            # }
            #
            # Wrapped response:
            # {
            #     "success": True,
            #     "status_code": 201,
            #     "result": {...}
            # }
            # -------------------------------------------------

            if isinstance(firewall_result, dict):

                if firewall_result.get("success") is True:

                    manager_result = firewall_result.get(
                        "result"
                    )

                    if not isinstance(
                        manager_result,
                        dict,
                    ):
                        manager_result = firewall_result

                    firewall_result = {
                        "success": True,
                        "status": "success",
                        "ip_address": manager_result.get(
                            "ip_address",
                            ip_address,
                        ),
                        "reason": manager_result.get(
                            "reason",
                            "High confidence attack",
                        ),
                        "dry_run": manager_result.get(
                            "dry_run",
                            True,
                        ),
                    }

                else:

                    firewall_result = {
                        "success": False,
                        "status": "failed",
                        "ip_address": ip_address,
                        "reason": firewall_result.get(
                            "error",
                            "Firewall operation failed.",
                        ),
                        "dry_run": True,
                        "error_type": firewall_result.get(
                            "error_type"
                        ),
                        "status_code": firewall_result.get(
                            "status_code"
                        ),
                    }

        return {
            "action": "block",
            "message": (
                "High confidence malicious traffic detected."
            ),
            "firewall": firewall_result,
        }

    # ---------------------------------------------------------
    # Medium confidence attack
    # ---------------------------------------------------------

    if confidence_level == "medium":
        return {
            "action": "monitor",
            "message": (
                "Monitor traffic for further analysis."
            ),
        }

    # ---------------------------------------------------------
    # Low confidence attack
    # ---------------------------------------------------------

    return {
        "action": "log",
        "message": (
            "Low confidence prediction. Event logged only."
        )
    }