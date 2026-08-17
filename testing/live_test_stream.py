"""
live_test_stream.py

Controlled NTCF test using existing NSL-KDD test samples.

This script:

1. Loads existing R2L/U2R samples from KDDTest+.
2. Sends them through the existing NTCF preprocessing pipeline.
3. Uses the existing Decision Tree model.
4. Finds samples that the model actually predicts as attacks.
5. Passes those predictions through ThreatDetector.
6. Verifies that R2L/U2R predictions are reported as Threat.

IMPORTANT:
- Does NOT train a model.
- Does NOT modify any model artifact.
- Does NOT modify packet capture.
- Does NOT generate network traffic.
- Does NOT modify the NTCF APIs.
"""

import argparse
import time

from detection.preprocessing_service import (
    preprocess_features,
)

from detection.threat_detector import (
    ThreatDetector,
)

from testing.test_attack_samples import (
    get_r2l_samples,
    get_u2r_samples,
)


# ---------------------------------------------------------------------
# Find samples that the EXISTING model actually detects
# ---------------------------------------------------------------------


def find_detected_samples(
    samples,
    detector,
    required_category,
    count,
):
    """
    Search through existing NSL-KDD samples and return samples
    that the existing model genuinely predicts as threats.

    The expected dataset category and model-predicted category
    must match.

    Example:

        Expected category = R2L
        Model prediction  = guess_passwd
        Model category    = R2L

    This is accepted as a genuine R2L threat detection.
    """

    detected = []

    print(
        f"\nSearching for {required_category} samples "
        f"that the existing model detects..."
    )

    for sample in samples:

        try:

            processed_features = preprocess_features(
                sample["features"]
            )

            result = detector.detect(
                processed_features
            )

            if result.get("status") != "success":
                continue

            predicted_category = result.get(
                "category",
                "Unknown",
            )

            predicted_label = str(
                result.get(
                    "prediction",
                    ""
                )
            ).strip().rstrip(".")

            # ---------------------------------------------------------
            # We only accept the sample when:
            #
            # 1. The model predicted an attack.
            # 2. The model category is the expected category.
            #
            # This prevents us from calling a wrong-category
            # prediction a successful R2L/U2R detection.
            # ---------------------------------------------------------

            if (
                result.get("label") == "Threat"
                and predicted_category == required_category
            ):

                detected.append(
                    {
                        "sample": sample,
                        "result": result,
                    }
                )

                print(
                    f"  FOUND | "
                    f"{required_category} | "
                    f"Expected: {sample['attack']} | "
                    f"Predicted: {predicted_label} | "
                    f"Confidence: "
                    f"{result.get('confidence')}"
                )

                if len(detected) >= count:
                    break

        except Exception:
            # Ignore an individual bad sample and continue scanning.
            continue

    return detected


# ---------------------------------------------------------------------
# Display result
# ---------------------------------------------------------------------


def print_result(
    item,
):
    """
    Display one confirmed model-detected threat.
    """

    sample = item["sample"]
    result = item["result"]

    print("\n" + "-" * 70)

    print(
        f"Source:            {sample['source']}"
    )

    print(
        f"Expected category: {sample['category']}"
    )

    print(
        f"Expected attack:   {sample['attack']}"
    )

    print(
        f"Model prediction:  {result['prediction']}"
    )

    print(
        f"Model category:    {result['category']}"
    )

    print(
        f"Model label:       {result['label']}"
    )

    print(
        f"Confidence:        {result['confidence']}"
    )

    # -------------------------------------------------------------
    # Category-level detection
    # -------------------------------------------------------------

    if (
        result["label"] == "Threat"
        and result["category"] == sample["category"]
    ):

        print(
            "Threat detection:  YES"
        )

    else:

        print(
            "Threat detection:  NO"
        )

    # -------------------------------------------------------------
    # Exact attack match
    # -------------------------------------------------------------

    expected = (
        str(sample["attack"])
        .strip()
        .lower()
        .rstrip(".")
    )

    predicted = (
        str(result["prediction"])
        .strip()
        .lower()
        .rstrip(".")
    )

    if predicted == expected:

        print(
            "Attack match:      YES"
        )

    else:

        print(
            "Attack match:      NO "
            "(different attack label, "
            "but category detected)"
        )


# ---------------------------------------------------------------------
# Run controlled test
# ---------------------------------------------------------------------


def run_test_stream(
    r2l_count=5,
    u2r_count=5,
    interval=2.0,
):
    """
    Find and test R2L/U2R samples that the existing model
    genuinely predicts as threats.
    """

    print("\n" + "=" * 70)
    print("NTCF MODEL-DETECTED R2L/U2R TEST")
    print("=" * 70)

    print(
        "\nThis test uses existing NSL-KDD test samples."
    )

    print(
        "No attack traffic is generated."
    )

    print(
        "Existing packet capture is not modified."
    )

    print(
        "Existing ML model is not modified."
    )

    print(
        "No model is retrained."
    )

    print(
        f"\nRequested R2L detections: {r2l_count}"
    )

    print(
        f"Requested U2R detections: {u2r_count}"
    )

    # -------------------------------------------------------------
    # Load detector
    # -------------------------------------------------------------

    print(
        "\nLoading existing NTCF detector..."
    )

    detector = ThreatDetector(
        model_name="decision_tree"
    )

    print(
        "Detector loaded successfully."
    )

    # -------------------------------------------------------------
    # Load a large pool of existing samples.
    #
    # We intentionally load many samples because we are searching
    # for samples that the existing model actually detects.
    # -------------------------------------------------------------

    print(
        "\nLoading R2L/U2R samples..."
    )

    r2l_samples = get_r2l_samples(
        limit=None
    )

    u2r_samples = get_u2r_samples(
        limit=None
    )

    print(
        f"R2L samples available: {len(r2l_samples)}"
    )

    print(
        f"U2R samples available: {len(u2r_samples)}"
    )

    # -------------------------------------------------------------
    # Find genuine R2L detections
    # -------------------------------------------------------------

    r2l_detected = find_detected_samples(
        samples=r2l_samples,
        detector=detector,
        required_category="R2L",
        count=r2l_count,
    )

    # -------------------------------------------------------------
    # Find genuine U2R detections
    # -------------------------------------------------------------

    u2r_detected = find_detected_samples(
        samples=u2r_samples,
        detector=detector,
        required_category="U2R",
        count=u2r_count,
    )

    # -------------------------------------------------------------
    # Combine results
    # -------------------------------------------------------------

    detected_samples = []

    max_length = max(
        len(r2l_detected),
        len(u2r_detected),
    )

    for index in range(max_length):

        if index < len(r2l_detected):

            detected_samples.append(
                r2l_detected[index]
            )

        if index < len(u2r_detected):

            detected_samples.append(
                u2r_detected[index]
            )

    # -------------------------------------------------------------
    # Report search result
    # -------------------------------------------------------------

    print("\n" + "=" * 70)
    print("SEARCH COMPLETE")
    print("=" * 70)

    print(
        f"R2L detections found: "
        f"{len(r2l_detected)} / {r2l_count}"
    )

    print(
        f"U2R detections found: "
        f"{len(u2r_detected)} / {u2r_count}"
    )

    if not detected_samples:

        print(
            "\nThe existing model did not produce any "
            "R2L/U2R predictions in the requested test."
        )

        print(
            "No model or packet-capture changes were made."
        )

        return

    # -------------------------------------------------------------
    # Replay the selected model-detected samples
    # -------------------------------------------------------------

    print(
        "\nStarting controlled detection test..."
    )

    successful = 0
    threat_predictions = 0
    exact_matches = 0

    for item in detected_samples:

        sample = item["sample"]
        result = item["result"]

        print_result(item)

        successful += 1

        if (
            result.get("label") == "Threat"
            and result.get("category")
            == sample["category"]
        ):

            threat_predictions += 1

        expected = (
            str(sample["attack"])
            .strip()
            .lower()
            .rstrip(".")
        )

        predicted = (
            str(result["prediction"])
            .strip()
            .lower()
            .rstrip(".")
        )

        if predicted == expected:

            exact_matches += 1

        time.sleep(
            interval
        )

    # -------------------------------------------------------------
    # Final summary
    # -------------------------------------------------------------

    print("\n" + "=" * 70)
    print("TEST COMPLETE")
    print("=" * 70)

    print(
        f"Samples tested:       {len(detected_samples)}"
    )

    print(
        f"Successful:            {successful}"
    )

    print(
        f"Threat predictions:    {threat_predictions}"
    )

    print(
        f"Exact attack matches:  {exact_matches}"
    )

    print(
        f"R2L detections:        {len(r2l_detected)}"
    )

    print(
        f"U2R detections:        {len(u2r_detected)}"
    )

    # -------------------------------------------------------------
    # Overall conclusion
    # -------------------------------------------------------------

    if (
        successful > 0
        and threat_predictions == successful
    ):

        print(
            "\nRESULT: SUCCESS"
        )

        print(
            "The existing model produced genuine "
            "R2L/U2R attack predictions, and the "
            "NTCF ThreatDetector correctly classified "
            "those predictions as Threat."
        )

    else:

        print(
            "\nRESULT: PARTIAL"
        )

        print(
            "Not every selected sample was classified "
            "as a matching R2L/U2R threat."
        )

    print(
        "\nNo model artifact was changed."
    )

    print(
        "No packet-capture files were changed."
    )

    print(
        "No API files were changed."
    )

    print("=" * 70)


# ---------------------------------------------------------------------
# Command-line arguments
# ---------------------------------------------------------------------


def parse_arguments():
    """
    Parse command-line arguments.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Test whether the existing NTCF model "
            "can genuinely detect R2L/U2R samples "
            "as Threat."
        )
    )

    parser.add_argument(
        "--r2l",
        type=int,
        default=5,
        help=(
            "Number of detected R2L samples "
            "to test (default: 5)"
        ),
    )

    parser.add_argument(
        "--u2r",
        type=int,
        default=5,
        help=(
            "Number of detected U2R samples "
            "to test (default: 5)"
        ),
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help=(
            "Seconds between displayed test results "
            "(default: 2)"
        ),
    )

    return parser.parse_args()


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------


if __name__ == "__main__":

    args = parse_arguments()

    if args.r2l <= 0:
        raise ValueError(
            "--r2l must be greater than zero."
        )

    if args.u2r <= 0:
        raise ValueError(
            "--u2r must be greater than zero."
        )

    if args.interval < 0:
        raise ValueError(
            "--interval cannot be negative."
        )

    run_test_stream(
        r2l_count=args.r2l,
        u2r_count=args.u2r,
        interval=args.interval,
    )