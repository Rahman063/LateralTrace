from detection.lateral_movement import detect_lateral_movement


def calculate_risk(account=None):

    findings = detect_lateral_movement(
        account=account
    )

    score = sum(
        finding["score"]
        for finding in findings
    )

    if score >= 80:
        severity = "CRITICAL"

    elif score >= 50:
        severity = "HIGH"

    elif score >= 25:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    return {
        "score": score,
        "severity": severity,
        "findings": findings
    }