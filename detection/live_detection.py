from detection.alerts import (
    create_alert,
    initialize_alerts
)


IGNORED_ACCOUNTS = {
    "system",
    "local service",
    "network service"
}


SUSPICIOUS_PROCESSES = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "mshta.exe"
}


def normalize_account(account):

    if not account:
        return ""

    return str(account).strip().lower()


def is_machine_account(account):

    normalized = normalize_account(
        account
    )

    return normalized.endswith("$")


def is_ignored_account(account):

    normalized = normalize_account(
        account
    )

    if normalized in IGNORED_ACCOUNTS:
        return True

    if is_machine_account(account):
        return True

    return False


def detect_event(event):

    findings = []

    event_id = event["event_id"]

    account = event.get(
        "account",
        ""
    )

    if event_id == 4625:

        if is_ignored_account(account):
            return findings

        findings.append({
            "type": "FAILED_LOGON",
            "severity": "LOW",
            "message": (
                f"Failed logon for "
                f"{account or 'unknown account'}"
            ),
            "score": 2
        })

    elif event_id == 4624:

        if event.get("logon_type") in (3, 10):

            if is_ignored_account(account):
                return findings

            findings.append({
                "type": "REMOTE_LOGON",
                "severity": "LOW",
                "message": (
                    f"Remote/network logon by "
                    f"{account or 'unknown account'} "
                    f"from "
                    f"{event.get('source_ip') or 'unknown source'}"
                ),
                "score": 3
            })

    elif event_id == 4672:

        if is_ignored_account(account):
            return findings

        findings.append({
            "type": "PRIVILEGED_LOGON",
            "severity": "LOW",
            "message": (
                f"Privileged logon detected for "
                f"{account}"
            ),
            "score": 5
        })

    elif event_id == 4688:

        process = (
            event.get("process_name")
            or ""
        ).lower()

        process_name = process.split("\\")[-1]

        if process_name in SUSPICIOUS_PROCESSES:

            if is_machine_account(account):
                return findings

            severity = "MEDIUM"

            findings.append({
                "type": "SUSPICIOUS_PROCESS",
                "severity": severity,
                "message": (
                    f"Suspicious process created: "
                    f"{process_name}"
                ),
                "score": 10
            })

    elif event_id == 4648:

        if is_ignored_account(account):
            return findings

        findings.append({
            "type": "EXPLICIT_CREDENTIALS",
            "severity": "MEDIUM",
            "message": (
                f"Explicit credentials used by "
                f"{account or 'unknown account'}"
            ),
            "score": 10
        })

    return findings


def analyze_events(events):

    initialize_alerts()

    detections = []

    for event in events:

        findings = detect_event(
            event
        )

        for finding in findings:

            created = create_alert(
                event,
                finding
            )

            detections.append({
                "event": event,
                "finding": finding,
                "alert_created": created
            })

    return detections