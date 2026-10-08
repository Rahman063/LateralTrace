from datetime import datetime

from database import get_connection
from detection.alerts import create_correlation_alert


WINDOW_MINUTES = 15

SUSPICIOUS_PROCESSES = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "mshta.exe"
}


def parse_timestamp(value):

    if not value:
        return None

    value = str(value).strip()

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%a %b %d %H:%M:%S %Y",
        "%a %b %d %H:%M:%S.%f %Y"
    ]

    for fmt in formats:

        try:
            return datetime.strptime(
                value,
                fmt
            )

        except ValueError:
            continue

    return None


def get_recent_windows_events(limit=500):

    db = get_connection()

    rows = db.execute(
        """
        SELECT
            id,
            timestamp,
            event_id,
            computer,
            account,
            source_ip,
            logon_type,
            process_name,
            command_line,
            target_account,
            description,
            record_id
        FROM events
        WHERE source = 'windows'
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    db.close()

    return [dict(row) for row in rows]


def normalize_account(account):

    if not account:
        return ""

    return str(account).strip().lower()


def is_remote_logon(event):

    return (
        event["event_id"] == 4624
        and event["logon_type"] in (3, 10)
    )


def is_suspicious_process(event):

    if event["event_id"] != 4688:
        return False

    process = (
        event.get("process_name")
        or ""
    ).lower()

    process_name = process.split("\\")[-1]

    return process_name in SUSPICIOUS_PROCESSES


def group_events_by_account(events):

    groups = {}

    for event in events:

        account = normalize_account(
            event.get("account")
        )

        if not account:
            continue

        if account in {
            "system",
            "local service",
            "network service"
        }:
            continue

        groups.setdefault(
            account,
            []
        ).append(event)

    return groups


def analyze_account(account, events):

    parsed_events = []

    for event in events:

        timestamp = parse_timestamp(
            event.get("timestamp")
        )

        if timestamp:

            event_copy = dict(event)
            event_copy["_parsed_time"] = timestamp

            parsed_events.append(
                event_copy
            )

    if not parsed_events:
        return None

    parsed_events.sort(
        key=lambda event: event["_parsed_time"]
    )

    remote_logons = [
        event
        for event in parsed_events
        if is_remote_logon(event)
    ]

    computers = sorted(
        {
            event["computer"]
            for event in remote_logons
            if event.get("computer")
        }
    )

    if len(computers) < 2:
        return None

    first_time = parsed_events[0]["_parsed_time"]
    last_time = parsed_events[-1]["_parsed_time"]

    time_span = (
        last_time - first_time
    ).total_seconds() / 60

    if time_span > WINDOW_MINUTES:
        return None

    privileged_events = [
        event
        for event in parsed_events
        if event["event_id"] == 4672
    ]

    suspicious_processes = [
        event
        for event in parsed_events
        if is_suspicious_process(event)
    ]

    explicit_credentials = [
        event
        for event in parsed_events
        if event["event_id"] == 4648
    ]

    score = 0
    findings = []

    if len(computers) >= 2:

        score += 25

        findings.append(
            f"Account accessed {len(computers)} computers"
        )

    if len(computers) >= 3:

        score += 20

        findings.append(
            "Account accessed three or more computers"
        )

    if privileged_events:

        score += 25

        findings.append(
            "Privileged activity detected"
        )

    if suspicious_processes:

        score += 25

        findings.append(
            "Suspicious process execution detected"
        )

    if explicit_credentials:

        score += 15

        findings.append(
            "Explicit credential usage detected"
        )

    score = min(
        score,
        100
    )

    if score >= 80:
        severity = "CRITICAL"

    elif score >= 60:
        severity = "HIGH"

    elif score >= 35:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    if score < 50:
        return None

    related_event_ids = [
        event["id"]
        for event in parsed_events
    ]

    return {
        "account": account,
        "score": score,
        "severity": severity,
        "computers": computers,
        "findings": findings,
        "related_event_ids": related_event_ids,
        "first_seen": first_time.isoformat(
            sep=" "
        ),
        "last_seen": last_time.isoformat(
            sep=" "
        )
    }


def correlate_events():

    events = get_recent_windows_events()

    groups = group_events_by_account(
        events
    )

    correlations = []

    for account, account_events in groups.items():

        result = analyze_account(
            account,
            account_events
        )

        if result:

            created = create_correlation_alert(
                result
            )

            result["alert_created"] = created

            correlations.append(
                result
            )

    return correlations


if __name__ == "__main__":

    print()
    print("LateralTrace Correlation Engine")
    print("================================")
    print()

    results = correlate_events()

    if not results:

        print(
            "No correlated lateral movement detected."
        )

    else:

        for result in results:

            status = (
                "NEW ALERT"
                if result["alert_created"]
                else "EXISTING ALERT"
            )

            print(
                f"[{result['severity']}] "
                f"{result['account']} -> "
                f"{status}"
            )

            print(
                f"Score: {result['score']}"
            )

            print(
                f"Computers: "
                f"{', '.join(result['computers'])}"
            )

            print(
                "Findings:"
            )

            for finding in result["findings"]:

                print(
                    f"  - {finding}"
                )

            print(
                f"Related events: "
                f"{len(result['related_event_ids'])}"
            )

            print(
                "-" * 60
            )