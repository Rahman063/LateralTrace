from database import get_connection


def detect_lateral_movement(account=None):
    db = get_connection()

    query = """
        SELECT
            timestamp,
            event_id,
            computer,
            account,
            source_ip,
            logon_type,
            process_name,
            command_line,
            description
        FROM events
        WHERE 1 = 1
    """

    parameters = []

    if account:
        query += """
            AND account = ?
        """

        parameters.append(account)

    query += """
        ORDER BY timestamp ASC
    """

    rows = db.execute(
        query,
        parameters
    ).fetchall()

    db.close()

    events = [dict(row) for row in rows]

    findings = []

    hosts = set()
    remote_logons = []
    privileged_events = []
    process_events = []

    for event in events:

        if event["event_id"] == 4624:

            if event["logon_type"] in (3, 10):

                remote_logons.append(event)

                hosts.add(
                    event["computer"]
                )

        if event["event_id"] == 4672:

            privileged_events.append(event)

        if event["event_id"] == 4688:

            process_events.append(event)

    if len(hosts) >= 3:

        findings.append(
            {
                "severity": "HIGH",
                "title": "Multi-host authentication",
                "description": (
                    f"Account {account or 'multiple accounts'} "
                    f"authenticated to {len(hosts)} hosts "
                    "using remote logon types."
                ),
                "score": 25
            }
        )

    if privileged_events:

        findings.append(
            {
                "severity": "HIGH",
                "title": "Privileged activity detected",
                "description": (
                    f"{len(privileged_events)} privileged "
                    "authentication event(s) were observed."
                ),
                "score": 25
            }
        )

    suspicious_processes = []

    for event in process_events:

        process = (
            event["process_name"] or ""
        ).lower()

        command = (
            event["command_line"] or ""
        ).lower()

        if process in (
            "powershell.exe",
            "cmd.exe"
        ):

            suspicious_processes.append(
                event
            )

        elif "powershell" in command:

            suspicious_processes.append(
                event
            )

    if suspicious_processes:

        findings.append(
            {
                "severity": "HIGH",
                "title": "Command execution after authentication",
                "description": (
                    f"{len(suspicious_processes)} command execution "
                    "event(s) involving cmd.exe or PowerShell "
                    "were observed."
                ),
                "score": 20
            }
        )

    dc_activity = [
        event
        for event in remote_logons
        if event["computer"].upper() == "DC-01"
    ]

    if dc_activity:

        findings.append(
            {
                "severity": "CRITICAL",
                "title": "Domain Controller access",
                "description": (
                    "The investigated account authenticated "
                    "to DC-01 using a remote logon."
                ),
                "score": 30
            }
        )

    return findings