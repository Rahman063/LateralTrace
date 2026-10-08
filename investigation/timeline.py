from database import get_connection


def get_timeline(
    account=None,
    suspicious_only=False
):
    db = get_connection()

    query = """
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

    if suspicious_only:
        query += """
            AND (
                event_id IN (4648, 4672)
                OR (
                    event_id = 4624
                    AND logon_type IN (3, 10)
                )
                OR event_id = 4688
            )
        """

    query += """
        ORDER BY timestamp ASC
    """

    rows = db.execute(
        query,
        parameters
    ).fetchall()

    db.close()

    return [dict(row) for row in rows]


def classify_event(event):
    event_id = event["event_id"]

    if event_id == 4624:
        if event["logon_type"] == 3:
            return "Network Logon"

        if event["logon_type"] == 10:
            return "Remote Interactive Logon"

        return "Successful Logon"

    if event_id == 4625:
        return "Failed Logon"

    if event_id == 4648:
        return "Explicit Credentials"

    if event_id == 4672:
        return "Privileged Logon"

    if event_id == 4688:
        return "Process Creation"

    if event_id == 4634:
        return "Logoff"

    return "Other"


def build_timeline(account=None):
    events = get_timeline(
        account=account,
        suspicious_only=True
    )

    timeline = []

    for event in events:

        event["category"] = classify_event(
            event
        )

        timeline.append(event)

    return timeline