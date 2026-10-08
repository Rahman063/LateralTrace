from database import get_connection


def get_live_events(limit=30):

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
            record_id,
            source
        FROM events
        WHERE source = 'windows'
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    db.close()

    return [dict(row) for row in rows]


if __name__ == "__main__":

    events = get_live_events()

    print()
    print("Recent Windows Events")
    print("=====================")
    print()

    for event in events:

        print(
            f"ID: {event['id']} | "
            f"Event: {event['event_id']} | "
            f"Time: {event['timestamp']}"
        )

        print(
            f"Computer: {event['computer']}"
        )

        print(
            f"Account: {event['account'] or '-'}"
        )

        print(
            f"Source IP: {event['source_ip'] or '-'}"
        )

        print(
            f"Logon Type: "
            f"{event['logon_type'] or '-'}"
        )

        print(
            f"Process: "
            f"{event['process_name'] or '-'}"
        )

        print(
            f"Command: "
            f"{event['command_line'] or '-'}"
        )

        print(
            f"Description: {event['description']}"
        )

        print(
            f"Record ID: {event['record_id']}"
        )

        print(
            f"Source: {event['source']}"
        )

        print(
            "-" * 70
        )