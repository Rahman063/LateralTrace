from database import get_connection


def get_all_hosts():
    db = get_connection()

    rows = db.execute(
        """
        SELECT
            computer,
            COUNT(*) AS event_count,
            COUNT(
                DISTINCT account
            ) AS account_count,
            COUNT(
                DISTINCT source_ip
            ) AS source_count,
            MIN(timestamp) AS first_seen,
            MAX(timestamp) AS last_seen
        FROM events
        GROUP BY computer
        ORDER BY computer ASC
        """
    ).fetchall()

    db.close()

    return [dict(row) for row in rows]


def get_host_summary(computer):
    db = get_connection()

    summary = db.execute(
        """
        SELECT
            computer,
            COUNT(*) AS total_events,
            COUNT(
                DISTINCT account
            ) AS account_count,
            COUNT(
                DISTINCT source_ip
            ) AS source_count,
            MIN(timestamp) AS first_seen,
            MAX(timestamp) AS last_seen
        FROM events
        WHERE computer = ?
        GROUP BY computer
        """,
        (computer,)
    ).fetchone()

    db.close()

    if not summary:
        return None

    return dict(summary)


def get_host_events(computer):
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
            description
        FROM events
        WHERE computer = ?
        ORDER BY timestamp ASC
        """,
        (computer,)
    ).fetchall()

    db.close()

    return [dict(row) for row in rows]


def get_incoming_authentication(computer):
    db = get_connection()

    rows = db.execute(
        """
        SELECT
            timestamp,
            event_id,
            computer,
            account,
            source_ip,
            logon_type,
            description
        FROM events
        WHERE computer = ?
        AND event_id = 4624
        ORDER BY timestamp ASC
        """,
        (computer,)
    ).fetchall()

    db.close()

    return [dict(row) for row in rows]


def get_privileged_activity(computer):
    db = get_connection()

    rows = db.execute(
        """
        SELECT
            timestamp,
            event_id,
            account,
            process_name,
            command_line,
            description
        FROM events
        WHERE computer = ?
        AND event_id IN (4672, 4688)
        ORDER BY timestamp ASC
        """,
        (computer,)
    ).fetchall()

    db.close()

    return [dict(row) for row in rows]