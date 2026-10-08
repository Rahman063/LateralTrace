from database import get_connection


def get_account_summary(account):
    db = get_connection()

    summary = db.execute(
        """
        SELECT
            MIN(timestamp) AS first_seen,
            MAX(timestamp) AS last_seen,
            COUNT(*) AS total_events,
            COUNT(
                DISTINCT computer
            ) AS host_count,
            COUNT(
                DISTINCT source_ip
            ) AS source_count
        FROM events
        WHERE account = ?
        """,
        (account,)
    ).fetchone()

    logons = db.execute(
        """
        SELECT
            COUNT(*) AS count
        FROM events
        WHERE account = ?
        AND event_id = 4624
        """,
        (account,)
    ).fetchone()

    privileged = db.execute(
        """
        SELECT
            COUNT(*) AS count
        FROM events
        WHERE account = ?
        AND event_id = 4672
        """,
        (account,)
    ).fetchone()

    db.close()

    if not summary:
        return None

    return {
        "account": account,
        "first_seen": summary["first_seen"],
        "last_seen": summary["last_seen"],
        "total_events": summary["total_events"],
        "host_count": summary["host_count"],
        "source_count": summary["source_count"],
        "successful_logons": logons["count"],
        "privileged_events": privileged["count"]
    }


def get_account_events(account):
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
        WHERE account = ?
        ORDER BY timestamp ASC
        """,
        (account,)
    ).fetchall()

    db.close()

    return [dict(row) for row in rows]


def get_account_hosts(account):
    db = get_connection()

    rows = db.execute(
        """
        SELECT
            computer,
            COUNT(*) AS event_count,
            MIN(timestamp) AS first_seen,
            MAX(timestamp) AS last_seen
        FROM events
        WHERE account = ?
        GROUP BY computer
        ORDER BY first_seen ASC
        """,
        (account,)
    ).fetchall()

    db.close()

    return [dict(row) for row in rows]


def get_account_sources(account):
    db = get_connection()

    rows = db.execute(
        """
        SELECT
            source_ip,
            COUNT(*) AS event_count
        FROM events
        WHERE account = ?
        AND source_ip != ''
        GROUP BY source_ip
        ORDER BY event_count DESC
        """,
        (account,)
    ).fetchall()

    db.close()

    return [dict(row) for row in rows]