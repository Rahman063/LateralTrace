import json

from database import get_connection


def initialize_alerts():

    db = get_connection()

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            timestamp TEXT NOT NULL,
            detection_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            account TEXT,
            computer TEXT,
            source_ip TEXT,
            message TEXT NOT NULL,
            score INTEGER DEFAULT 0,
            status TEXT DEFAULT 'NEW',
            correlation_key TEXT,
            related_event_count INTEGER DEFAULT 0,
            details TEXT
        )
        """
    )

    columns = db.execute(
        """
        PRAGMA table_info(alerts)
        """
    ).fetchall()

    column_names = {
        column["name"]
        for column in columns
    }

    if "correlation_key" not in column_names:

        db.execute(
            """
            ALTER TABLE alerts
            ADD COLUMN correlation_key TEXT
            """
        )

    if "related_event_count" not in column_names:

        db.execute(
            """
            ALTER TABLE alerts
            ADD COLUMN related_event_count INTEGER DEFAULT 0
            """
        )

    if "details" not in column_names:

        db.execute(
            """
            ALTER TABLE alerts
            ADD COLUMN details TEXT
            """
        )

    db.commit()
    db.close()


def alert_exists(
    event_id,
    detection_type
):

    initialize_alerts()

    db = get_connection()

    result = db.execute(
        """
        SELECT id
        FROM alerts
        WHERE event_id = ?
        AND detection_type = ?
        """,
        (
            event_id,
            detection_type
        )
    ).fetchone()

    db.close()

    return result is not None


def create_alert(
    event,
    finding
):

    initialize_alerts()

    if alert_exists(
        event["id"],
        finding["type"]
    ):
        return False

    db = get_connection()

    db.execute(
        """
        INSERT INTO alerts (
            event_id,
            timestamp,
            detection_type,
            severity,
            account,
            computer,
            source_ip,
            message,
            score,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event["id"],
            event["timestamp"],
            finding["type"],
            finding["severity"],
            event.get("account", ""),
            event.get("computer", ""),
            event.get("source_ip", ""),
            finding["message"],
            finding["score"],
            "NEW"
        )
    )

    db.commit()
    db.close()

    return True


def create_correlation_alert(
    correlation
):

    initialize_alerts()

    account = correlation["account"]

    computers = correlation["computers"]

    correlation_key = (
        f"LATERAL_MOVEMENT:"
        f"{account}:"
        f"{correlation['first_seen']}"
    )

    db = get_connection()

    existing = db.execute(
        """
        SELECT id
        FROM alerts
        WHERE correlation_key = ?
        """,
        (correlation_key,)
    ).fetchone()

    if existing:

        db.close()

        return False

    message = (
        f"Potential lateral movement detected for "
        f"{account}. "
        f"Activity observed across "
        f"{len(computers)} computers."
    )

    details = json.dumps(
        {
            "computers": computers,
            "findings": correlation["findings"],
            "related_event_ids": (
                correlation["related_event_ids"]
            ),
            "first_seen": correlation["first_seen"],
            "last_seen": correlation["last_seen"]
        }
    )

    db.execute(
        """
        INSERT INTO alerts (
            event_id,
            timestamp,
            detection_type,
            severity,
            account,
            computer,
            source_ip,
            message,
            score,
            status,
            correlation_key,
            related_event_count,
            details
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            correlation["related_event_ids"][-1]
            if correlation["related_event_ids"]
            else None,
            correlation["last_seen"],
            "LATERAL_MOVEMENT_CORRELATION",
            correlation["severity"],
            account,
            ", ".join(computers),
            "",
            message,
            correlation["score"],
            "NEW",
            correlation_key,
            len(
                correlation["related_event_ids"]
            ),
            details
        )
    )

    db.commit()
    db.close()

    return True


def get_alerts(
    status=None,
    limit=100
):

    initialize_alerts()

    db = get_connection()

    if status:

        rows = db.execute(
            """
            SELECT *
            FROM alerts
            WHERE status = ?
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (
                status,
                limit
            )
        ).fetchall()

    else:

        rows = db.execute(
            """
            SELECT *
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,)
        ).fetchall()

    db.close()

    return [
        dict(row)
        for row in rows
    ]


def update_alert_status(
    alert_id,
    status
):

    allowed_statuses = {
        "NEW",
        "INVESTIGATING",
        "RESOLVED",
        "FALSE_POSITIVE"
    }

    if status not in allowed_statuses:

        raise ValueError(
            f"Invalid alert status: {status}"
        )

    db = get_connection()

    db.execute(
        """
        UPDATE alerts
        SET status = ?
        WHERE id = ?
        """,
        (
            status,
            alert_id
        )
    )

    db.commit()
    db.close()