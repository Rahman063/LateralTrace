import json
import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

DATABASE = DATA_DIR / "lateraltrace.db"
EVENT_FILE = DATA_DIR / "events.json"


def initialize_alert_table(db):
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
def get_connection():
    DATA_DIR.mkdir(
        exist_ok=True
    )

    db = sqlite3.connect(
        DATABASE,
        check_same_thread=False
    )

    db.row_factory = sqlite3.Row

    return db


def initialize_database():
    db = get_connection()

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_id INTEGER NOT NULL,
            computer TEXT NOT NULL,
            account TEXT NOT NULL,
            source_ip TEXT,
            logon_type INTEGER,
            process_name TEXT,
            command_line TEXT,
            target_account TEXT,
            description TEXT,
            record_id INTEGER,
            source TEXT
        )
        """
    )

    columns = db.execute(
        """
        PRAGMA table_info(events)
        """
    ).fetchall()

    column_names = {
        column["name"]
        for column in columns
    }

    if "record_id" not in column_names:

        db.execute(
            """
            ALTER TABLE events
            ADD COLUMN record_id INTEGER
            """
        )

    if "source" not in column_names:

        db.execute(
            """
            ALTER TABLE events
            ADD COLUMN source TEXT
            """
        )
    initialize_alert_table(db)
    db.commit()
    db.close()


def load_events():
    if not EVENT_FILE.exists():

        raise FileNotFoundError(
            "events.json was not found. "
            "Run generator\\incident_generator.py first."
        )

    with open(
        EVENT_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        events = json.load(file)

    db = get_connection()

    db.execute(
        """
        DELETE FROM events
        WHERE source IS NULL
        OR source = 'synthetic'
        """
    )

    for event in events:

        db.execute(
            """
            INSERT INTO events (
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
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["timestamp"],
                event["event_id"],
                event["computer"],
                event["account"],
                event["source_ip"],
                event["logon_type"],
                event["process_name"],
                event["command_line"],
                event["target_account"],
                event["description"],
                None,
                "synthetic"
            )
        )

    db.commit()
    db.close()


def insert_windows_event(event):

    db = get_connection()

    existing = db.execute(
        """
        SELECT id
        FROM events
        WHERE computer = ?
        AND record_id = ?
        AND source = 'windows'
        """,
        (
            event["computer"],
            event["record_id"]
        )
    ).fetchone()

    if existing:

        db.close()

        return None

    cursor = db.execute(
        """
        INSERT INTO events (
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
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event["timestamp"],
            event["event_id"],
            event["computer"],
            event.get("account", ""),
            event.get("source_ip", ""),
            event.get("logon_type"),
            event.get("process_name", ""),
            event.get("command_line", ""),
            event.get("target_account", ""),
            event.get("description", ""),
            event["record_id"],
            "windows"
        )
    )

    db.commit()

    database_id = cursor.lastrowid

    db.close()

    return database_id



def reset_database():
    db = get_connection()

    db.execute(
        "DELETE FROM events"
    )

    db.commit()
    db.close()


if __name__ == "__main__":

    initialize_database()

    load_events()

    print()
    print("LateralTrace database initialized.")
    print(f"Database: {DATABASE}")
    print()