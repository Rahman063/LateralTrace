import win32evtlog

from database import (
    initialize_database,
    insert_windows_event
)


LOG_NAME = "Security"


SUPPORTED_EVENTS = {
    4624,
    4625,
    4634,
    4648,
    4672,
    4688
}


def read_security_events(max_events=100):

    handle = win32evtlog.OpenEventLog(
        "localhost",
        LOG_NAME
    )

    flags = (
        win32evtlog.EVENTLOG_BACKWARDS_READ
        | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    )

    events = []

    try:

        while len(events) < max_events:

            records = win32evtlog.ReadEventLog(
                handle,
                flags,
                0
            )

            if not records:
                break

            for record in records:

                event_id = (
                    record.EventID & 0xFFFF
                )

                if event_id not in SUPPORTED_EVENTS:
                    continue

                events.append(
                    {
                        "event_id": event_id,
                        "timestamp": (
                            record.TimeGenerated.Format()
                        ),
                        "computer": record.ComputerName,
                        "record_id": record.RecordNumber,
                        "source": record.SourceName,
                        "strings": (
                            record.StringInserts or []
                        )
                    }
                )

                if len(events) >= max_events:
                    break

    finally:

        win32evtlog.CloseEventLog(
            handle
        )

    return events


def get_string(strings, index):

    if index >= len(strings):
        return ""

    value = strings[index]

    if value is None:
        return ""

    return str(value)


def _to_int(value):

    try:

        return int(value)

    except (
        ValueError,
        TypeError
    ):

        return None


def parse_4624(strings):

    return {
        "account": get_string(
            strings,
            5
        ),
        "source_ip": get_string(
            strings,
            18
        ),
        "logon_type": _to_int(
            get_string(
                strings,
                8
            )
        ),
        "description": "Successful logon"
    }


def parse_4625(strings):

    return {
        "account": get_string(
            strings,
            5
        ),
        "source_ip": get_string(
            strings,
            19
        ),
        "logon_type": _to_int(
            get_string(
                strings,
                8
            )
        ),
        "description": "Failed logon"
    }


def parse_4634(strings):

    return {
        "account": get_string(
            strings,
            1
        ),
        "description": "User logoff"
    }


def parse_4648(strings):

    return {
        "account": get_string(
            strings,
            1
        ),
        "target_account": get_string(
            strings,
            5
        ),
        "source_ip": get_string(
            strings,
            13
        ),
        "description": "Explicit credentials used"
    }


def parse_4672(strings):

    return {
        "account": get_string(
            strings,
            1
        ),
        "description": (
            "Special privileges assigned "
            "to new logon"
        )
    }


def parse_4688(strings):

    return {
        "account": get_string(
            strings,
            1
        ),
        "process_name": get_string(
            strings,
            5
        ),
        "command_line": get_string(
            strings,
            8
        ),
        "target_account": get_string(
            strings,
            10
        ),
        "description": "Process created"
    }


def normalize_event(event):

    strings = event["strings"]

    parsed = {
        "account": "",
        "source_ip": "",
        "logon_type": None,
        "process_name": "",
        "command_line": "",
        "target_account": "",
        "description": ""
    }

    event_id = event["event_id"]

    if event_id == 4624:

        parsed.update(
            parse_4624(
                strings
            )
        )

    elif event_id == 4625:

        parsed.update(
            parse_4625(
                strings
            )
        )

    elif event_id == 4634:

        parsed.update(
            parse_4634(
                strings
            )
        )

    elif event_id == 4648:

        parsed.update(
            parse_4648(
                strings
            )
        )

    elif event_id == 4672:

        parsed.update(
            parse_4672(
                strings
            )
        )

    elif event_id == 4688:

        parsed.update(
            parse_4688(
                strings
            )
        )

    return {
        "timestamp": event["timestamp"],
        "event_id": event_id,
        "computer": event["computer"],
        "account": parsed["account"],
        "source_ip": parsed["source_ip"],
        "logon_type": parsed["logon_type"],
        "process_name": parsed["process_name"],
        "command_line": parsed["command_line"],
        "target_account": parsed["target_account"],
        "description": parsed["description"],
        "record_id": event["record_id"]
    }


def collect_events(max_events=100):

    initialize_database()

    raw_events = read_security_events(
        max_events=max_events
    )

    inserted_events = []

    for raw_event in raw_events:

        event = normalize_event(
            raw_event
        )

        database_id = insert_windows_event(
            event
        )

        if database_id:

            event["id"] = database_id

            inserted_events.append(
                event
            )

    return (
        len(raw_events),
        len(inserted_events),
        inserted_events
    )


if __name__ == "__main__":

    print()
    print(
        "LateralTrace Windows Event Collector"
    )
    print(
        "------------------------------------"
    )
    print()

    total, inserted, events = collect_events(
        max_events=100
    )

    print(
        f"Events read: {total}"
    )

    print(
        f"New events inserted: {inserted}"
    )

    print()

    for event in events:

        print(
            f"New event: "
            f"{event['event_id']} | "
            f"{event['account'] or '-'} | "
            f"{event['computer']} | "
            f"DB ID: {event['id']}"
        )

    print()