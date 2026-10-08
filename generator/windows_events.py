from datetime import datetime, timedelta


BASE_TIME = datetime(2026, 10, 8, 9, 0, 0)


def make_event(
    event_id,
    timestamp,
    computer,
    account,
    source_ip="",
    logon_type="",
    process_name="",
    command_line="",
    target_account="",
    description=""
):
    return {
        "timestamp": timestamp.isoformat(timespec="seconds"),
        "event_id": event_id,
        "computer": computer,
        "account": account,
        "source_ip": source_ip,
        "logon_type": logon_type,
        "process_name": process_name,
        "command_line": command_line,
        "target_account": target_account,
        "description": description
    }


def generate_normal_events():
    events = []

    events.append(
        make_event(
            4624,
            BASE_TIME,
            "WS-01",
            "alice",
            "10.10.10.21",
            2,
            description="Interactive logon"
        )
    )

    events.append(
        make_event(
            4624,
            BASE_TIME + timedelta(minutes=2),
            "WS-02",
            "bob",
            "10.10.10.22",
            2,
            description="Interactive logon"
        )
    )

    events.append(
        make_event(
            4624,
            BASE_TIME + timedelta(minutes=4),
            "SERVER-01",
            "svc_backup",
            "10.10.10.50",
            3,
            description="Network logon"
        )
    )

    events.append(
        make_event(
            4634,
            BASE_TIME + timedelta(minutes=7),
            "WS-01",
            "alice",
            description="User logoff"
        )
    )

    events.append(
        make_event(
            4624,
            BASE_TIME + timedelta(minutes=10),
            "ADMIN-01",
            "administrator",
            "10.10.10.30",
            10,
            description="RemoteInteractive logon"
        )
    )

    events.append(
        make_event(
            4672,
            BASE_TIME + timedelta(minutes=10, seconds=2),
            "ADMIN-01",
            "administrator",
            description="Special privileges assigned to new logon"
        )
    )

    events.append(
        make_event(
            4688,
            BASE_TIME + timedelta(minutes=11),
            "ADMIN-01",
            "administrator",
            process_name="mmc.exe",
            command_line="mmc.exe",
            description="Process created"
        )
    )

    events.append(
        make_event(
            4625,
            BASE_TIME + timedelta(minutes=15),
            "SERVER-01",
            "bob",
            "10.10.10.22",
            3,
            description="Failed network logon"
        )
    )

    events.append(
        make_event(
            4624,
            BASE_TIME + timedelta(minutes=20),
            "WS-02",
            "bob",
            "10.10.10.22",
            2,
            description="Interactive logon"
        )
    )

    return events


def generate_lateral_movement_events():
    events = []

    attacker_ip = "10.10.10.25"

    events.append(
        make_event(
            4624,
            BASE_TIME + timedelta(minutes=32),
            "WS-01",
            "svc_backup",
            attacker_ip,
            3,
            description="Network logon"
        )
    )

    events.append(
        make_event(
            4648,
            BASE_TIME + timedelta(minutes=32, seconds=4),
            "WS-01",
            "svc_backup",
            attacker_ip,
            target_account="svc_backup",
            description="Explicit credentials used"
        )
    )

    events.append(
        make_event(
            4624,
            BASE_TIME + timedelta(minutes=34),
            "SERVER-01",
            "svc_backup",
            "10.10.10.25",
            3,
            description="Network logon"
        )
    )

    events.append(
        make_event(
            4672,
            BASE_TIME + timedelta(minutes=34, seconds=3),
            "SERVER-01",
            "svc_backup",
            description="Special privileges assigned to new logon"
        )
    )

    events.append(
        make_event(
            4688,
            BASE_TIME + timedelta(minutes=35),
            "SERVER-01",
            "svc_backup",
            process_name="cmd.exe",
            command_line="cmd.exe /c whoami",
            description="Process created"
        )
    )

    events.append(
        make_event(
            4688,
            BASE_TIME + timedelta(minutes=36),
            "SERVER-01",
            "svc_backup",
            process_name="powershell.exe",
            command_line="powershell.exe -ExecutionPolicy Bypass",
            description="Process created"
        )
    )

    events.append(
        make_event(
            4624,
            BASE_TIME + timedelta(minutes=39),
            "ADMIN-01",
            "svc_backup",
            "10.10.10.40",
            10,
            description="RemoteInteractive logon"
        )
    )

    events.append(
        make_event(
            4672,
            BASE_TIME + timedelta(minutes=39, seconds=2),
            "ADMIN-01",
            "svc_backup",
            description="Special privileges assigned to new logon"
        )
    )

    events.append(
        make_event(
            4688,
            BASE_TIME + timedelta(minutes=40),
            "ADMIN-01",
            "svc_backup",
            process_name="cmd.exe",
            command_line="cmd.exe /c net group \"Domain Admins\"",
            description="Process created"
        )
    )

    events.append(
        make_event(
            4624,
            BASE_TIME + timedelta(minutes=44),
            "DC-01",
            "svc_backup",
            "10.10.10.40",
            3,
            description="Network logon"
        )
    )

    events.append(
        make_event(
            4672,
            BASE_TIME + timedelta(minutes=44, seconds=2),
            "DC-01",
            "svc_backup",
            description="Special privileges assigned to new logon"
        )
    )

    events.append(
        make_event(
            4688,
            BASE_TIME + timedelta(minutes=45),
            "DC-01",
            "svc_backup",
            process_name="powershell.exe",
            command_line="powershell.exe -Command Get-ADUser -Filter *",
            description="Process created"
        )
    )

    return events


def generate_events():
    events = []

    events.extend(generate_normal_events())
    events.extend(generate_lateral_movement_events())

    events.sort(
        key=lambda event: event["timestamp"]
    )

    return events