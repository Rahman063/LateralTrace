from investigation.event_search import search_events


print()
print("All events:")
print()

events = search_events()

for event in events:
    print(
        event["timestamp"],
        "|",
        event["event_id"],
        "|",
        event["computer"],
        "|",
        event["account"],
        "|",
        "Type:",
        event["logon_type"]
    )


print()
print("svc_backup events:")
print()

events = search_events(
    account="svc_backup"
)

for event in events:
    print(
        event["timestamp"],
        "|",
        event["event_id"],
        "|",
        event["computer"],
        "|",
        event["description"]
    )