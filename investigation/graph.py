from database import get_connection


def build_attack_graph(account=None):
    db = get_connection()

    if account:
        rows = db.execute(
            """
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
            WHERE account = ?
            AND event_id = 4624
            AND logon_type IN (3, 10)
            ORDER BY timestamp ASC
            """,
            (account,)
        ).fetchall()

    else:
        rows = db.execute(
            """
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
            WHERE event_id = 4624
            AND logon_type IN (3, 10)
            ORDER BY timestamp ASC
            """
        ).fetchall()

    db.close()

    nodes = {}
    edges = []

    for row in rows:

        event = dict(row)

        destination = event["computer"]
        source = event["source_ip"]

        destination_id = f"host:{destination}"

        if destination_id not in nodes:
            nodes[destination_id] = {
                "data": {
                    "id": destination_id,
                    "label": destination,
                    "type": "host"
                }
            }

        if source:

            source_id = f"source:{source}"

            if source_id not in nodes:
                nodes[source_id] = {
                    "data": {
                        "id": source_id,
                        "label": source,
                        "type": "source"
                    }
                }

            edge_id = (
                f"{source_id}:"
                f"{destination_id}:"
                f"{event['timestamp']}"
            )

            edges.append(
                {
                    "data": {
                        "id": edge_id,
                        "source": source_id,
                        "target": destination_id,
                        "account": event["account"],
                        "timestamp": event["timestamp"],
                        "logon_type": event["logon_type"]
                    }
                }
            )

    return {
        "nodes": list(nodes.values()),
        "edges": edges
    }