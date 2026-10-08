from database import get_connection


def search_events(
    event_id=None,
    account=None,
    computer=None,
    source_ip=None,
    logon_type=None,
    source=None,
    limit=200
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
            description,
            record_id,
            source
        FROM events
        WHERE 1 = 1
    """

    parameters = []

    if event_id:
        query += " AND event_id = ?"
        parameters.append(event_id)

    if account:
        query += " AND account = ?"
        parameters.append(account)

    if computer:
        query += " AND computer = ?"
        parameters.append(computer)

    if source_ip:
        query += " AND source_ip = ?"
        parameters.append(source_ip)

    if logon_type:
        query += " AND logon_type = ?"
        parameters.append(logon_type)

    if source:
        query += " AND source = ?"
        parameters.append(source)

    query += """
        ORDER BY timestamp DESC
        LIMIT ?
    """

    parameters.append(limit)

    rows = db.execute(
        query,
        parameters
    ).fetchall()

    db.close()

    return [dict(row) for row in rows]