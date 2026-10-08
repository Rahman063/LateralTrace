from flask import Blueprint, render_template, request

from investigation.event_search import search_events


bp = Blueprint(
    "events",
    __name__,
    url_prefix="/events"
)


@bp.get("/")
def events():

    event_id = request.args.get(
        "event_id",
        ""
    ).strip()

    account = request.args.get(
        "account",
        ""
    ).strip()

    computer = request.args.get(
        "computer",
        ""
    ).strip()

    source_ip = request.args.get(
        "source_ip",
        ""
    ).strip()

    logon_type = request.args.get(
        "logon_type",
        ""
    ).strip()

    source = request.args.get(
        "source",
        ""
    ).strip()

    results = search_events(
        event_id=event_id or None,
        account=account or None,
        computer=computer or None,
        source_ip=source_ip or None,
        logon_type=logon_type or None,
        source=source or None,
        limit=200
    )

    filters = {
        "event_id": event_id,
        "account": account,
        "computer": computer,
        "source_ip": source_ip,
        "logon_type": logon_type,
        "source": source
    }

    return render_template(
        "events.html",
        events=results,
        filters=filters
    )