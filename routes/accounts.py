from flask import Blueprint, render_template, abort

from database import get_connection

from investigation.accounts import (
    get_account_summary,
    get_account_events,
    get_account_hosts,
    get_account_sources
)


bp = Blueprint(
    "accounts",
    __name__,
    url_prefix="/accounts"
)


@bp.get("/")
def accounts():

    db = get_connection()

    rows = db.execute(
        """
        SELECT
            account,
            COUNT(*) AS event_count,
            COUNT(
                DISTINCT computer
            ) AS host_count,
            COUNT(
                DISTINCT source_ip
            ) AS source_count,
            MIN(timestamp) AS first_seen,
            MAX(timestamp) AS last_seen
        FROM events
        GROUP BY account
        ORDER BY account ASC
        """
    ).fetchall()

    db.close()

    accounts = [dict(row) for row in rows]

    return render_template(
        "accounts.html",
        accounts=accounts
    )


@bp.get("/<account>")
def account(account):

    summary = get_account_summary(account)

    if not summary:
        abort(404)

    events = get_account_events(account)
    hosts = get_account_hosts(account)
    sources = get_account_sources(account)

    return render_template(
        "account.html",
        summary=summary,
        events=events,
        hosts=hosts,
        sources=sources
    )