from flask import Blueprint, render_template, request

from investigation.timeline import build_timeline


bp = Blueprint(
    "timeline",
    __name__,
    url_prefix="/timeline"
)


@bp.get("/")
def timeline():

    account = request.args.get(
        "account",
        ""
    ).strip()

    events = build_timeline(
        account=account or None
    )

    return render_template(
        "timeline.html",
        events=events,
        account=account
    )