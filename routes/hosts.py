from flask import Blueprint, render_template, abort

from investigation.hosts import (
    get_all_hosts,
    get_host_summary,
    get_host_events,
    get_incoming_authentication,
    get_privileged_activity
)


bp = Blueprint(
    "hosts",
    __name__,
    url_prefix="/hosts"
)


@bp.get("/")
def hosts():

    hosts = get_all_hosts()

    return render_template(
        "hosts.html",
        hosts=hosts
    )


@bp.get("/<computer>")
def host(computer):

    summary = get_host_summary(computer)

    if not summary:
        abort(404)

    events = get_host_events(computer)

    incoming = get_incoming_authentication(
        computer
    )

    privileged = get_privileged_activity(
        computer
    )

    return render_template(
        "host.html",
        summary=summary,
        events=events,
        incoming=incoming,
        privileged=privileged
    )