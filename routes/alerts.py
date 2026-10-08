from flask import Blueprint, render_template, request, redirect, url_for

from detection.alerts import (
    get_alerts,
    update_alert_status
)


bp = Blueprint(
    "alerts",
    __name__,
    url_prefix="/alerts"
)


@bp.get("/")
def alerts():

    status = request.args.get(
        "status",
        ""
    ).strip()

    results = get_alerts(
        status=status or None,
        limit=200
    )

    return render_template(
        "alerts.html",
        alerts=results,
        status=status
    )


@bp.post("/<int:alert_id>/status")
def change_status(alert_id):

    status = request.form.get(
        "status",
        ""
    ).strip()

    if status:

        update_alert_status(
            alert_id,
            status
        )

    return redirect(
        url_for(
            "alerts.alerts"
        )
    )