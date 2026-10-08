from flask import (
    Blueprint,
    render_template,
    request
)

from database import get_connection

from detection.alerts import (
    get_alerts,
    update_alert_status
)

from detection.mitre import (
    get_mitre_for_alert
)


bp = Blueprint(
    "incidents",
    __name__,
    url_prefix="/incidents"
)


def get_incident(alert_id):

    db = get_connection()

    alert = db.execute(
        """
        SELECT *
        FROM alerts
        WHERE id = ?
        """,
        (alert_id,)
    ).fetchone()

    if not alert:

        db.close()

        return None

    alert = dict(alert)

    events = []

    details = alert.get(
        "details"
    )

    if details:

        import json

        try:

            details_data = json.loads(
                details
            )

            event_ids = details_data.get(
                "related_event_ids",
                []
            )

            if event_ids:

                placeholders = ",".join(
                    "?" for _ in event_ids
                )

                rows = db.execute(
                    f"""
                    SELECT *
                    FROM events
                    WHERE id IN ({placeholders})
                    ORDER BY timestamp ASC
                    """,
                    event_ids
                ).fetchall()

                events = [
                    dict(row)
                    for row in rows
                ]

        except (
            ValueError,
            TypeError,
            json.JSONDecodeError
        ):

            events = []

    db.close()

    return {
        "alert": alert,
        "events": events
    }


@bp.get("/")
def incidents():

    alerts = get_alerts(
        limit=200
    )

    return render_template(
        "incidents.html",
        alerts=alerts
    )


@bp.get("/<int:alert_id>")
def incident(alert_id):

    incident_data = get_incident(
        alert_id
    )

    if not incident_data:

        return (
            "Incident not found",
            404
        )

    mitre = get_mitre_for_alert(
        incident_data["alert"]
    )

    return render_template(
        "incident.html",
        incident=incident_data,
        mitre=mitre
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

    return render_template(
        "incident.html",
        incident=get_incident(
            alert_id
        ),
        mitre=get_mitre_for_alert(
            get_incident(
                alert_id
            )["alert"]
        )
    )