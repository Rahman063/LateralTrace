from flask import (
    Blueprint,
    render_template
)

from routes.incidents import get_incident

from detection.mitre import (
    get_mitre_for_alert
)


bp = Blueprint(
    "report",
    __name__,
    url_prefix="/report"
)


@bp.get("/<int:alert_id>")
def report(alert_id):

    incident = get_incident(
        alert_id
    )

    if not incident:
        return (
            "Incident not found",
            404
        )

    mitre = get_mitre_for_alert(
        incident["alert"]
    )

    return render_template(
        "report.html",
        incident=incident,
        mitre=mitre
    )