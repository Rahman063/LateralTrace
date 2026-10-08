from flask import Blueprint, render_template

from database import get_connection
from detection.alerts import get_alerts


bp = Blueprint(
    "dashboard",
    __name__
)


def get_dashboard_stats():

    db = get_connection()

    total_events = db.execute(
        """
        SELECT COUNT(*)
        FROM events
        """
    ).fetchone()[0]

    windows_events = db.execute(
        """
        SELECT COUNT(*)
        FROM events
        WHERE source = 'windows'
        """
    ).fetchone()[0]

    synthetic_events = db.execute(
        """
        SELECT COUNT(*)
        FROM events
        WHERE source = 'synthetic'
        """
    ).fetchone()[0]

    new_alerts = db.execute(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE status = 'NEW'
        """
    ).fetchone()[0]

    high_alerts = db.execute(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'HIGH'
        AND status != 'RESOLVED'
        """
    ).fetchone()[0]

    critical_alerts = db.execute(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'CRITICAL'
        AND status != 'RESOLVED'
        """
    ).fetchone()[0]

    medium_alerts = db.execute(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'MEDIUM'
        AND status != 'RESOLVED'
        """
    ).fetchone()[0]

    low_alerts = db.execute(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'LOW'
        AND status != 'RESOLVED'
        """
    ).fetchone()[0]

    db.close()

    return {
        "total_events": total_events,
        "windows_events": windows_events,
        "synthetic_events": synthetic_events,
        "new_alerts": new_alerts,
        "high_alerts": high_alerts,
        "critical_alerts": critical_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts
    }


@bp.get("/")
def dashboard():

    stats = get_dashboard_stats()

    recent_alerts = get_alerts(
        limit=10
    )

    return render_template(
        "dashboard.html",
        stats=stats,
        recent_alerts=recent_alerts
    )