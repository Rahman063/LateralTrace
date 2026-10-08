from database import get_connection
from detection.alerts import initialize_alerts


initialize_alerts()

db = get_connection()

db.execute(
    "DELETE FROM alerts"
)

db.commit()
db.close()

print()
print("All alerts cleared.")
print("Event telemetry was preserved.")
print()