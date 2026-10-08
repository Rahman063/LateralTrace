from flask import Flask
from routes.mitre import bp as mitre_bp 
from database import initialize_database, load_events
from routes.alerts import bp as alerts_bp
from routes.dashboard import bp as dashboard_bp
from routes.events import bp as events_bp
from routes.accounts import bp as accounts_bp
from routes.hosts import bp as hosts_bp
from routes.timeline import bp as timeline_bp
from routes.graph import bp as graph_bp
from routes.incidents import bp as incidents_bp
from routes.report import bp as report_bp

app = Flask(__name__)


initialize_database()
load_events()


app.register_blueprint(dashboard_bp)
app.register_blueprint(events_bp)
app.register_blueprint(accounts_bp)
app.register_blueprint(hosts_bp)
app.register_blueprint(timeline_bp)
app.register_blueprint(graph_bp)
app.register_blueprint(incidents_bp)
app.register_blueprint(alerts_bp)
app.register_blueprint(mitre_bp)
app.register_blueprint(report_bp)

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )