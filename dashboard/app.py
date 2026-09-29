"""
NetGuardian Flask Dashboard Application
Provides the web-based monitoring interface: live device list, trust-marking toggle,
per-device anomaly scores, traffic metadata summary, and alert history.
"""

from pathlib import Path
from flask import Flask, jsonify, render_template, request

import config
from database.db import Database, db as default_db

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app(database: Database = None) -> Flask:
    """Application factory for the NetGuardian Flask dashboard."""
    app = Flask(
        __name__,
        template_folder=str(TEMPLATE_DIR),
        static_folder=str(STATIC_DIR),
    )
    app.config["SECRET_KEY"] = config.SECRET_KEY
    db_instance = database or default_db

    @app.route("/")
    def index():
        """Render the main dashboard overview page."""
        summary = db_instance.get_dashboard_summary()
        devices = db_instance.get_all_devices()
        anomalies = db_instance.get_anomalies(limit=20)
        recent_traffic = db_instance.get_recent_traffic(limit=30)
        recent_alerts = db_instance.get_recent_alerts(limit=20)

        return render_template(
            "index.html",
            summary=summary,
            devices=devices,
            anomalies=anomalies,
            recent_traffic=recent_traffic,
            recent_alerts=recent_alerts,
        )

    # -------------------------------------------------------------
    # REST API Endpoints for interactive JS interactions
    # -------------------------------------------------------------

    @app.route("/api/summary", methods=["GET"])
    def api_summary():
        """Return real-time summary statistics for live polling."""
        return jsonify(db_instance.get_dashboard_summary())

    @app.route("/api/devices", methods=["GET"])
    def api_devices():
        """Return list of all registered network devices."""
        return jsonify(db_instance.get_all_devices())

    @app.route("/api/devices/<path:mac>/trust", methods=["POST"])
    def api_toggle_trust(mac: str):
        """Toggle device trusted state."""
        data = request.get_json(silent=True) or {}
        is_trusted = data.get("is_trusted")

        if is_trusted is None:
            # If not explicitly specified, invert current state
            dev = db_instance.get_device(mac)
            if not dev:
                return jsonify({"error": "Device not found"}), 404
            is_trusted = not bool(dev.get("is_trusted", 0))

        success = db_instance.set_device_trust(mac, bool(is_trusted))
        return jsonify({"success": success, "mac": mac, "is_trusted": int(bool(is_trusted))})

    @app.route("/api/devices/<path:mac>/active-hours", methods=["POST"])
    def api_update_active_hours(mac: str):
        """Update active normal hours schedule for a device."""
        data = request.get_json(silent=True) or {}
        start = int(data.get("start", 0))
        end = int(data.get("end", 23))

        if not (0 <= start <= 23 and 0 <= end <= 23):
            return jsonify({"error": "Hours must be between 0 and 23"}), 400

        success = db_instance.update_device_active_hours(mac, start, end)
        return jsonify({"success": success, "start": start, "end": end})

    @app.route("/api/traffic", methods=["GET"])
    def api_traffic():
        """Return recent packet metadata records."""
        limit = request.args.get("limit", 50, type=int)
        mac = request.args.get("mac")
        return jsonify(db_instance.get_recent_traffic(limit=limit, mac_address=mac))

    @app.route("/api/anomalies", methods=["GET"])
    def api_anomalies():
        """Return security anomalies."""
        unresolved_only = request.args.get("unresolved", "false").lower() == "true"
        return jsonify(db_instance.get_anomalies(unresolved_only=unresolved_only))

    @app.route("/api/anomalies/<int:anomaly_id>/resolve", methods=["POST"])
    def api_resolve_anomaly(anomaly_id: int):
        """Mark an anomaly as resolved."""
        success = db_instance.resolve_anomaly(anomaly_id)
        return jsonify({"success": success, "anomaly_id": anomaly_id})

    @app.route("/api/scan", methods=["POST"])
    def api_trigger_scan():
        """Trigger an on-demand network scan pass."""
        try:
            from scanner.scanner_service import ScannerService
            scanner = ScannerService(database=db_instance)
            devices = scanner.scan_once()
            return jsonify({"success": True, "discovered_count": len(devices)})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    return app


# Global default app instance
app = create_app()

if __name__ == "__main__":
    app.run(
        host=config.DASHBOARD_HOST,
        port=config.DASHBOARD_PORT,
        debug=config.DASHBOARD_DEBUG,
    )
