"""
NetGuardian Main Entry Point
Orchestrates network discovery, packet metadata capture, device identification,
hybrid rule-based + ML anomaly detection, alerting, and the Flask web dashboard.

Usage:
    python main.py                  # Runs complete system (scanner, traffic, detection, dashboard)
    python main.py --dashboard-only # Starts only the Flask dashboard
    python main.py --scan-once      # Executes a single scan pass and exits
"""

import argparse
import logging
import signal
import sys
import threading
import time

import config
from alerts.alert_service import alert_service
from dashboard.app import create_app
from database.db import db
from detection.detection_manager import detection_manager_service
from identification.device_identifier import device_identifier_service
from scanner.scanner_service import ScannerService
from traffic.sniffer import TrafficSniffer

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(config.DATA_DIR / "netguardian.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("NetGuardian")


def run_full_system():
    """Starts all NetGuardian modules concurrently."""
    logger.info("==================================================")
    logger.info("   🛡️ Starting NetGuardian Network Sentinel")
    logger.info("==================================================")

    # 1. Start Alert Service
    alert_service.start()
    logger.info("[1/5] Alerting service initialized.")

    # 2. Wire anomaly dispatch callback to alert service
    detection_manager_service.on_anomaly_confirmed = alert_service.trigger_alert
    logger.info("[2/5] Detection engine wired to alert dispatcher.")

    # 3. Start Device Identifier worker thread
    device_identifier_service.start()
    logger.info("[3/5] Device identifier service running.")

    # 4. Callback on device discovery from scanner
    def on_device_discovered(device_record, is_new):
        mac = device_record.get("mac_address")
        ip = device_record.get("ip_address")
        # Enqueue for vendor + hostname resolution
        if mac and ip:
            device_identifier_service.enqueue_identification(mac, ip)
        # Evaluate Rule A (unrecognized device)
        detection_manager_service.process_device_discovery(device_record, is_new)

    # 5. Start Scanner Service
    scanner = ScannerService(
        database=db,
        scan_interval=config.SCAN_INTERVAL_SECONDS,
        interface=config.NETWORK_INTERFACE,
        on_device_discovered=on_device_discovered,
    )
    scanner.start()
    logger.info("[4/5] Background ARP scanner active.")

    # 6. Start Traffic Sniffer
    def on_packet_captured(packet_meta):
        # Evaluate Rule B (off-hours schedule checks)
        detection_manager_service.process_packet_traffic(packet_meta)

    sniffer = TrafficSniffer(
        database=db,
        interface=config.NETWORK_INTERFACE,
        on_packet_captured=on_packet_captured,
    )
    sniffer.start()
    logger.info("[5/5] Passive packet metadata sniffer active.")

    # Graceful shutdown handler
    def shutdown_signal(sig, frame):
        logger.info("\nShutting down NetGuardian services gracefully...")
        sniffer.stop()
        scanner.stop()
        device_identifier_service.stop()
        alert_service.stop()
        db.close()
        logger.info("NetGuardian shutdown complete.")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_signal)
    signal.signal(signal.SIGTERM, shutdown_signal)

    # Start Flask Web Dashboard on main thread
    logger.info(
        "🌐 NetGuardian Dashboard listening at http://%s:%d",
        config.DASHBOARD_HOST,
        config.DASHBOARD_PORT,
    )
    app = create_app(db)
    app.run(
        host=config.DASHBOARD_HOST,
        port=config.DASHBOARD_PORT,
        debug=False,
        use_reloader=False,
    )


def main():
    parser = argparse.ArgumentParser(description="NetGuardian Autonomous Network Monitor")
    parser.add_argument(
        "--dashboard-only", action="store_true", help="Launch web dashboard only"
    )
    parser.add_argument(
        "--scan-once", action="store_true", help="Perform single scan pass and exit"
    )
    args = parser.parse_args()

    if args.dashboard_only:
        logger.info(
            "Starting Dashboard only at http://%s:%d",
            config.DASHBOARD_HOST,
            config.DASHBOARD_PORT,
        )
        app = create_app(db)
        app.run(
            host=config.DASHBOARD_HOST,
            port=config.DASHBOARD_PORT,
            debug=config.DASHBOARD_DEBUG,
        )
    elif args.scan_once:
        logger.info("Executing single network scan pass...")
        scanner = ScannerService(database=db)
        found = scanner.scan_once()
        logger.info("Scan completed. Discovered %d devices:", len(found))
        for d in found:
            logger.info("  - %s (%s) Vendor: %s, Hostname: %s", d['mac_address'], d['ip_address'], d.get('vendor'), d.get('hostname'))
        db.close()
    else:
        run_full_system()


if __name__ == "__main__":
    main()
