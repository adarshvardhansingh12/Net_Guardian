"""
NetGuardian Configuration Module
Centralized configuration management for network monitoring, detection,
database paths, alerts, and dashboard settings.
"""

import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

# Database Configuration
# Using SQLite for zero-cost, zero-configuration local persistence
DB_PATH = DATA_DIR / "netguardian.db"

# Network & Scanner Configuration
# None enables automatic interface detection via Scapy / OS routing table
NETWORK_INTERFACE = None
# Interval between background active/passive scans (in seconds)
SCAN_INTERVAL_SECONDS = 30
# Timeout for active ARP ping requests (seconds)
ARP_PING_TIMEOUT = 2.0

# Identification Configuration
# Fallback chain: DHCP -> mDNS (zeroconf) -> Reverse DNS -> NetBIOS
HOSTNAME_RESOLVERS = ["dhcp", "mdns", "dns", "netbios"]
# OUI Database path (offline IEEE MAC vendor list)
OUI_CACHE_PATH = DATA_DIR / "oui_cache.json"
# Online fallback endpoint (free tier, rate-limited)
MAC_VENDORS_API_URL = "https://api.macvendors.com/"
MAC_VENDORS_TIMEOUT = 3.0

# Detection & ML Configuration
# Isolation Forest is chosen because it isolates anomalies directly rather than
# profiling normal points, functioning exceptionally well with multi-modal network data
# and low memory overhead without requiring labeled training datasets.
ML_MIN_SAMPLES_FOR_TRAIN = 20  # Minimum windowed observations before training baseline
ML_CONTAMINATION_RATE = 0.05   # Expected proportion of outliers in the data
ML_WINDOW_SIZE_MINUTES = 60    # Observation aggregation window for traffic stats
ML_SCORE_THRESHOLD = -0.15     # Anomaly decision function threshold (< 0 indicates outlier)
# Alert only if an anomaly repeats across consecutive observation windows to suppress noise
CONSECUTIVE_ANOMALIES_FOR_ALERT = 2

# Alerting Configuration
ALERT_EMAIL_ENABLED = os.getenv("NETGUARDIAN_EMAIL_ENABLED", "false").lower() == "true"
SMTP_SERVER = os.getenv("NETGUARDIAN_SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("NETGUARDIAN_SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("NETGUARDIAN_SMTP_USER", "")
SMTP_PASSWORD = os.getenv("NETGUARDIAN_SMTP_PASS", "")
ALERT_EMAIL_TO = os.getenv("NETGUARDIAN_EMAIL_TO", "")

ALERT_DISCORD_ENABLED = os.getenv("NETGUARDIAN_DISCORD_ENABLED", "false").lower() == "true"
DISCORD_WEBHOOK_URL = os.getenv("NETGUARDIAN_DISCORD_WEBHOOK", "")

# Dashboard Configuration
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 5000
DASHBOARD_DEBUG = False
SECRET_KEY = os.getenv("NETGUARDIAN_SECRET_KEY", "netguardian-college-project-secret-2026")
