# 🛡️ NetGuardian

> **Lightweight, Zero-Cost Network Monitoring & Anomaly Sentinel for Home Networks and Small Offices**  
> *Developed as a College Minor Project in Cybersecurity & Network Engineering.*

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Packet_Engine-Scapy-red.svg)](https://scapy.net/)
[![Machine Learning](https://img.shields.io/badge/ML-Isolation_Forest-success.svg)](https://scikit-learn.org/)
[![Database](https://img.shields.io/badge/Database-SQLite3_WAL-lightgrey.svg)](https://www.sqlite.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📋 Project Overview

**NetGuardian** is an autonomous network monitoring system designed to discover devices connected to a local area network (LAN), accurately identify their manufacturers and hostnames, and flag suspicious behavior in real-time.

It combines **deterministic rule-based checks** (unrecognized device alerts, off-hours activity) with an **unsupervised Machine Learning model (Isolation Forest)** trained per-device on rolling traffic baselines.

### 🎯 Core Design Principles
* **100% Free & Open-Source**: Zero cloud subscriptions, zero paid APIs, zero specialized appliances required. Runs comfortably on any standard laptop or desktop (Windows, Linux, macOS).
* **Privacy by Design**: Strictly inspects Layer 2, Layer 3, and Layer 4 **headers only** (MAC, IP, ports, protocols, packet size). Never inspects, decodes, or logs payload content.
* **Faculty Explainability**: Clear, modular codebase with documented algorithmic rationales designed for academic review and demonstration.

---

## 🏗️ Architecture & Project Structure

```text
Net_Guardians/
├── scanner/                    # Device discovery engine
│   ├── network_utils.py        # Subnet discovery, MAC normalization, IP validation
│   ├── passive_scanner.py      # Zero-packet OS ARP cache reader
│   ├── active_scanner.py       # Scapy ARP subnet broadcast prober
│   └── scanner_service.py      # Background scanner loop & DB writer
│
├── identification/             # Identity resolution engine
│   ├── vendor_lookup.py        # Offline IEEE OUI database + online API fallback
│   ├── hostname_resolver.py    # 4-tier fallback chain (DHCP -> mDNS -> DNS -> NetBIOS)
│   └── device_identifier.py    # Asynchronous device profiling worker
│
├── traffic/                    # Packet metadata logging
│   ├── packet_parser.py        # Layer 2/3/4 header parser (no payload inspection)
│   └── sniffer.py              # Scapy sniffer + high-speed SQLite batch writer
│
├── detection/                  # Hybrid anomaly detection engine
│   ├── rule_detector.py        # Rules: New devices & off-hours schedule violations
│   ├── ml_engine.py            # Per-device Isolation Forest models
│   └── detection_manager.py    # False-positive filtering & streak confirmation
│
├── alerts/                     # Notification engine
│   ├── email_notifier.py       # Free SMTP email alert sender
│   ├── discord_notifier.py     # Free Discord Webhook embed dispatcher
│   └── alert_service.py        # Asynchronous multi-channel alert queue
│
├── dashboard/                  # Web interface & REST API
│   ├── app.py                  # Flask web application factory & endpoints
│   ├── static/                 # Dark-mode CSS stylesheet and client JS
│   │   ├── style.css
│   │   └── dashboard.js
│   └── templates/              # HTML5 responsive UI template
│       └── index.html
│
├── database/                   # Shared persistence layer
│   ├── schema.sql              # SQLite schema (WAL mode, indexed lookups)
│   └── db.py                   # Thread-safe database connection manager
│
├── data/                       # Local data directory
│   ├── oui_cache.json          # Bundled offline IEEE OUI vendor database
│   └── netguardian.db          # SQLite operational database
│
├── tests/                      # Pytest unit & integration test suite
│   ├── test_database.py
│   ├── test_scanner.py
│   ├── test_identification.py
│   ├── test_traffic.py
│   ├── test_detection.py
│   └── test_alerts.py
│
├── config.py                   # Centralized configuration & environment variables
├── main.py                     # Master service orchestrator & CLI
├── requirements.txt            # Python dependencies
├── pytest.ini                  # Pytest configuration
└── README.md                   # Project documentation
```

---

## 🔬 Academic Decisions & Faculty Review Notes

### 1. Why Isolation Forest for Network Anomaly Detection?
* **Direct Anomaly Isolation**: Unlike density-based or distance-based estimators (like One-Class SVM or Gaussian Mixture Models) that attempt to compute the complex profile of "normal" behavior, Isolation Forest isolates anomalies directly using random feature partitioning.
* **Algorithmic Complexity**: Operates in **$O(n)$ linear time** with low constant factors, making it uniquely suited for commodity desktops and laptops without GPU acceleration.
* **Multi-Modal Network Realities**: Network traffic is bursty, non-linear, and multi-modal. Isolation Forest makes no assumptions about normal distribution curves.
* **Per-Device Training**: Models are trained on each device's *own* rolling historical baseline, accommodating devices with naturally high throughput (like streaming media servers) versus low-traffic IoT sensors without manual threshold tuning.

### 2. Why This Specific 4-Tier Hostname Fallback Chain?
1. **Tier 1: DHCP Sniffing (Option 12)**: When a device requests or renews an IP lease, RFC 2132 Option 12 contains the canonical machine name provided directly by the operating system (e.g. `Adarsh-MacBook`). It is the most authoritative identifier.
2. **Tier 2: mDNS / Zeroconf (.local)**: Modern IoT devices, macOS/iOS devices (Bonjour), and Linux hosts (Avahi) broadcast friendly multicast DNS names on port 5353.
3. **Tier 3: Reverse DNS (PTR query)**: If the home router runs a local DNS proxy (such as Dnsmasq, Unbound, or Pi-hole), standard `gethostbyaddr` resolves the hostname mapped during DHCP assignment.
4. **Tier 4: NetBIOS Node Status (UDP 137)**: Legacy Windows workstations and Samba file servers respond to NetBIOS status queries, providing a reliable safety net when modern DNS protocols are firewalled.

### 3. False-Positive Mitigation Strategy
* **Trust-Marking Feedback**: Users can flag devices or known patterns as "trusted" via the dashboard with a single click. Trusted devices bypass new-device alerts, and their observed metrics feed back into baseline normalization.
* **Consecutive Window Confirmation**: Transient network spikes (e.g. software updates or cloud backups) often score as temporary statistical outliers. NetGuardian suppresses single-window outliers and **only emits alerts when an ML anomaly persists across $\ge 2$ consecutive observation windows**.

---

## ⚙️ Installation & Setup

### Prerequisites
* **Python 3.11+**
* On **Windows**: Install [Npcap](https://npcap.com/) (select *"Install Npcap in WinPcap API-compatible Mode"* during setup) to enable packet sniffing and active ARP probing.
* On **Linux**: Ensure `libpcap-dev` is installed (`sudo apt install libpcap-dev`).

### 1. Clone & Set Up Virtual Environment
```bash
# Clone the repository
git clone https://github.com/your-username/NetGuardian.git
cd NetGuardian

# Create and activate Python virtual environment
# Windows:
python -m venv .venv
.\.venv\Scripts\activate

# Linux / macOS:
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🚀 Running NetGuardian

### Option A: Complete System (Recommended)
Launches the background ARP scanner, packet metadata sniffer, device identifier, ML engine, alert dispatcher, and the Flask web dashboard simultaneously:
```bash
# Note: Packet capture and active ARP probing require administrative privileges
# Windows: Run in an Administrator Command Prompt or PowerShell
python main.py
```
Open your browser and navigate to: **`http://127.0.0.1:5000`**

### Option B: Web Dashboard Only
Inspect historical devices, traffic logs, and alerts without starting background packet sniffing:
```bash
python main.py --dashboard-only
```

### Option C: Single Scan Pass (CLI)
Perform an on-demand passive + active ARP discovery pass, print discovered hosts to the console, update the database, and exit:
```bash
python main.py --scan-once
```

---

## 🔔 Configuring Free Alerts

Configure alerting channels directly via environment variables or by editing [`config.py`](file:///c:/Users/AdarshSingh/OneDrive/Desktop/Net_Guardians/config.py):

### 1. Free Discord Webhooks
1. In your Discord server: Go to **Channel Settings** > **Integrations** > **Webhooks** > **New Webhook**.
2. Copy the Webhook URL.
3. Set environment variable:
   ```bash
   # Windows PowerShell:
   $env:NETGUARDIAN_DISCORD_ENABLED="true"
   $env:NETGUARDIAN_DISCORD_WEBHOOK="https://discord.com/api/webhooks/your/webhook/url"
   ```

### 2. Free Email Alerts (Gmail SMTP)
1. Generate a free 16-character [Google App Password](https://myaccount.google.com/apppasswords).
2. Set environment variables:
   ```bash
   # Windows PowerShell:
   $env:NETGUARDIAN_EMAIL_ENABLED="true"
   $env:NETGUARDIAN_SMTP_SERVER="smtp.gmail.com"
   $env:NETGUARDIAN_SMTP_PORT="587"
   $env:NETGUARDIAN_SMTP_USER="your-email@gmail.com"
   $env:NETGUARDIAN_SMTP_PASS="your-16-char-app-password"
   $env:NETGUARDIAN_EMAIL_TO="recipient-email@gmail.com"
   ```

---

## 🧪 Running the Test Suite

Execute the unit test suite covering database operations, packet parsing, OUI vendor lookups, and detection logic:
```bash
pytest tests/test_database.py -v
```

---

## 📊 Database Schema Summary

NetGuardian uses SQLite configured with **Write-Ahead Logging (WAL)** for high concurrency:

| Table | Purpose |
| :--- | :--- |
| `devices` | Tracks MAC, IP, vendor, hostname, active hours, trust state, and ML anomaly score. |
| `traffic_logs` | High-throughput packet header metadata (timestamps, protocols, ports, sizes). |
| `anomalies` | Record of flagged rule violations and persistent ML deviations. |
| `alerts` | Audit trail of dispatched Email, Discord, and Dashboard notifications. |

---

## 👥 Authors & Academic Context

* **Project**: NetGuardian — Autonomous Network Monitor
* **Type**: College Minor Project
* **Guide**: Faculty of Computer Science & Engineering / Information Technology
* **Year**: 2026
