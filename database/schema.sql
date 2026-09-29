-- NetGuardian Database Schema
-- Optimized for SQLite with WAL mode for concurrent scanner & dashboard read/writes.

CREATE TABLE IF NOT EXISTS devices (
    mac_address TEXT PRIMARY KEY,
    ip_address TEXT NOT NULL,
    hostname TEXT,
    vendor TEXT,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    is_trusted INTEGER DEFAULT 0,
    active_hours_start INTEGER DEFAULT 0,
    active_hours_end INTEGER DEFAULT 23,
    anomaly_score REAL DEFAULT 0.0,
    consecutive_ml_anomalies INTEGER DEFAULT 0,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS traffic_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL,
    src_mac TEXT,
    dst_mac TEXT,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    protocol TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    packet_size INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL,
    mac_address TEXT,
    ip_address TEXT,
    anomaly_type TEXT NOT NULL, -- 'NEW_DEVICE', 'OFF_HOURS_ACTIVITY', 'ML_TRAFFIC_SPIKE', etc.
    description TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'MEDIUM', -- 'LOW', 'MEDIUM', 'HIGH'
    score REAL DEFAULT 0.0,
    is_resolved INTEGER DEFAULT 0,
    FOREIGN KEY (mac_address) REFERENCES devices(mac_address) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL,
    anomaly_id INTEGER,
    channel TEXT NOT NULL, -- 'EMAIL', 'DISCORD', 'DASHBOARD'
    status TEXT NOT NULL,  -- 'SENT', 'FAILED', 'PENDING'
    message TEXT NOT NULL,
    error_message TEXT,
    FOREIGN KEY (anomaly_id) REFERENCES anomalies(id) ON DELETE CASCADE
);

-- Indices for performance
CREATE INDEX IF NOT EXISTS idx_traffic_src_mac ON traffic_logs(src_mac);
CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_traffic_protocol ON traffic_logs(protocol);
CREATE INDEX IF NOT EXISTS idx_anomalies_mac ON anomalies(mac_address);
CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp ON anomalies(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
