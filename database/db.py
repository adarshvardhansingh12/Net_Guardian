"""
NetGuardian Database Access Layer
Provides clean, thread-safe SQLite operations for scanner, traffic capture,
ML detection engine, alerting, and Flask dashboard.
"""

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import config


def get_current_utc_iso() -> str:
    """Return current UTC timestamp in standard SQLite format (YYYY-MM-DD HH:MM:SS)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class Database:
    """
    SQLite Database Manager for NetGuardian.
    Supports thread-local connections and WAL mode for high-concurrency read/writes.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path or config.DB_PATH)
        self._local = threading.local()
        self._all_conns: List[sqlite3.Connection] = []
        self._init_lock = threading.Lock()
        self.ensure_initialized()

    def get_connection(self) -> sqlite3.Connection:
        """
        Return a thread-local SQLite connection with foreign keys and WAL mode enabled.
        """
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(
                str(self.db_path),
                timeout=30.0,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            # Enable WAL mode for high concurrency between scanner, ML, and dashboard
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            self._local.conn = conn
            with self._init_lock:
                self._all_conns.append(conn)
        return self._local.conn

    def close(self) -> None:
        """Close all connections across threads."""
        with self._init_lock:
            for c in self._all_conns:
                try:
                    c.close()
                except Exception:
                    pass
            self._all_conns.clear()
            if hasattr(self._local, "conn"):
                self._local.conn = None

    def ensure_initialized(self) -> None:
        """Execute schema.sql if tables do not exist."""
        with self._init_lock:
            schema_file = Path(__file__).resolve().parent / "schema.sql"
            if schema_file.exists():
                with open(schema_file, "r", encoding="utf-8") as f:
                    schema_sql = f.read()
                conn = self.get_connection()
                with conn:
                    conn.executescript(schema_sql)

    # ---------------------------------------------------------
    # Devices Operations
    # ---------------------------------------------------------

    def upsert_device(
        self,
        mac_address: str,
        ip_address: str,
        hostname: Optional[str] = None,
        vendor: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Inserts a newly discovered device or updates an existing device's last_seen & IP.
        
        Returns:
            (is_new, device_record_dict)
            is_new: True if this device was never recorded before in the database.
        """
        mac = mac_address.lower().strip()
        now = get_current_utc_iso()
        conn = self.get_connection()

        with conn:
            cursor = conn.execute(
                "SELECT * FROM devices WHERE mac_address = ?", (mac,)
            )
            row = cursor.fetchone()

            if row is None:
                # Newly discovered device
                conn.execute(
                    """
                    INSERT INTO devices (
                        mac_address, ip_address, hostname, vendor,
                        first_seen, last_seen, is_trusted,
                        active_hours_start, active_hours_end,
                        anomaly_score, consecutive_ml_anomalies, notes
                    ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, 23, 0.0, 0, ?)
                    """,
                    (mac, ip_address, hostname, vendor, now, now, notes),
                )
                cur = conn.execute("SELECT * FROM devices WHERE mac_address = ?", (mac,))
                return True, dict(cur.fetchone())
            else:
                # Update existing device IP and last_seen
                update_fields = ["ip_address = ?", "last_seen = ?"]
                params: List[Any] = [ip_address, now]

                if hostname and not row["hostname"]:
                    update_fields.append("hostname = ?")
                    params.append(hostname)
                if vendor and not row["vendor"]:
                    update_fields.append("vendor = ?")
                    params.append(vendor)
                if notes:
                    update_fields.append("notes = ?")
                    params.append(notes)

                params.append(mac)
                conn.execute(
                    f"UPDATE devices SET {', '.join(update_fields)} WHERE mac_address = ?",
                    params,
                )
                cur = conn.execute("SELECT * FROM devices WHERE mac_address = ?", (mac,))
                return False, dict(cur.fetchone())

    def get_device(self, mac_address: str) -> Optional[Dict[str, Any]]:
        """Fetch a single device by MAC address."""
        conn = self.get_connection()
        cursor = conn.execute(
            "SELECT * FROM devices WHERE mac_address = ?",
            (mac_address.lower().strip(),),
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_all_devices(self, trusted_only: bool = False) -> List[Dict[str, Any]]:
        """Retrieve all registered devices ordered by last seen."""
        conn = self.get_connection()
        query = "SELECT * FROM devices"
        params: List[Any] = []
        if trusted_only:
            query += " WHERE is_trusted = 1"
        query += " ORDER BY datetime(last_seen) DESC"
        cursor = conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def set_device_trust(self, mac_address: str, is_trusted: bool) -> bool:
        """Mark a device as trusted or untrusted."""
        conn = self.get_connection()
        with conn:
            cursor = conn.execute(
                "UPDATE devices SET is_trusted = ? WHERE mac_address = ?",
                (1 if is_trusted else 0, mac_address.lower().strip()),
            )
            return cursor.rowcount > 0

    def update_device_identification(
        self,
        mac_address: str,
        vendor: Optional[str] = None,
        hostname: Optional[str] = None,
    ) -> bool:
        """Update resolved hostname or vendor for a device."""
        mac = mac_address.lower().strip()
        updates = []
        params: List[Any] = []
        if vendor is not None:
            updates.append("vendor = ?")
            params.append(vendor)
        if hostname is not None:
            updates.append("hostname = ?")
            params.append(hostname)
        if not updates:
            return False

        params.append(mac)
        conn = self.get_connection()
        with conn:
            cursor = conn.execute(
                f"UPDATE devices SET {', '.join(updates)} WHERE mac_address = ?",
                params,
            )
            return cursor.rowcount > 0

    def update_device_active_hours(
        self, mac_address: str, start_hour: int, end_hour: int
    ) -> bool:
        """Update expected normal active hours (0-23) for rule-based detection."""
        conn = self.get_connection()
        with conn:
            cursor = conn.execute(
                """
                UPDATE devices 
                SET active_hours_start = ?, active_hours_end = ? 
                WHERE mac_address = ?
                """,
                (start_hour, end_hour, mac_address.lower().strip()),
            )
            return cursor.rowcount > 0

    def update_device_ml_state(
        self, mac_address: str, anomaly_score: float, consecutive_ml_anomalies: int
    ) -> bool:
        """Update the latest ML anomaly score and consecutive anomaly counter."""
        conn = self.get_connection()
        with conn:
            cursor = conn.execute(
                """
                UPDATE devices 
                SET anomaly_score = ?, consecutive_ml_anomalies = ? 
                WHERE mac_address = ?
                """,
                (anomaly_score, consecutive_ml_anomalies, mac_address.lower().strip()),
            )
            return cursor.rowcount > 0

    # ---------------------------------------------------------
    # Traffic Logs Operations
    # ---------------------------------------------------------

    def log_traffic(
        self,
        src_mac: Optional[str],
        dst_mac: Optional[str],
        src_ip: str,
        dst_ip: str,
        protocol: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        packet_size: int,
        timestamp: Optional[str] = None,
    ) -> int:
        """Log packet header metadata (no payloads)."""
        ts = timestamp or get_current_utc_iso()
        s_mac = src_mac.lower().strip() if src_mac else None
        d_mac = dst_mac.lower().strip() if dst_mac else None

        conn = self.get_connection()
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO traffic_logs (
                    timestamp, src_mac, dst_mac, src_ip, dst_ip,
                    protocol, src_port, dst_port, packet_size
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (ts, s_mac, d_mac, src_ip, dst_ip, protocol, src_port, dst_port, packet_size),
            )
            return cursor.lastrowid or 0

    def batch_log_traffic(self, logs: List[Dict[str, Any]]) -> int:
        """Batch insert packet logs for high-throughput sniffing."""
        if not logs:
            return 0
        conn = self.get_connection()
        records = []
        for l in logs:
            records.append((
                l.get("timestamp") or get_current_utc_iso(),
                l.get("src_mac").lower().strip() if l.get("src_mac") else None,
                l.get("dst_mac").lower().strip() if l.get("dst_mac") else None,
                l.get("src_ip", ""),
                l.get("dst_ip", ""),
                l.get("protocol", "OTHER"),
                l.get("src_port"),
                l.get("dst_port"),
                l.get("packet_size", 0),
            ))
        with conn:
            cursor = conn.executemany(
                """
                INSERT INTO traffic_logs (
                    timestamp, src_mac, dst_mac, src_ip, dst_ip,
                    protocol, src_port, dst_port, packet_size
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                records,
            )
            return cursor.rowcount

    def get_recent_traffic(
        self, limit: int = 100, mac_address: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch recent traffic metadata logs."""
        conn = self.get_connection()
        if mac_address:
            cursor = conn.execute(
                """
                SELECT * FROM traffic_logs 
                WHERE src_mac = ? OR dst_mac = ? 
                ORDER BY id DESC LIMIT ?
                """,
                (mac_address.lower().strip(), mac_address.lower().strip(), limit),
            )
        else:
            cursor = conn.execute(
                "SELECT * FROM traffic_logs ORDER BY id DESC LIMIT ?",
                (limit,),
            )
        return [dict(row) for row in cursor.fetchall()]

    def get_device_windowed_stats(
        self, mac_address: str, hours_back: int = 24
    ) -> List[Dict[str, Any]]:
        """
        Aggregate traffic metrics (packet count, total bytes, active hours)
        into 1-hour time buckets for ML baseline training.
        """
        conn = self.get_connection()
        cursor = conn.execute(
            """
            SELECT 
                strftime('%Y-%m-%d %H:00:00', timestamp) AS window_hour,
                CAST(strftime('%H', timestamp) AS INTEGER) AS hour_of_day,
                COUNT(*) AS packet_count,
                SUM(packet_size) AS byte_volume,
                COUNT(DISTINCT protocol) AS protocol_variety
            FROM traffic_logs
            WHERE (src_mac = ? OR dst_mac = ?)
              AND datetime(timestamp) >= datetime('now', ?)
            GROUP BY window_hour
            ORDER BY window_hour ASC
            """,
            (mac_address.lower().strip(), mac_address.lower().strip(), f"-{hours_back} hours"),
        )
        return [dict(row) for row in cursor.fetchall()]

    # ---------------------------------------------------------
    # Anomalies Operations
    # ---------------------------------------------------------

    def record_anomaly(
        self,
        mac_address: Optional[str],
        ip_address: Optional[str],
        anomaly_type: str,
        description: str,
        severity: str = "MEDIUM",
        score: float = 0.0,
    ) -> int:
        """Record a newly detected rule-based or ML anomaly."""
        now = get_current_utc_iso()
        mac = mac_address.lower().strip() if mac_address else None
        conn = self.get_connection()
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO anomalies (
                    timestamp, mac_address, ip_address,
                    anomaly_type, description, severity, score, is_resolved
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (now, mac, ip_address, anomaly_type, description, severity, score),
            )
            return cursor.lastrowid or 0

    def get_anomalies(
        self, unresolved_only: bool = False, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Fetch recorded anomalies."""
        conn = self.get_connection()
        query = "SELECT * FROM anomalies"
        params: List[Any] = []
        if unresolved_only:
            query += " WHERE is_resolved = 0"
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        cursor = conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def resolve_anomaly(self, anomaly_id: int) -> bool:
        """Mark an anomaly as resolved."""
        conn = self.get_connection()
        with conn:
            cursor = conn.execute(
                "UPDATE anomalies SET is_resolved = 1 WHERE id = ?", (anomaly_id,)
            )
            return cursor.rowcount > 0

    # ---------------------------------------------------------
    # Alerts Operations
    # ---------------------------------------------------------

    def record_alert(
        self,
        anomaly_id: Optional[int],
        channel: str,
        status: str,
        message: str,
        error_message: Optional[str] = None,
    ) -> int:
        """Record dispatched notification (Email, Discord, Dashboard)."""
        now = get_current_utc_iso()
        conn = self.get_connection()
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO alerts (
                    timestamp, anomaly_id, channel, status, message, error_message
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (now, anomaly_id, channel, status, message, error_message),
            )
            return cursor.lastrowid or 0

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch alert history."""
        conn = self.get_connection()
        cursor = conn.execute(
            """
            SELECT a.*, an.anomaly_type, an.severity, an.mac_address, an.ip_address
            FROM alerts a
            LEFT JOIN anomalies an ON a.anomaly_id = an.id
            ORDER BY a.id DESC LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in cursor.fetchall()]

    # ---------------------------------------------------------
    # Dashboard Aggregations
    # ---------------------------------------------------------

    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Fetch aggregate network and security statistics for the Flask dashboard."""
        conn = self.get_connection()
        total_devices = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        # Active devices: seen in the last 10 minutes
        active_devices = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE datetime(last_seen) >= datetime('now', '-10 minutes')"
        ).fetchone()[0]
        total_packets = conn.execute("SELECT COUNT(*) FROM traffic_logs").fetchone()[0]
        unresolved_anomalies = conn.execute(
            "SELECT COUNT(*) FROM anomalies WHERE is_resolved = 0"
        ).fetchone()[0]
        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

        # Protocol distribution
        protocols_cur = conn.execute(
            """
            SELECT protocol, COUNT(*) as count 
            FROM traffic_logs 
            GROUP BY protocol 
            ORDER BY count DESC LIMIT 8
            """
        )
        protocol_breakdown = [dict(row) for row in protocols_cur.fetchall()]

        return {
            "total_devices": total_devices,
            "active_devices": active_devices,
            "total_packets": total_packets,
            "unresolved_anomalies": unresolved_anomalies,
            "total_alerts": total_alerts,
            "protocol_breakdown": protocol_breakdown,
        }


# Global singleton instance
db = Database()


def init_db(custom_path: Optional[Path] = None) -> Database:
    """Helper to initialize or get a database instance."""
    return Database(custom_path)
