"""
NetGuardian Traffic Sniffer
Passively captures network packets, extracts header metadata, and buffers writes
to SQLite using a high-throughput batching worker.
"""

import logging
import queue
import threading
import time
from typing import Any, Callable, Dict, List, Optional

import config
from database.db import Database, db as default_db
from identification.hostname_resolver import (
    HostnameResolver,
    hostname_resolver_service as default_resolver,
)
from traffic.packet_parser import parse_packet_metadata

logger = logging.getLogger(__name__)


class TrafficSniffer:
    """
    Continuous passive network traffic metadata capture service.
    Runs a dedicated Scapy sniffer thread and an asynchronous SQLite batch writer.
    """

    def __init__(
        self,
        database: Optional[Database] = None,
        interface: Optional[str] = None,
        hostname_resolver: Optional[HostnameResolver] = None,
        on_packet_captured: Optional[Callable[[Dict[str, Any]], None]] = None,
        batch_size: int = 50,
        flush_interval: float = 1.0,
    ):
        self.db = database or default_db
        self.interface = interface or config.NETWORK_INTERFACE
        self.hostname_resolver = hostname_resolver or default_resolver
        self.on_packet_captured = on_packet_captured
        self.batch_size = batch_size
        self.flush_interval = flush_interval

        self._queue: queue.Queue = queue.Queue(maxsize=10000)
        self._stop_event = threading.Event()
        self._sniff_thread: Optional[threading.Thread] = None
        self._writer_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def process_packet(self, packet: Any) -> None:
        """Callback invoked by Scapy for each captured packet."""
        try:
            meta = parse_packet_metadata(packet)
            if not meta:
                return

            # Feed observed DHCP hostnames to the resolver
            if meta.get("dhcp_hostname"):
                target = meta.get("src_mac") or meta.get("src_ip")
                if target:
                    self.hostname_resolver.record_dhcp_hostname(
                        target, meta["dhcp_hostname"]
                    )

            # Enqueue for database persistence
            try:
                self._queue.put_nowait(meta)
            except queue.Full:
                logger.warning("Traffic metadata queue is full; dropping packet record.")

            # Fire real-time detection callback
            if self.on_packet_captured:
                try:
                    self.on_packet_captured(meta)
                except Exception as cb_err:
                    logger.debug("Error in packet captured callback: %s", cb_err)

        except Exception as e:
            logger.debug("Error handling packet in sniffer: %s", e)

    def _batch_writer_loop(self) -> None:
        """Buffers metadata and performs high-speed batch inserts into SQLite."""
        buffer: List[Dict[str, Any]] = []
        last_flush = time.time()

        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                # Wait briefly for incoming records
                try:
                    meta = self._queue.get(timeout=0.2)
                    buffer.append(meta)
                    self._queue.task_done()
                except queue.Empty:
                    pass

                now = time.time()
                # Flush condition: reached batch size or flush interval elapsed
                if buffer and (
                    len(buffer) >= self.batch_size
                    or (now - last_flush) >= self.flush_interval
                ):
                    self.db.batch_log_traffic(buffer)
                    buffer.clear()
                    last_flush = now

            except Exception as e:
                logger.error("Error in traffic batch writer: %s", e)

        # Flush any remaining items before exiting
        if buffer:
            try:
                self.db.batch_log_traffic(buffer)
            except Exception as e:
                logger.error("Error in final traffic batch flush: %s", e)

    def _sniffer_loop(self) -> None:
        """Internal thread running Scapy sniff in a loop with timeout check."""
        logger.info(
            "TrafficSniffer started on interface: %s",
            self.interface or "Default/Auto",
        )
        try:
            from scapy.sendrecv import sniff

            while not self._stop_event.is_set():
                kwargs = {
                    "prn": self.process_packet,
                    "store": 0,
                    "timeout": 1.0,
                }
                if self.interface:
                    kwargs["iface"] = self.interface

                sniff(**kwargs)
        except PermissionError:
            logger.warning(
                "Packet sniffing requires administrative privileges or Npcap/WinPcap."
            )
        except Exception as e:
            logger.warning("Traffic sniffing error: %s", e)

        logger.info("TrafficSniffer stopped.")

    def start(self) -> None:
        """Start sniffer and batch writer worker threads."""
        with self._lock:
            if self._sniff_thread is not None and self._sniff_thread.is_alive():
                return

            self._stop_event.clear()

            # Start SQLite batch writer first
            self._writer_thread = threading.Thread(
                target=self._batch_writer_loop,
                name="NetGuardian-TrafficWriter",
                daemon=True,
            )
            self._writer_thread.start()

            # Start Scapy sniffer thread
            self._sniff_thread = threading.Thread(
                target=self._sniffer_loop,
                name="NetGuardian-TrafficSniffer",
                daemon=True,
            )
            self._sniff_thread.start()

    def stop(self) -> None:
        """Gracefully stop sniffer and flush remaining metadata."""
        with self._lock:
            self._stop_event.set()
            if self._sniff_thread is not None:
                self._sniff_thread.join(timeout=2.0)
                self._sniff_thread = None
            if self._writer_thread is not None:
                self._writer_thread.join(timeout=3.0)
                self._writer_thread = None

    @property
    def is_running(self) -> bool:
        """Check if sniffer is running."""
        return self._sniff_thread is not None and self._sniff_thread.is_alive()
