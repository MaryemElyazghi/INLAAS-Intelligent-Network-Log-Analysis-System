"""
Log Collector Module
====================
Automated log collection from multiple Network Management System platforms.
Supports Syslog, SNMP, NETCONF, REST API, and NMS integrations (SolarWinds,
PRTG, Nagios, Zabbix).
"""

import json
import logging
import re
import socket
import socketserver
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

import requests

logger = logging.getLogger(__name__)


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class RawLog:
    """Represents a raw, un-classified log entry from any source."""
    log_id: str = field(default_factory=lambda: f"LOG-{uuid4().hex[:8].upper()}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = ""
    source_ip: str = ""
    platform: str = ""          # syslog | snmp | netconf | api | nms
    component: str = ""
    version: str = ""
    severity: str = "INFO"
    description: str = ""
    raw_message: str = ""
    metrics: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    collected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

# ─── Syslog Collector ────────────────────────────────────────────────────────

class SyslogHandler(socketserver.BaseRequestHandler):
    """UDP/TCP Syslog message handler."""

    # RFC 5424 severity mapping
    SEVERITY_MAP = {
        0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
        4: "WARNING",   5: "NOTICE", 6: "INFO",    7: "DEBUG",
    }

    # Common network log patterns
    PATTERNS = {
        "BGP":       re.compile(r"%BGP[-\w]+:", re.IGNORECASE),
        "OSPF":      re.compile(r"%OSPF[-\w]+:", re.IGNORECASE),
        "STP":       re.compile(r"%STP[-\w]+:", re.IGNORECASE),
        "INTERFACE": re.compile(r"%LINK[-\w]+:|GigabitEthernet|TenGigE|Ethernet", re.IGNORECASE),
        "SECURITY":  re.compile(r"%ASA[-\w]+:|%SEC[-\w]+:|firewall|ACL", re.IGNORECASE),
        "HARDWARE":  re.compile(r"%CPU|%MEMORY|%ENVIRONMENT|chassis", re.IGNORECASE),
        "QOS":       re.compile(r"%QOS[-\w]+:|queue|bandwidth", re.IGNORECASE),
    }

    def __init__(self, request, client_address, server):
        self.callback: Optional[Callable] = getattr(server, "log_callback", None)
        super().__init__(request, client_address, server)

    def handle(self):
        try:
            if hasattr(self.request, "recv"):
                data = self.request[0].strip().decode("utf-8", errors="replace")
            else:
                data = self.request.recv(4096).strip().decode("utf-8", errors="replace")

            log = self._parse_syslog(data, self.client_address[0])
            if self.callback:
                self.callback(log)
        except Exception as exc:
            logger.error("Syslog handler error: %s", exc)

    def _parse_syslog(self, message: str, source_ip: str) -> RawLog:
        severity = "INFO"
        component = "UNKNOWN"

        # Extract PRI field: <priority>
        pri_match = re.match(r"^<(\d+)>", message)
        if pri_match:
            pri = int(pri_match.group(1))
            sev_code = pri & 0x07
            severity = self.SEVERITY_MAP.get(sev_code, "INFO")

        # Detect component
        for comp, pattern in self.PATTERNS.items():
            if pattern.search(message):
                component = comp
                break

        return RawLog(
            source_ip=source_ip,
            platform="syslog",
            component=component,
            severity=severity,
            description=message[:200],
            raw_message=message,
        )


class SyslogCollector:
    """
    Listens on UDP/TCP for incoming syslog messages.
    Supports RFC 3164 and RFC 5424 formats.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 514,
                 callback: Optional[Callable] = None):
        self.host = host
        self.port = port
        self.callback = callback
        self._server: Optional[socketserver.UDPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.collected: List[RawLog] = []

    def _default_callback(self, log: RawLog):
        self.collected.append(log)
        logger.info("Syslog received from %s: %s", log.source_ip, log.description[:80])

    def start(self):
        cb = self.callback or self._default_callback

        class _Server(socketserver.UDPServer):
            log_callback = cb

        self._server = _Server((self.host, self.port), SyslogHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info("SyslogCollector listening on %s:%d (UDP)", self.host, self.port)

    def stop(self):
        if self._server:
            self._server.shutdown()
            logger.info("SyslogCollector stopped.")

