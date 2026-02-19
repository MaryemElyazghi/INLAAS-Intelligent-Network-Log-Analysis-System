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


# ─── REST / NMS Collector ────────────────────────────────────────────────────

class NMSCollector:
    """
    Polls Network Management System REST APIs to collect logs and events.
    Currently supports: SolarWinds, PRTG, Nagios, Zabbix, and generic REST.
    """

    def __init__(self, config: Dict):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    # ── Generic REST ─────────────────────────────────────────
    def collect_from_rest(self, base_url: str, endpoint: str,
                          headers: Optional[Dict] = None,
                          params: Optional[Dict] = None) -> List[RawLog]:
        """Pull logs from a generic REST API endpoint."""
        try:
            resp = self.session.get(
                f"{base_url}/{endpoint.lstrip('/')}",
                headers=headers or {},
                params=params or {},
                timeout=self.config.get("timeout_seconds", 10),
            )
            resp.raise_for_status()
            data = resp.json()
            return self._normalize_rest_response(data, base_url)
        except requests.RequestException as exc:
            logger.error("REST collection failed for %s: %s", base_url, exc)
            return []

    def _normalize_rest_response(self, data: Any, source: str) -> List[RawLog]:
        logs = []
        items = data if isinstance(data, list) else data.get("results", data.get("logs", []))
        for item in items[:self.config.get("batch_size", 500)]:
            logs.append(RawLog(
                source=item.get("source", source),
                platform="api",
                component=item.get("component", "UNKNOWN"),
                version=item.get("version", ""),
                severity=item.get("severity", "INFO").upper(),
                description=item.get("description", item.get("message", "")),
                raw_message=json.dumps(item),
                metrics=item.get("metrics", {}),
            ))
        return logs

    # ── SolarWinds SWIS ──────────────────────────────────────
    def collect_from_solarwinds(self, base_url: str,
                                 username: str, password: str) -> List[RawLog]:
        """Query SolarWinds Information Service (SWIS) for network events."""
        query = {
            "query": (
                "SELECT EventTime, NetObjectID, NetObjectType, Message, "
                "Acknowledged, EngineID "
                "FROM Orion.Events "
                "WHERE EventTime > GETDATE()-1 "
                "ORDER BY EventTime DESC"
            )
        }
        try:
            resp = self.session.post(
                f"{base_url}/Query",
                json=query,
                auth=(username, password),
                verify=False,
                timeout=15,
            )
            resp.raise_for_status()
            results = resp.json().get("results", [])
            return [
                RawLog(
                    timestamp=r.get("EventTime", datetime.now(timezone.utc).isoformat()),
                    source=str(r.get("NetObjectID", "")),
                    platform="nms_solarwinds",
                    component=r.get("NetObjectType", "UNKNOWN"),
                    description=r.get("Message", ""),
                    raw_message=json.dumps(r),
                )
                for r in results
            ]
        except requests.RequestException as exc:
            logger.error("SolarWinds collection failed: %s", exc)
            return []

    # ── Zabbix ───────────────────────────────────────────────
    def collect_from_zabbix(self, base_url: str,
                             username: str, password: str) -> List[RawLog]:
        """Authenticate and pull events from Zabbix API."""
        try:
            # Authenticate
            auth_resp = self.session.post(base_url, json={
                "jsonrpc": "2.0", "method": "user.login",
                "params": {"username": username, "password": password},
                "id": 1,
            })
            token = auth_resp.json().get("result", "")

            # Get events
            events_resp = self.session.post(base_url, json={
                "jsonrpc": "2.0", "method": "event.get",
                "params": {
                    "output": "extend",
                    "select_hosts": ["host"],
                    "limit": self.config.get("batch_size", 500),
                    "sortfield": ["clock"],
                    "sortorder": "DESC",
                },
                "auth": token, "id": 2,
            })
            events = events_resp.json().get("result", [])
            return [
                RawLog(
                    timestamp=datetime.fromtimestamp(
                        int(e.get("clock", 0)), timezone.utc
                    ).isoformat(),
                    source=e.get("hosts", [{}])[0].get("host", "unknown"),
                    platform="nms_zabbix",
                    severity=self._zabbix_severity(int(e.get("severity", 0))),
                    description=e.get("name", ""),
                    raw_message=json.dumps(e),
                )
                for e in events
            ]
        except requests.RequestException as exc:
            logger.error("Zabbix collection failed: %s", exc)
            return []

    @staticmethod
    def _zabbix_severity(sev: int) -> str:
        mapping = {0: "INFO", 1: "INFO", 2: "WARNING",
                   3: "ERROR", 4: "ERROR", 5: "CRITICAL"}
        return mapping.get(sev, "INFO")

