"""
Security Threat Analysis Module
================================
Identifies and scores security threats from network logs.
Provides threat intelligence correlation, IOC extraction, and incident scoring.
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set

from src.classifiers.log_classifier import ClassifiedLog

logger = logging.getLogger(__name__)


@dataclass
class SecurityThreat:
    threat_id: str
    threat_type: str
    severity: str
    score: float                          # 0-1
    source_ips: List[str]
    target_ips: List[str]
    target_ports: List[int]
    affected_devices: List[str]
    log_ids: List[str]
    first_seen: str
    last_seen: str
    event_count: int
    description: str
    iocs: List[str] = field(default_factory=list)   # Indicators of Compromise
    mitre_tactics: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    is_active: bool = True

    def to_dict(self) -> Dict:
        return self.__dict__


class SecurityAnalyzer:
    """
    Scans classified logs for security threats, extracts IOCs (IPs, ports,
    hashes), maps to MITRE ATT&CK tactics, and generates incident reports.
    """

    # MITRE ATT&CK tactic mapping by threat type
    MITRE_MAP: Dict[str, List[str]] = {
        "port_scan":        ["TA0043 - Reconnaissance", "T1595 - Active Scanning"],
        "brute_force":      ["TA0006 - Credential Access", "T1110 - Brute Force"],
        "dos_attack":       ["TA0040 - Impact", "T1498 - Network DoS"],
        "ddos_attack":      ["TA0040 - Impact", "T1498.002 - Reflection Amplification"],
        "dns_amplification":["TA0040 - Impact", "T1498.002 - Reflection Amplification"],
        "unauthorized":     ["TA0001 - Initial Access", "T1078 - Valid Accounts"],
        "data_exfiltration":["TA0010 - Exfiltration", "T1048 - Exfiltration Over Alt Protocol"],
        "arp_spoofing":     ["TA0007 - Discovery", "T1557 - Adversary-in-the-Middle"],
    }

    SEVERITY_THRESHOLDS = {
        "CRITICAL": 0.85,
        "HIGH":     0.70,
        "MEDIUM":   0.50,
        "LOW":      0.30,
    }

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._active_threats: Dict[str, SecurityThreat] = {}
        self._blocked_ips: Set[str] = set()

    # ── IOC Extraction ────────────────────────────────────────

    @staticmethod
    def extract_iocs(log: ClassifiedLog) -> Dict[str, List]:
        """Extract Indicators of Compromise from log text."""
        text = f"{log.description} {log.raw_message}"
        iocs: Dict[str, List] = {"ips": [], "ports": [], "domains": [], "hashes": []}

        # IPv4 addresses
        iocs["ips"] = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))

        # Ports
        port_matches = re.findall(r":(\d{2,5})\b", text)
        iocs["ports"] = list({int(p) for p in port_matches if int(p) <= 65535})

        # Domains (simple pattern)
        domains = re.findall(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|gov|edu)\b",
                             text, re.IGNORECASE)
        iocs["domains"] = list(set(domains))

        # MD5/SHA hashes
        hashes = re.findall(r"\b[0-9a-f]{32,64}\b", text, re.IGNORECASE)
        iocs["hashes"] = list(set(hashes))

        return iocs

    # ── Single-Log Threat Assessment ─────────────────────────

    def assess_log(self, log: ClassifiedLog) -> Optional[SecurityThreat]:
        """
        If the log contains a security threat, return a SecurityThreat object.
        Returns None for non-threatening logs.
        """
        if not log.security_threat or log.threat_score < 0.30:
            return None

        iocs = self.extract_iocs(log)
        mitre = self.MITRE_MAP.get(log.threat_type, ["TA0000 - Unknown"])

        # Determine severity bucket
        sev = "LOW"
        for bucket, threshold in self.SEVERITY_THRESHOLDS.items():
            if log.threat_score >= threshold:
                sev = bucket
                break

        actions = self._build_actions(log.threat_type, sev, iocs["ips"])

        return SecurityThreat(
            threat_id=f"THR-{abs(hash(log.log_id)) % 100000:05d}",
            threat_type=log.threat_type,
            severity=sev,
            score=log.threat_score,
            source_ips=iocs["ips"][:5],
            target_ips=[log.source_ip] if log.source_ip else [],
            target_ports=iocs["ports"][:10],
            affected_devices=[log.source],
            log_ids=[log.log_id],
            first_seen=log.timestamp,
            last_seen=log.timestamp,
            event_count=1,
            description=log.description[:300],
            iocs=iocs["ips"] + iocs["domains"] + iocs["hashes"],
            mitre_tactics=mitre,
            recommended_actions=actions,
        )

    # ── Batch Analysis ────────────────────────────────────────

    def analyze_batch(self, logs: List[ClassifiedLog]) -> List[SecurityThreat]:
        """
        Analyze a batch of logs, consolidate related threats by type+source,
        and return deduplicated incident list.
        """
        # Group by threat type + source IP
        buckets: Dict[str, List[ClassifiedLog]] = {}
        for log in logs:
            if log.security_threat and log.threat_score >= 0.30:
                iocs = self.extract_iocs(log)
                src = iocs["ips"][0] if iocs["ips"] else log.source
                key = f"{log.threat_type}::{src}"
                buckets.setdefault(key, []).append(log)

        threats = []
        for key, group in buckets.items():
            consolidated = self._consolidate(group)
            if consolidated:
                threats.append(consolidated)
                self._active_threats[consolidated.threat_id] = consolidated

        threats.sort(key=lambda t: t.score, reverse=True)
        logger.info("Security analysis: %d threats from %d logs", len(threats), len(logs))
        return threats

    def _consolidate(self, logs: List[ClassifiedLog]) -> Optional[SecurityThreat]:
        """Merge multiple logs of the same threat type into one incident."""
        if not logs:
            return None

        first = self.assess_log(logs[0])
        if not first:
            return None

        all_iocs = self.extract_iocs(logs[0])
        all_log_ids = [logs[0].log_id]
        max_score = logs[0].threat_score

        for log in logs[1:]:
            ioc = self.extract_iocs(log)
            all_iocs["ips"].extend(ioc["ips"])
            all_iocs["ports"].extend(ioc["ports"])
            all_log_ids.append(log.log_id)
            max_score = max(max_score, log.threat_score)

        first.log_ids = all_log_ids
        first.event_count = len(logs)
        first.score = round(min(max_score + 0.05 * (len(logs) - 1), 1.0), 3)
        first.iocs = list(set(all_iocs["ips"] + all_iocs["domains"]))[:20]
        first.source_ips = list(set(all_iocs["ips"]))[:10]
        first.last_seen = max(l.timestamp for l in logs)

        # Recalculate severity
        for bucket, threshold in self.SEVERITY_THRESHOLDS.items():
            if first.score >= threshold:
                first.severity = bucket
                break

        return first

    def _build_actions(self, threat_type: str, severity: str,
                        source_ips: List[str]) -> List[str]:
        actions = []
        ip_list = ", ".join(source_ips[:3]) or "unknown source"

        base_actions = {
            "port_scan": [
                f"Block source IP(s): {ip_list} at perimeter firewall.",
                "Enable IPS signature for reconnaissance activity.",
                "Review open ports and disable unnecessary services.",
            ],
            "brute_force": [
                f"Immediately block {ip_list} at firewall.",
                "Enforce multi-factor authentication on all remote access.",
                "Audit user account lockout policies.",
                "Alert SOC and review authentication logs for compromise.",
            ],
            "dos_attack": [
                "Activate upstream DDoS scrubbing if available.",
                f"Rate-limit traffic from {ip_list}.",
                "Enable SYN cookies / connection rate limiting.",
            ],
            "dns_amplification": [
                "Restrict DNS ANY query responses.",
                "Implement DNS rate limiting (RRL).",
                "Verify resolver is not open to the internet.",
            ],
            "unauthorized": [
                "Revoke potentially compromised credentials immediately.",
                "Audit privilege escalation paths and sudo rules.",
                "Review authentication logs for successful breaches.",
            ],
        }

        actions = base_actions.get(threat_type, [
            "Investigate and contain the incident.",
            "Review related logs for additional context.",
        ])

        if severity == "CRITICAL":
            actions.insert(0, "🚨 CRITICAL: Engage incident response team immediately.")

        return actions

    # ── Summary ───────────────────────────────────────────────

    def get_threat_summary(self, threats: List[SecurityThreat]) -> Dict:
        """Return a summary dict suitable for dashboards and reports."""
        by_type = {}
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for t in threats:
            by_type[t.threat_type] = by_type.get(t.threat_type, 0) + 1
            by_severity[t.severity] = by_severity.get(t.severity, 0) + 1

        return {
            "total_threats": len(threats),
            "by_type": by_type,
            "by_severity": by_severity,
            "top_source_ips": self._top_ips(threats),
            "active_incidents": len([t for t in threats if t.is_active]),
        }

    @staticmethod
    def _top_ips(threats: List[SecurityThreat], n: int = 10) -> List[Dict]:
        from collections import Counter
        all_ips = [ip for t in threats for ip in t.source_ips]
        return [{"ip": ip, "count": cnt} for ip, cnt in Counter(all_ips).most_common(n)]
