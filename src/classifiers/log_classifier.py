"""
Log Classifier Module
=====================
AI-powered log classification by description, version, and impacted components.
Uses a Random Forest classifier trained on feature-engineered log data.
Provides both supervised (ML) and rule-based fallback classification.
"""

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score

from src.collectors.log_collector import RawLog

logger = logging.getLogger(__name__)


# ─── Classified Log ──────────────────────────────────────────────────────────

@dataclass
class ClassifiedLog:
    """A log entry enriched with ML classification results."""
    log_id: str
    timestamp: str
    source: str
    source_ip: str
    platform: str
    raw_message: str
    description: str
    metrics: Dict

    # Classification results
    category: str = "UNKNOWN"          # BGP, OSPF, SECURITY, HARDWARE, etc.
    subcategory: str = ""              # More granular label
    severity: str = "INFO"
    impacted_components: List[str] = field(default_factory=list)
    version: str = ""
    classification_confidence: float = 0.0
    classification_method: str = "rule"  # 'ml' | 'rule' | 'hybrid'
    is_anomaly: bool = False
    anomaly_score: float = 0.0
    security_threat: bool = False
    threat_type: str = ""
    threat_score: float = 0.0
    recommended_action: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return self.__dict__


# ─── Feature Engineer ────────────────────────────────────────────────────────

class LogFeatureEngineer:
    """
    Transforms raw log text into numerical features for ML models.
    Extracts keywords, severity indicators, component names, and metric ratios.
    """

    SEVERITY_KEYWORDS = {
        "CRITICAL": ["critical", "crash", "fatal", "emergency", "down", "failed", "failure"],
        "ERROR":    ["error", "err", "fault", "unreachable", "timeout", "reset"],
        "WARNING":  ["warning", "warn", "high", "degraded", "slow", "delay"],
        "INFO":     ["up", "established", "connected", "success", "normal", "restored"],
    }

    COMPONENT_KEYWORDS = {
        "BGP":       ["bgp", "neighbor", "as-path", "route-reflector", "ibgp", "ebgp"],
        "OSPF":      ["ospf", "adjacency", "lsa", "spf", "area", "dr/bdr"],
        "STP":       ["stp", "rstp", "mstp", "topology change", "bpdu", "root bridge"],
        "INTERFACE": ["interface", "link", "port", "ethernet", "gigabit", "tengig",
                      "physical", "duplex", "bandwidth"],
        "SECURITY":  ["firewall", "acl", "asa", "ids", "scan", "intrusion",
                      "brute force", "attack", "exploit", "vulnerability"],
        "HARDWARE":  ["cpu", "memory", "temperature", "fan", "power", "hardware",
                      "chassis", "module", "linecard"],
        "QOS":       ["qos", "queue", "traffic shaping", "policing", "dscp", "cos"],
        "DNS":       ["dns", "query", "resolver", "zone", "nxdomain", "servfail"],
        "DHCP":      ["dhcp", "lease", "discover", "offer", "request", "ack"],
        "VPN":       ["vpn", "ipsec", "tunnel", "ikev2", "esp", "crypto"],
    }

    THREAT_PATTERNS = {
        "port_scan":        re.compile(r"port.{0,20}scan|scan.{0,20}port", re.IGNORECASE),
        "brute_force":      re.compile(r"brute.?force|failed.login|auth.fail", re.IGNORECASE),
        "dos_attack":       re.compile(r"dos|flood|syn.flood|icmp.flood", re.IGNORECASE),
        "dns_amplification":re.compile(r"dns.amp|amplification|dns.flood", re.IGNORECASE),
        "unauthorized":     re.compile(r"unauthorized|permission.denied|privilege", re.IGNORECASE),
    }

    def extract_features(self, log: RawLog) -> Dict:
        """Return a flat feature dictionary for a single log."""
        text = f"{log.description} {log.raw_message}".lower()
        features = {}

        # Severity encoding
        sev_map = {"DEBUG": 0, "INFO": 1, "NOTICE": 2,
                   "WARNING": 3, "ERROR": 4, "CRITICAL": 5, "ALERT": 6, "EMERGENCY": 7}
        features["severity_num"] = sev_map.get(log.severity.upper(), 1)

        # Keyword hits per component
        for comp, keywords in self.COMPONENT_KEYWORDS.items():
            features[f"kw_{comp.lower()}"] = sum(1 for kw in keywords if kw in text)

        # Severity keyword hits
        for sev, keywords in self.SEVERITY_KEYWORDS.items():
            features[f"sev_{sev.lower()}"] = sum(1 for kw in keywords if kw in text)

        # Threat pattern hits
        for threat, pattern in self.THREAT_PATTERNS.items():
            features[f"threat_{threat}"] = 1 if pattern.search(text) else 0

        # Metric features
        m = log.metrics or {}
        features["cpu_usage"]         = m.get("cpu_usage", 0) / 100.0
        features["memory_usage"]      = m.get("memory_usage", 0) / 100.0
        features["interface_errors"]  = min(m.get("interface_errors", 0), 100) / 100.0

        # Text length and special characters
        features["msg_length"]        = min(len(log.raw_message), 500) / 500.0
        features["has_ip_address"]    = 1 if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
                                                         text) else 0
        features["has_percent_code"]  = 1 if "%" in log.raw_message else 0
        features["has_port_number"]   = 1 if re.search(r":\d{2,5}\b", text) else 0

        return features

    def features_to_array(self, features: Dict) -> np.ndarray:
        """Convert feature dict to a consistent numpy array."""
        keys = sorted(features.keys())
        return np.array([features[k] for k in keys], dtype=np.float32)


# ─── Rule-Based Classifier (Fallback) ────────────────────────────────────────

class RuleBasedClassifier:
    """
    Pattern-matching classifier used as a fallback when ML model confidence
    is low or the model has not been trained yet.
    """

    RULES: List[Tuple[re.Pattern, str, str, str]] = [
        # (pattern, category, subcategory, recommended_action)
        (re.compile(r"%BGP|bgp.neighbor|hold.timer", re.I),
         "BGP", "neighbor_down", "Check BGP timers and verify peer reachability"),
        (re.compile(r"%OSPF|ospf.adjacency|lsa.flood", re.I),
         "OSPF", "adjacency_change", "Verify OSPF hello intervals and authentication"),
        (re.compile(r"%STP|topology.change|bpdu", re.I),
         "STP", "topology_change", "Investigate root bridge changes and rogue switches"),
        (re.compile(r"%LINK|interface.*down|link.down", re.I),
         "INTERFACE", "link_down", "Check physical layer: cable, SFP, remote interface state"),
        (re.compile(r"port.scan|scan.*port", re.I),
         "SECURITY", "port_scan", "Block source IP, review firewall ACLs"),
        (re.compile(r"brute.force|auth.*fail|failed.login", re.I),
         "SECURITY", "brute_force", "Enable account lockout, alert SOC team"),
        (re.compile(r"%CPU|cpu.utilization.*8[5-9]|cpu.utilization.*9\d", re.I),
         "HARDWARE", "high_cpu", "Identify high-CPU processes; consider load balancing"),
        (re.compile(r"%MEMORY|memory.alert|memory.*9[0-9]%", re.I),
         "HARDWARE", "high_memory", "Clear unused processes; consider hardware upgrade"),
        (re.compile(r"dns.*spike|dns.*amplification|dns.*flood", re.I),
         "DNS", "dns_amplification", "Enable DNS rate limiting; restrict ANY queries"),
        (re.compile(r"%QOS|packet.drop.*queue|voice.queue", re.I),
         "QOS", "queue_overflow", "Review QoS policy; increase voice queue bandwidth"),
        (re.compile(r"IDS|snort|intrusion|signature", re.I),
         "SECURITY", "ids_alert", "Review IDS alert; correlate with firewall logs"),
        (re.compile(r"vpn|ipsec|tunnel.*down|ikev2", re.I),
         "VPN", "tunnel_down", "Verify IKE proposals and check peer configuration"),
    ]

    def classify(self, log: RawLog) -> Tuple[str, str, float, str]:
        """Return (category, subcategory, confidence, recommended_action)."""
        text = f"{log.description} {log.raw_message}"
        for pattern, category, sub, action in self.RULES:
            if pattern.search(text):
                return category, sub, 0.85, action
        return "GENERAL", "informational", 0.50, "No immediate action required"


