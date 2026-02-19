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


# ─── ML-Based Classifier ─────────────────────────────────────────────────────

class MLLogClassifier:
    """
    Random Forest classifier that learns to categorize network logs.
    Falls back to rule-based classifier when confidence is below threshold.
    """

    def __init__(self, model_path: str = "models/log_classifier.pkl",
                 confidence_threshold: float = 0.65):
        self.model_path = model_path
        self.confidence_threshold = confidence_threshold
        self.feature_engineer = LogFeatureEngineer()
        self.rule_classifier = RuleBasedClassifier()
        self.model: Optional[RandomForestClassifier] = None
        self.label_encoder = LabelEncoder()
        self.is_trained = False
        self._load_model()

    def _load_model(self):
        if os.path.exists(self.model_path):
            try:
                saved = joblib.load(self.model_path)
                self.model = saved["model"]
                self.label_encoder = saved["label_encoder"]
                self.is_trained = True
                logger.info("ML classifier loaded from %s", self.model_path)
            except Exception as exc:
                logger.warning("Could not load model: %s. Will use rule-based classifier.", exc)

    def _save_model(self):
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump({"model": self.model, "label_encoder": self.label_encoder},
                    self.model_path)
        logger.info("ML classifier saved to %s", self.model_path)

    def train(self, logs: List[RawLog], labels: List[str]) -> Dict:
        """
        Train (or retrain) the classifier on labeled examples.

        Args:
            logs:   List of RawLog objects
            labels: Ground-truth category labels (must align with logs)

        Returns:
            Dict with accuracy, cross-val scores, and full classification report
        """
        if len(logs) < 20:
            raise ValueError("Need at least 20 labeled examples to train.")

        logger.info("Training ML classifier on %d examples...", len(logs))

        X = np.array([self.feature_engineer.features_to_array(
            self.feature_engineer.extract_features(log)) for log in logs])
        y_enc = self.label_encoder.fit_transform(labels)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y_enc, test_size=0.2, random_state=42, stratify=y_enc
        )

        self.model = RandomForestClassifier(
            n_estimators=100, max_depth=10, min_samples_split=5,
            class_weight="balanced", random_state=42, n_jobs=-1
        )
        self.model.fit(X_train, y_train)

        y_pred = self.model.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        cv_scores = cross_val_score(self.model, X, y_enc, cv=5)
        report = classification_report(
            y_test, y_pred,
            target_names=self.label_encoder.classes_,
            output_dict=True,
        )

        self.is_trained = True
        self._save_model()

        logger.info("Training complete. Accuracy: %.3f | CV mean: %.3f±%.3f",
                    acc, cv_scores.mean(), cv_scores.std())

        return {
            "accuracy": acc,
            "cv_mean": cv_scores.mean(),
            "cv_std": cv_scores.std(),
            "report": report,
            "n_samples": len(logs),
            "classes": list(self.label_encoder.classes_),
        }

    def predict(self, log: RawLog) -> Tuple[str, float, str]:
        """
        Returns (category, confidence, method) for a single log.
        Uses ML if trained and confident; otherwise falls back to rules.
        """
        features = self.feature_engineer.extract_features(log)
        feat_arr = self.feature_engineer.features_to_array(features).reshape(1, -1)

        if self.is_trained and self.model is not None:
            probs = self.model.predict_proba(feat_arr)[0]
            best_idx = np.argmax(probs)
            confidence = float(probs[best_idx])
            category = self.label_encoder.inverse_transform([best_idx])[0]

            if confidence >= self.confidence_threshold:
                return category, confidence, "ml"

        # Fallback to rule-based
        category, _, confidence, _ = self.rule_classifier.classify(log)
        return category, confidence, "rule"

    def get_feature_importance(self) -> Optional[Dict[str, float]]:
        """Return feature importance scores if model is trained."""
        if not self.is_trained or self.model is None:
            return None
        eng = LogFeatureEngineer()
        dummy = RawLog()
        feat_keys = sorted(eng.extract_features(dummy).keys())
        importance = dict(zip(feat_keys, self.model.feature_importances_))
        return dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))


# ─── Full Classification Pipeline ────────────────────────────────────────────

class LogClassificationPipeline:
    """
    End-to-end pipeline: takes RawLog → ClassifiedLog.
    Handles component extraction, version parsing, threat detection,
    and recommended action generation.
    """

    def __init__(self, config: Optional[Dict] = None):
        cfg = config or {}
        self.ml_classifier = MLLogClassifier(
            model_path=cfg.get("model_path", "models/log_classifier.pkl"),
            confidence_threshold=cfg.get("confidence_threshold", 0.65),
        )
        self.feature_engineer = LogFeatureEngineer()
        self.rule_classifier = RuleBasedClassifier()

    def _extract_components(self, log: RawLog) -> List[str]:
        """Parse impacted components from raw log text."""
        text = f"{log.description} {log.raw_message}"
        components = []

        # Named interfaces
        iface_matches = re.findall(
            r"(?:GigabitEthernet|TenGigE|FastEthernet|Ethernet|Port-channel|Vlan)"
            r"[\d/]+",
            text, re.IGNORECASE
        )
        components.extend(set(iface_matches))

        # IP addresses
        ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        components.extend(set(ip_matches[:3]))  # Limit to 3 IPs

        # Protocol / service names
        for comp in LogFeatureEngineer.COMPONENT_KEYWORDS:
            if any(kw in text.lower() for kw in LogFeatureEngineer.COMPONENT_KEYWORDS[comp]):
                if comp not in components:
                    components.append(comp)

        return components[:10]  # Cap at 10

    def _extract_version(self, log: RawLog) -> str:
        """Extract OS/firmware version strings from the log."""
        if log.version:
            return log.version
        text = f"{log.description} {log.raw_message}"
        patterns = [
            r"IOS-XE\s[\d\.]+",
            r"NX-OS\s[\d\.]+",
            r"IOS\s[\d\.]+",
            r"ASA\s[\d\.]+",
            r"v[\d]+\.[\d]+\.[\d]+",
        ]
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return m.group(0)
        return "Unknown"

    def _detect_threat(self, log: RawLog, category: str) -> Tuple[bool, str, float]:
        """Return (is_threat, threat_type, threat_score)."""
        if category != "SECURITY":
            return False, "", 0.0

        text = f"{log.description} {log.raw_message}".lower()
        best_threat, best_score = "", 0.0

        for threat, pattern in LogFeatureEngineer.THREAT_PATTERNS.items():
            if pattern.search(text):
                # Base threat score from severity
                sev_scores = {"CRITICAL": 0.95, "ERROR": 0.80,
                              "WARNING": 0.65, "INFO": 0.40}
                score = sev_scores.get(log.severity.upper(), 0.60)
                # Boost for high resource usage
                if (log.metrics or {}).get("cpu_usage", 0) > 80:
                    score = min(score + 0.05, 1.0)
                if score > best_score:
                    best_score = score
                    best_threat = threat

        return bool(best_threat), best_threat, best_score

    def _get_action(self, category: str, subcategory: str,
                     severity: str, threat_type: str) -> str:
        """Map category + severity to a human-readable recommended action."""
        if threat_type:
            actions = {
                "port_scan":        "🔒 Block source IP immediately. Review ACLs and enable IPS.",
                "brute_force":      "🔒 Lockout source IP. Enforce MFA. Alert security team.",
                "dos_attack":       "🔒 Activate DDoS mitigation. Rate-limit traffic from source.",
                "dns_amplification":"🔒 Restrict DNS ANY queries. Implement DNS rate limiting.",
                "unauthorized":     "🔒 Audit privilege escalation attempts. Rotate credentials.",
            }
            return actions.get(threat_type, "🔒 Investigate and contain the security incident.")

        action_map = {
            "BGP":       "Verify BGP peer reachability and check routing table integrity.",
            "OSPF":      "Check OSPF hello intervals, authentication, and MTU mismatches.",
            "STP":       "Investigate topology change: look for rogue switches or BPDU storms.",
            "INTERFACE": "Check physical: cable integrity, SFP module, and remote port state.",
            "HARDWARE":  {
                "high_cpu":    "Identify top processes (show proc cpu); consider process restart.",
                "high_memory": "Identify memory consumers; plan maintenance window for reload.",
            },
            "QOS":       "Review QoS policies; increase bandwidth allocation for critical queues.",
            "DNS":       "Inspect DNS server logs; check for misconfigurations or attacks.",
            "VPN":       "Check IKE proposals, PSK/certificates, and IP routing to peer.",
            "GENERAL":   "Log recorded for baseline; no immediate action required.",
        }
        result = action_map.get(category, "Review log details and consult network runbook.")
        if isinstance(result, dict):
            result = result.get(subcategory, f"Investigate {category} issue.")
        return result

    def classify(self, log: RawLog) -> ClassifiedLog:
        """Transform a RawLog into a fully classified ClassifiedLog."""
        category, confidence, method = self.ml_classifier.predict(log)
        _, subcategory, _, _ = self.rule_classifier.classify(log)

        components = self._extract_components(log)
        version = self._extract_version(log)
        is_threat, threat_type, threat_score = self._detect_threat(log, category)
        action = self._get_action(category, subcategory, log.severity, threat_type)

        return ClassifiedLog(
            log_id=log.log_id,
            timestamp=log.timestamp,
            source=log.source,
            source_ip=log.source_ip,
            platform=log.platform,
            raw_message=log.raw_message,
            description=log.description,
            metrics=log.metrics,
            category=category,
            subcategory=subcategory,
            severity=log.severity,
            impacted_components=components,
            version=version,
            classification_confidence=round(confidence, 3),
            classification_method=method,
            is_anomaly=False,     # Set by AnomalyDetector later
            anomaly_score=0.0,
            security_threat=is_threat,
            threat_type=threat_type,
            threat_score=round(threat_score, 3),
            recommended_action=action,
            tags=log.tags,
        )

    def classify_batch(self, logs: List[RawLog]) -> List[ClassifiedLog]:
        """Classify a list of logs, returning ClassifiedLog objects."""
        return [self.classify(log) for log in logs]
