"""
Pattern Recognition Module
==========================
Identifies recurring patterns, correlated events, and temporal sequences
in network logs. Detects root-cause cascades (e.g., interface down → BGP drop).
"""

import logging
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

import numpy as np

from src.classifiers.log_classifier import ClassifiedLog

logger = logging.getLogger(__name__)


@dataclass
class LogPattern:
    pattern_id: str
    description: str
    frequency: int
    sources: List[str]
    categories: List[str]
    first_seen: str
    last_seen: str
    severity: str
    is_recurring: bool
    correlation_chain: List[str] = field(default_factory=list)  # Causal chain
    impact_score: float = 0.0
    recommended_action: str = ""

    def to_dict(self) -> Dict:
        return self.__dict__


@dataclass
class CorrelationEvent:
    """Two or more logs that appear to share a root cause."""
    correlation_id: str
    root_event_id: str
    related_event_ids: List[str]
    root_cause_hypothesis: str
    confidence: float
    time_window_seconds: float
    affected_sources: List[str]

    def to_dict(self) -> Dict:
        return self.__dict__


class PatternRecognizer:
    """
    Analyzes a window of classified logs to find:
    - Recurring message patterns (template matching)
    - Cross-device correlated events (cascade detection)
    - Temporal sequences (event A always precedes event B)
    """

    # Known root-cause cascades (event_A_category → expected_effect_category)
    CASCADE_RULES: List[Tuple[str, str, str, float]] = [
        ("INTERFACE", "BGP",      "Interface failure causing BGP session drop",       0.90),
        ("INTERFACE", "OSPF",     "Interface failure causing OSPF adjacency loss",     0.88),
        ("HARDWARE",  "INTERFACE","High CPU/memory degrading interface performance",   0.75),
        ("HARDWARE",  "BGP",      "Hardware stress destabilising routing protocols",   0.70),
        ("SECURITY",  "HARDWARE", "Security attack causing resource exhaustion",       0.80),
        ("DNS",       "SECURITY", "DNS anomaly indicating potential DDoS",             0.72),
    ]

    def __init__(self, config: Optional[Dict] = None):
        cfg = config or {}
        self.min_frequency = cfg.get("min_pattern_frequency", 3)
        self.time_window = cfg.get("time_window_minutes", 60) * 60   # → seconds
        self.similarity_threshold = cfg.get("similarity_threshold", 0.75)
        self._pattern_store: Dict[str, LogPattern] = {}

    # ── Template Extraction ───────────────────────────────────

    @staticmethod
    def _tokenize(text: str) -> str:
        """Replace variable fields (IPs, numbers, interface names) with tokens."""
        t = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP>", text)
        t = re.sub(r"\b[0-9a-f]{4,}\b", "<HEX>", t, flags=re.IGNORECASE)
        t = re.sub(r"(?:GigabitEthernet|TenGigE|Ethernet|Port-channel)[\d/]+",
                   "<IFACE>", t, flags=re.IGNORECASE)
        t = re.sub(r"\b\d+\b", "<NUM>", t)
        t = re.sub(r"\s+", " ", t).strip().lower()
        return t

    def find_patterns(self, logs: List[ClassifiedLog]) -> List[LogPattern]:
        """Find recurring message templates across a batch of logs."""
        template_groups: Dict[str, List[ClassifiedLog]] = defaultdict(list)

        for log in logs:
            template = self._tokenize(log.description)
            template_groups[template].append(log)

        patterns = []
        for template, group in template_groups.items():
            if len(group) < self.min_frequency:
                continue

            severities = [g.severity for g in group]
            # Severity = worst in group
            sev_order = ["DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL"]
            worst_sev = max(severities,
                            key=lambda s: sev_order.index(s) if s in sev_order else 0)

            pattern = LogPattern(
                pattern_id=f"PAT-{abs(hash(template)) % 100000:05d}",
                description=template[:150],
                frequency=len(group),
                sources=list({g.source for g in group}),
                categories=list({g.category for g in group}),
                first_seen=min(g.timestamp for g in group),
                last_seen=max(g.timestamp for g in group),
                severity=worst_sev,
                is_recurring=True,
                impact_score=self._calc_impact(group),
                recommended_action=self._pattern_action(group),
            )
            patterns.append(pattern)
            self._pattern_store[pattern.pattern_id] = pattern

        patterns.sort(key=lambda p: (p.frequency, p.impact_score), reverse=True)
        logger.info("Found %d patterns (threshold=%d)", len(patterns), self.min_frequency)
        return patterns

    # ── Cascade Correlation ───────────────────────────────────

    def find_correlations(self, logs: List[ClassifiedLog]) -> List[CorrelationEvent]:
        """Detect root-cause cascade events within the time window."""
        correlations = []
        # Sort chronologically
        sorted_logs = sorted(logs, key=lambda l: l.timestamp)

        for i, root_log in enumerate(sorted_logs):
            root_ts = self._parse_ts(root_log.timestamp)

            for cause_cat, effect_cat, hypothesis, confidence in self.CASCADE_RULES:
                if root_log.category != cause_cat:
                    continue

                # Find effect events after root event, within window
                related = []
                for j in range(i + 1, len(sorted_logs)):
                    effect_log = sorted_logs[j]
                    effect_ts = self._parse_ts(effect_log.timestamp)
                    delta = (effect_ts - root_ts).total_seconds()

                    if delta > self.time_window:
                        break

                    if effect_log.category == effect_cat and delta >= 0:
                        related.append(effect_log.log_id)

                if related:
                    corr_id = f"CORR-{abs(hash(root_log.log_id + effect_cat)) % 100000:05d}"
                    all_ids = [root_log.log_id] + related
                    correlations.append(CorrelationEvent(
                        correlation_id=corr_id,
                        root_event_id=root_log.log_id,
                        related_event_ids=related,
                        root_cause_hypothesis=hypothesis,
                        confidence=confidence,
                        time_window_seconds=self.time_window,
                        affected_sources=list({l.source for l in sorted_logs
                                               if l.log_id in all_ids}),
                    ))

        logger.info("Found %d correlation events", len(correlations))
        return correlations

    # ── Helpers ───────────────────────────────────────────────

    @staticmethod
    def _parse_ts(ts: str) -> datetime:
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc)

    @staticmethod
    def _calc_impact(logs: List[ClassifiedLog]) -> float:
        sev_weights = {"DEBUG": 0.1, "INFO": 0.2, "WARNING": 0.5,
                       "ERROR": 0.8, "CRITICAL": 1.0}
        scores = [sev_weights.get(l.severity.upper(), 0.2) for l in logs]
        return round(float(np.mean(scores)), 3) if scores else 0.0

    @staticmethod
    def _pattern_action(logs: List[ClassifiedLog]) -> str:
        categories = Counter(l.category for l in logs)
        top_cat, _ = categories.most_common(1)[0]
        actions = {
            "HARDWARE":  "Schedule maintenance; monitor resource trends for degradation.",
            "SECURITY":  "Escalate to SOC; review firewall rules and access controls.",
            "BGP":       "Monitor BGP stability; check peer AS health.",
            "INTERFACE": "Audit physical plant; check for intermittent hardware faults.",
        }
        return actions.get(top_cat, "Monitor the pattern; review logs for root cause.")
