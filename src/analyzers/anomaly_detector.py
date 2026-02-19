"""
Anomaly Detection Module
========================
ML-powered detection of anomalous network behaviour using Isolation Forest
and statistical baseline methods. Provides real-time scoring and alerts.
"""

import logging
import os
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.classifiers.log_classifier import ClassifiedLog

logger = logging.getLogger(__name__)

# ─── Anomaly Result ──────────────────────────────────────────────────────────

@dataclass
class AnomalyResult:
    log_id: str
    timestamp: str
    source: str
    anomaly_score: float          # 0-1, higher = more anomalous
    is_anomaly: bool
    anomaly_type: str             # metric | frequency | pattern | combined
    contributing_factors: List[str] = field(default_factory=list)
    baseline_deviation: float = 0.0
    severity_upgrade: bool = False  # Did we escalate severity due to anomaly?

    def to_dict(self) -> Dict:
        return self.__dict__


# ─── Statistical Baseline ────────────────────────────────────────────────────

class BaselineTracker:
    """
    Maintains rolling statistical baselines (mean, std) per source device
    and per metric. Computes z-score deviations to flag statistical outliers.
    """

    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        # { source -> { metric -> deque of values } }
        self._windows: Dict[str, Dict[str, Deque]] = {}

    def update(self, source: str, metrics: Dict[str, float]):
        if source not in self._windows:
            self._windows[source] = {}
        for metric, value in metrics.items():
            if metric not in self._windows[source]:
                self._windows[source][metric] = deque(maxlen=self.window_size)
            self._windows[source][metric].append(value)

    def z_score(self, source: str, metric: str, value: float) -> float:
        """Return z-score for a metric value against the rolling baseline."""
        data = self._windows.get(source, {}).get(metric)
        if not data or len(data) < 10:
            return 0.0
        arr = np.array(data)
        mean, std = arr.mean(), arr.std()
        if std < 1e-6:
            return 0.0
        return abs((value - mean) / std)

    def get_baseline(self, source: str) -> Dict[str, Tuple[float, float]]:
        """Return {metric: (mean, std)} for all tracked metrics of a source."""
        result = {}
        for metric, vals in self._windows.get(source, {}).items():
            arr = np.array(vals)
            result[metric] = (float(arr.mean()), float(arr.std()))
        return result


# ─── Frequency Tracker ───────────────────────────────────────────────────────

class FrequencyTracker:
    """
    Tracks log frequency per source and per category in sliding time windows.
    Detects burst events (sudden spike in log volume).
    """

    def __init__(self, window_minutes: int = 5, burst_multiplier: float = 3.0):
        self.window_seconds = window_minutes * 60
        self.burst_multiplier = burst_multiplier
        # { key -> list of unix timestamps }
        self._timestamps: Dict[str, list] = {}

    def record(self, key: str, ts: Optional[float] = None):
        now = ts or datetime.now(timezone.utc).timestamp()
        if key not in self._timestamps:
            self._timestamps[key] = []
        self._timestamps[key].append(now)
        # Prune old entries
        cutoff = now - self.window_seconds * 6  # Keep 6 windows for baseline
        self._timestamps[key] = [t for t in self._timestamps[key] if t > cutoff]

    def rate_in_window(self, key: str, ts: Optional[float] = None) -> float:
        """Events per minute in the most recent window."""
        now = ts or datetime.now(timezone.utc).timestamp()
        cutoff = now - self.window_seconds
        recent = [t for t in self._timestamps.get(key, []) if t > cutoff]
        return len(recent) / (self.window_seconds / 60)

    def is_burst(self, key: str, ts: Optional[float] = None) -> Tuple[bool, float]:
        """
        Compare current-window rate to historical baseline.
        Returns (is_burst, burst_ratio).
        """
        now = ts or datetime.now(timezone.utc).timestamp()
        all_ts = self._timestamps.get(key, [])
        if len(all_ts) < 5:
            return False, 1.0

        # Current window
        cutoff_now = now - self.window_seconds
        current = len([t for t in all_ts if t > cutoff_now])

        # Historical (previous 5 windows)
        historic_counts = []
        for i in range(1, 6):
            start = now - self.window_seconds * (i + 1)
            end = now - self.window_seconds * i
            historic_counts.append(len([t for t in all_ts if start < t <= end]))

        baseline = np.mean(historic_counts) if historic_counts else 0
        if baseline < 1:
            baseline = 1.0

        ratio = current / baseline
        return ratio >= self.burst_multiplier, round(ratio, 2)
