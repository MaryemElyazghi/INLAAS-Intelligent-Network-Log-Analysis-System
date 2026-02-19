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

# ─── Isolation Forest Detector ───────────────────────────────────────────────

class IsolationForestDetector:
    """
    Trains an Isolation Forest on normal-operation log features.
    Scores new logs: scores close to -1 are anomalous, close to 1 are normal.
    """

    FEATURE_KEYS = [
        "cpu_usage", "memory_usage", "interface_errors",
        "severity_num", "has_ip_address",
    ]

    def __init__(self, model_path: str = "models/anomaly_detector.pkl",
                 contamination: float = 0.05):
        self.model_path = model_path
        self.contamination = contamination
        self.model: Optional[IsolationForest] = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self._load_model()

    def _load_model(self):
        if os.path.exists(self.model_path):
            try:
                saved = joblib.load(self.model_path)
                self.model = saved["model"]
                self.scaler = saved["scaler"]
                self.is_trained = True
                logger.info("Anomaly detector loaded from %s", self.model_path)
            except Exception as exc:
                logger.warning("Could not load anomaly model: %s", exc)

    def _save_model(self):
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump({"model": self.model, "scaler": self.scaler}, self.model_path)

    def _extract_features(self, log: ClassifiedLog) -> np.ndarray:
        sev_map = {"DEBUG": 0, "INFO": 1, "NOTICE": 2, "WARNING": 3,
                   "ERROR": 4, "CRITICAL": 5}
        m = log.metrics or {}
        return np.array([
            m.get("cpu_usage", 0) / 100.0,
            m.get("memory_usage", 0) / 100.0,
            min(m.get("interface_errors", 0), 100) / 100.0,
            sev_map.get(log.severity.upper(), 1) / 7.0,
            1.0 if log.source_ip else 0.0,
        ], dtype=np.float32)

    def fit(self, logs: List[ClassifiedLog]) -> Dict:
        X = np.array([self._extract_features(log) for log in logs])
        X_scaled = self.scaler.fit_transform(X)
        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)
        self.is_trained = True
        self._save_model()
        logger.info("Anomaly detector trained on %d samples.", len(logs))
        return {"n_samples": len(logs), "contamination": self.contamination}

    def score(self, log: ClassifiedLog) -> float:
        """
        Return anomaly score in [0, 1].
        Score > 0.65 → anomalous.
        """
        if not self.is_trained or self.model is None:
            return 0.0
        feat = self._extract_features(log).reshape(1, -1)
        feat_scaled = self.scaler.transform(feat)
        # decision_function: negative = anomalous
        raw = float(self.model.decision_function(feat_scaled)[0])
        # Normalize to [0,1]: raw ∈ [-0.5, 0.5] typically
        normalized = 1.0 - (raw + 0.5)
        return float(np.clip(normalized, 0.0, 1.0))


# ─── Orchestrated Anomaly Detector ───────────────────────────────────────────

class AnomalyDetector:
    """
    Combines Isolation Forest, statistical baselines, and frequency tracking
    into a unified anomaly scoring and alerting system.
    """

    ANOMALY_THRESHOLD = 0.65
    Z_SCORE_THRESHOLD = 2.5
    SECURITY_CATEGORIES = {"SECURITY", "IDS"}

    def __init__(self, config: Optional[Dict] = None):
        cfg = config or {}
        self.if_detector = IsolationForestDetector(
            model_path=cfg.get("model_path", "models/anomaly_detector.pkl"),
            contamination=cfg.get("contamination", 0.05),
        )
        self.baseline = BaselineTracker(window_size=cfg.get("window_size", 100))
        self.freq_tracker = FrequencyTracker()
        self.anomaly_threshold = cfg.get("anomaly_score_alert", self.ANOMALY_THRESHOLD)

    def train(self, logs: List[ClassifiedLog]) -> Dict:
        # Pre-populate baselines
        for log in logs:
            self.baseline.update(log.source, log.metrics or {})
        return self.if_detector.fit(logs)

    def analyze(self, log: ClassifiedLog) -> AnomalyResult:
        """Score a classified log for anomalous behaviour."""
        self.baseline.update(log.source, log.metrics or {})
        self.freq_tracker.record(log.source)
        self.freq_tracker.record(f"{log.source}:{log.category}")

        factors: List[str] = []
        scores: List[float] = []

        # ── 1. Isolation Forest score ────────────────────────
        ml_score = self.if_detector.score(log)
        scores.append(ml_score)
        if ml_score > self.anomaly_threshold:
            factors.append(f"ML anomaly score={ml_score:.2f}")

        # ── 2. Statistical metric deviation ──────────────────
        max_z = 0.0
        for metric, value in (log.metrics or {}).items():
            z = self.baseline.z_score(log.source, metric, value)
            max_z = max(max_z, z)
            if z > self.Z_SCORE_THRESHOLD:
                factors.append(f"{metric} z-score={z:.1f}σ (value={value})")
        if max_z > 0:
            scores.append(min(max_z / 5.0, 1.0))

        # ── 3. Frequency burst detection ─────────────────────
        is_burst, burst_ratio = self.freq_tracker.is_burst(log.source)
        if is_burst:
            factors.append(f"Log burst: {burst_ratio:.1f}x normal rate")
            scores.append(min(burst_ratio / 10.0, 1.0))

        # ── 4. Security category boost ───────────────────────
        if log.category in self.SECURITY_CATEGORIES:
            sev_boost = {"CRITICAL": 0.30, "ERROR": 0.15, "WARNING": 0.05}.get(
                log.severity.upper(), 0.0)
            if sev_boost:
                scores.append(sev_boost)
                factors.append(f"Security category severity boost (+{sev_boost:.0%})")

        # ── 5. Combined score ─────────────────────────────────
        combined_score = float(np.clip(np.mean(scores) if scores else 0.0, 0.0, 1.0))
        is_anomaly = combined_score >= self.anomaly_threshold

        # Determine anomaly type
        if is_anomaly:
            if ml_score > self.anomaly_threshold and max_z > self.Z_SCORE_THRESHOLD:
                atype = "combined"
            elif ml_score > self.anomaly_threshold:
                atype = "pattern"
            elif max_z > self.Z_SCORE_THRESHOLD:
                atype = "metric"
            elif is_burst:
                atype = "frequency"
            else:
                atype = "pattern"
        else:
            atype = "none"

        # Severity upgrade
        sev_upgrade = (is_anomaly and log.severity in ("INFO", "WARNING")
                       and combined_score > 0.80)

        return AnomalyResult(
            log_id=log.log_id,
            timestamp=log.timestamp,
            source=log.source,
            anomaly_score=round(combined_score, 3),
            is_anomaly=is_anomaly,
            anomaly_type=atype,
            contributing_factors=factors,
            baseline_deviation=round(max_z, 2),
            severity_upgrade=sev_upgrade,
        )

    def analyze_batch(self, logs: List[ClassifiedLog]) -> List[AnomalyResult]:
        return [self.analyze(log) for log in logs]

    def enrich_logs(self, logs: List[ClassifiedLog]) -> List[ClassifiedLog]:
        """In-place enrich ClassifiedLog objects with anomaly scores."""
        results = self.analyze_batch(logs)
        for log, result in zip(logs, results):
            log.is_anomaly = result.is_anomaly
            log.anomaly_score = result.anomaly_score
        return logs
