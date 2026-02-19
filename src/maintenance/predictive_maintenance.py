"""
Predictive Maintenance Module
==============================
Uses time-series feature engineering and gradient boosting to predict
network failures before they occur. Generates proactive maintenance alerts
with risk scores and recommended remediation windows.
"""

import logging
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from src.classifiers.log_classifier import ClassifiedLog

logger = logging.getLogger(__name__)


# ─── Maintenance Alert ───────────────────────────────────────────────────────

@dataclass
class MaintenanceAlert:
    alert_id: str
    device: str
    failure_probability: float       # 0-1
    predicted_failure_type: str      # interface_down | hardware_failure | routing_instability
    time_horizon_hours: int
    confidence: float
    risk_level: str                  # LOW | MEDIUM | HIGH | CRITICAL
    contributing_signals: List[str]
    recommended_actions: List[str]
    maintenance_window: str          # Suggested time to perform maintenance
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict:
        return self.__dict__


# ─── Device Health Tracker ───────────────────────────────────────────────────

class DeviceHealthTracker:
    """
    Maintains a rolling window of health indicators per device.
    Computes trend slopes and rates-of-change for predictive features.
    """

    def __init__(self, window_size: int = 50):
        self.window_size = window_size
        # { device -> { signal -> [values] } }
        self._history: Dict[str, Dict[str, List[float]]] = defaultdict(
            lambda: defaultdict(list))

    def record(self, device: str, metrics: Dict[str, float],
               severity_num: float, error_count: float):
        h = self._history[device]
        for key, val in metrics.items():
            h[key].append(float(val))
            if len(h[key]) > self.window_size:
                h[key] = h[key][-self.window_size:]
        h["severity_num"].append(severity_num)
        h["error_count"].append(error_count)
        if len(h["severity_num"]) > self.window_size:
            h["severity_num"] = h["severity_num"][-self.window_size:]
        if len(h["error_count"]) > self.window_size:
            h["error_count"] = h["error_count"][-self.window_size:]

    def get_features(self, device: str) -> Optional[np.ndarray]:
        """
        Return a fixed-length feature vector for the device.
        Returns None if insufficient history.
        """
        h = self._history.get(device, {})
        min_samples = 5
        if len(h.get("cpu_usage", [])) < min_samples:
            return None

        def stats(key: str) -> Tuple[float, float, float, float]:
            vals = h.get(key, [0.0])
            arr = np.array(vals, dtype=float)
            mean = float(arr.mean())
            std = float(arr.std()) if len(arr) > 1 else 0.0
            trend = float(np.polyfit(range(len(arr)), arr, 1)[0]) if len(arr) > 2 else 0.0
            last = float(arr[-1])
            return mean, std, trend, last

        cpu_m, cpu_s, cpu_t, cpu_l    = stats("cpu_usage")
        mem_m, mem_s, mem_t, mem_l    = stats("memory_usage")
        err_m, err_s, err_t, err_l    = stats("interface_errors")
        sev_m, _,     sev_t, sev_l    = stats("severity_num")
        cnt_m, _,     cnt_t, _        = stats("error_count")

        return np.array([
            cpu_m / 100, cpu_s / 100, cpu_t / 10, cpu_l / 100,
            mem_m / 100, mem_s / 100, mem_t / 10, mem_l / 100,
            err_m / 100, err_s / 100, err_t / 10, err_l / 100,
            sev_m / 7,   sev_t / 2,   sev_l / 7,
            cnt_m / 20,  cnt_t / 5,
        ], dtype=np.float32)

    def all_devices(self) -> List[str]:
        return list(self._history.keys())


# ─── Predictive Model ────────────────────────────────────────────────────────

class PredictiveMaintenanceModel:
    """
    Gradient Boosting classifier predicting imminent device failures.
    Trained on sequences of health metrics labelled with failure outcomes.
    """

    def __init__(self, model_path: str = "models/predictive_model.pkl"):
        self.model_path = model_path
        self.model: Optional[GradientBoostingClassifier] = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self._load()

    def _load(self):
        if os.path.exists(self.model_path):
            try:
                saved = joblib.load(self.model_path)
                self.model = saved["model"]
                self.scaler = saved["scaler"]
                self.is_trained = True
                logger.info("Predictive model loaded from %s", self.model_path)
            except Exception as exc:
                logger.warning("Could not load predictive model: %s", exc)

    def _save(self):
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump({"model": self.model, "scaler": self.scaler}, self.model_path)

    def train(self, X: np.ndarray, y: np.ndarray) -> Dict:
        X_scaled = self.scaler.fit_transform(X)
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )
        self.model = GradientBoostingClassifier(
            n_estimators=150, max_depth=4, learning_rate=0.05,
            subsample=0.8, random_state=42
        )
        self.model.fit(X_train, y_train)
        y_pred = self.model.predict(X_test)
        report = classification_report(y_test, y_pred,
                                        target_names=["normal", "pre-failure"],
                                        output_dict=True)
        self.is_trained = True
        self._save()
        return {"report": report}

    def predict_proba(self, features: np.ndarray) -> float:
        """Return probability of failure (class=1)."""
        if not self.is_trained or self.model is None:
            return 0.0
        feat_scaled = self.scaler.transform(features.reshape(1, -1))
        probs = self.model.predict_proba(feat_scaled)[0]
        return float(probs[1])  # P(failure)


# ─── Predictive Maintenance Engine ───────────────────────────────────────────

class PredictiveMaintenanceEngine:
    """
    High-level engine: ingests logs, updates device health, generates alerts.
    """

    FAILURE_TYPES = {
        "interface": ("interface_down", "Interface failure"),
        "hardware":  ("hardware_failure", "Hardware failure (CPU/memory)"),
        "routing":   ("routing_instability", "Routing protocol instability"),
    }

    RISK_LEVELS = [
        (0.85, "CRITICAL"),
        (0.65, "HIGH"),
        (0.40, "MEDIUM"),
        (0.0,  "LOW"),
    ]

    def __init__(self, config: Optional[Dict] = None):
        cfg = config or {}
        self.horizon_hours: int = cfg.get("prediction_horizon_hours", 24)
        self.confidence_threshold: float = cfg.get("confidence_threshold", 0.70)
        self.model = PredictiveMaintenanceModel(
            model_path=cfg.get("model_path", "models/predictive_model.pkl")
        )
        self.tracker = DeviceHealthTracker()

    def ingest_logs(self, logs: List[ClassifiedLog]):
        """Update device health tracker with new log data."""
        sev_map = {"DEBUG": 0, "INFO": 1, "WARNING": 3, "ERROR": 4, "CRITICAL": 5}
        for log in logs:
            sev = sev_map.get(log.severity.upper(), 1)
            self.tracker.record(
                device=log.source,
                metrics=log.metrics or {},
                severity_num=float(sev),
                error_count=float((log.metrics or {}).get("interface_errors", 0)),
            )

    def generate_alerts(self) -> List[MaintenanceAlert]:
        """
        Score all tracked devices and return alerts for those
        above the confidence threshold.
        """
        alerts = []
        for device in self.tracker.all_devices():
            features = self.tracker.get_features(device)
            if features is None:
                continue

            prob = self.model.predict_proba(features) if self.model.is_trained \
                else self._heuristic_score(features)

            if prob < self.confidence_threshold:
                continue

            risk_level = self._risk_level(prob)
            failure_type, failure_desc = self._predict_failure_type(device, features)
            signals = self._contributing_signals(device, features)
            actions = self._maintenance_actions(failure_type, risk_level)
            window = self._suggest_maintenance_window(risk_level)

            alert = MaintenanceAlert(
                alert_id=f"MAINT-{abs(hash(device + failure_type)) % 100000:05d}",
                device=device,
                failure_probability=round(prob, 3),
                predicted_failure_type=failure_type,
                time_horizon_hours=self.horizon_hours,
                confidence=round(prob, 3),
                risk_level=risk_level,
                contributing_signals=signals,
                recommended_actions=actions,
                maintenance_window=window,
            )
            alerts.append(alert)
            logger.info("Maintenance alert: %s | device=%s | risk=%s | prob=%.2f",
                        alert.alert_id, device, risk_level, prob)

        alerts.sort(key=lambda a: a.failure_probability, reverse=True)
        return alerts

    def _heuristic_score(self, features: np.ndarray) -> float:
        """Rule-based fallback score when ML model is not trained."""
        # features[3]=cpu_last, features[7]=mem_last, features[10]=err_trend
        cpu_last  = float(features[3])   # normalised 0-1
        mem_last  = float(features[7])
        err_trend = float(features[10])
        sev_last  = float(features[14]) if len(features) > 14 else 0.0

        score = (cpu_last * 0.3 + mem_last * 0.3
                 + min(abs(err_trend), 1.0) * 0.2
                 + sev_last * 0.2)
        return float(np.clip(score, 0.0, 1.0))

    def _risk_level(self, prob: float) -> str:
        for threshold, level in self.RISK_LEVELS:
            if prob >= threshold:
                return level
        return "LOW"

    def _predict_failure_type(self, device: str,
                               features: np.ndarray) -> Tuple[str, str]:
        err_trend = float(features[10]) if len(features) > 10 else 0
        cpu_last  = float(features[3])  if len(features) > 3  else 0
        mem_last  = float(features[7])  if len(features) > 7  else 0

        if err_trend > 0.05 or err_trend < -0.05:
            return self.FAILURE_TYPES["interface"]
        if cpu_last > 0.80 or mem_last > 0.85:
            return self.FAILURE_TYPES["hardware"]
        return self.FAILURE_TYPES["routing"]

    def _contributing_signals(self, device: str,
                               features: np.ndarray) -> List[str]:
        signals = []
        cpu_mean,_,cpu_trend,cpu_last = features[0:4]
        mem_mean,_,mem_trend,mem_last = features[4:8]
        err_mean,_,err_trend,err_last = features[8:12]

        if cpu_last > 0.75:
            signals.append(f"CPU at {cpu_last*100:.0f}% (mean {cpu_mean*100:.0f}%)")
        if cpu_trend > 0.02:
            signals.append(f"CPU increasing at +{cpu_trend*100:.1f}%/sample")
        if mem_last > 0.80:
            signals.append(f"Memory at {mem_last*100:.0f}% (mean {mem_mean*100:.0f}%)")
        if err_last > 0.05:
            signals.append(f"Interface errors at {err_last*100:.0f}/sample")
        if err_trend > 0.01:
            signals.append(f"Error count trending up (+{err_trend*100:.1f}/sample)")
        if not signals:
            signals.append("Cumulative metric degradation pattern detected")
        return signals

    def _maintenance_actions(self, failure_type: str, risk: str) -> List[str]:
        actions_map = {
            "interface_down": [
                "Schedule cable/SFP inspection during low-traffic window.",
                "Verify interface error counters and clean physical connections.",
                "Prepare standby interface or failover path.",
            ],
            "hardware_failure": [
                "Identify and terminate unnecessary high-CPU processes.",
                "Review memory allocation; consider module replacement.",
                "Schedule controlled reload in next maintenance window.",
                "Ensure redundant hardware is available.",
            ],
            "routing_instability": [
                "Review routing protocol timers and authentication.",
                "Check for configuration drift against baseline.",
                "Verify route table consistency across peer devices.",
            ],
        }
        actions = list(actions_map.get(failure_type, ["Review device health metrics."]))
        if risk == "CRITICAL":
            actions.insert(0, "⚠️ URGENT: Schedule maintenance within 4 hours.")
        elif risk == "HIGH":
            actions.insert(0, "Schedule maintenance within next 24 hours.")
        return actions

    @staticmethod
    def _suggest_maintenance_window(risk: str) -> str:
        now = datetime.now(timezone.utc)
        if risk == "CRITICAL":
            window = now + timedelta(hours=4)
            return f"Within 4 hours (by {window.strftime('%Y-%m-%d %H:%M UTC')})"
        elif risk == "HIGH":
            # Next 2am–4am
            window = now.replace(hour=2, minute=0) + timedelta(days=1)
            return f"Next maintenance window: {window.strftime('%Y-%m-%d 02:00-04:00 UTC')}"
        else:
            window = now + timedelta(days=7)
            return f"Routine maintenance before {window.strftime('%Y-%m-%d UTC')}"
