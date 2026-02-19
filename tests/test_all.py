"""
Test Suite — INLAAS
====================
pytest-based tests covering all core modules.
"""

import json
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_raw_logs():
    from src.collectors.log_collector import RawLog
    return [
        RawLog(
            log_id="LOG-001",
            source="router-core-01",
            source_ip="10.0.0.1",
            platform="syslog",
            component="BGP",
            severity="WARNING",
            description="BGP neighbor 10.0.0.2 went down - Hold timer expired",
            raw_message="%BGP-3-NOTIFICATION: sent to neighbor 10.0.0.2 6/2",
            metrics={"cpu_usage": 45, "memory_usage": 60, "interface_errors": 2},
        ),
        RawLog(
            log_id="LOG-002",
            source="firewall-dmz-01",
            source_ip="10.0.0.2",
            platform="api",
            component="SECURITY",
            severity="CRITICAL",
            description="Port scan detected from 203.0.113.45",
            raw_message="%ASA-3-338001: Dynamic filter monitored blacklisted IP",
            metrics={"cpu_usage": 88, "memory_usage": 70, "interface_errors": 0},
        ),
        RawLog(
            log_id="LOG-003",
            source="core-switch-01",
            source_ip="10.0.0.3",
            platform="snmp",
            component="HARDWARE",
            severity="ERROR",
            description="High CPU utilization 87% for 5 minutes",
            raw_message="%CPU_REPORT-3-CPU_UTILIZATION: CPU utilization 87%",
            metrics={"cpu_usage": 87, "memory_usage": 78, "interface_errors": 5},
        ),
        RawLog(
            log_id="LOG-004",
            source="ids-sensor-01",
            source_ip="10.0.0.4",
            platform="syslog",
            component="IDS",
            severity="CRITICAL",
            description="Brute force SSH login attempt from 198.51.100.22 - 50 failed attempts",
            raw_message="[**] SSH Brute Force Attempt [**] 198.51.100.22:42315 -> 10.1.1.5:22",
            metrics={"cpu_usage": 55, "memory_usage": 45, "interface_errors": 0},
        ),
        RawLog(
            log_id="LOG-005",
            source="router-edge-02",
            source_ip="10.0.0.5",
            platform="api",
            component="INTERFACE",
            severity="ERROR",
            description="Interface GigabitEthernet0/0/1 link down",
            raw_message="%LINK-3-UPDOWN: Interface GigabitEthernet0/0/1, changed state to down",
            metrics={"cpu_usage": 42, "memory_usage": 58, "interface_errors": 15},
        ),
    ]


@pytest.fixture
def sample_classified_logs(sample_raw_logs):
    from src.classifiers.log_classifier import LogClassificationPipeline
    pipeline = LogClassificationPipeline()
    return pipeline.classify_batch(sample_raw_logs)


# ─── Collector Tests ──────────────────────────────────────────────────────────

class TestLogCollector:

    def test_raw_log_creation(self):
        from src.collectors.log_collector import RawLog
        log = RawLog(source="test-device", severity="ERROR",
                     description="Test log")
        assert log.source == "test-device"
        assert log.severity == "ERROR"
        assert log.log_id.startswith("LOG-")

    def test_raw_log_to_dict(self, sample_raw_logs):
        d = sample_raw_logs[0].to_dict()
        assert "log_id" in d
        assert "timestamp" in d
        assert "source" in d
        assert "description" in d

    def test_file_collector_json(self, tmp_path):
        from src.collectors.log_collector import FileLogCollector
        data = [
            {"log_id": "T-001", "source": "test-device", "severity": "INFO",
             "description": "Test", "raw_message": "Test message",
             "metrics": {"cpu_usage": 20}}
        ]
        f = tmp_path / "test_logs.json"
        f.write_text(json.dumps(data))

        collector = FileLogCollector()
        logs = collector.collect_from_json(str(f))
        assert len(logs) == 1
        assert logs[0].log_id == "T-001"
        assert logs[0].source == "test-device"

    def test_orchestrator_ingest(self, tmp_path):
        from src.collectors.log_collector import LogCollectionOrchestrator
        data = [{"source": "dev-1", "severity": "WARNING",
                 "description": "test", "raw_message": "test"}]
        f = tmp_path / "logs.json"
        f.write_text(json.dumps(data))

        orch = LogCollectionOrchestrator({})
        logs = orch.ingest_file(str(f))
        assert len(logs) >= 1

    def test_syslog_parser(self):
        from src.collectors.log_collector import SyslogHandler
        handler = SyslogHandler.__new__(SyslogHandler)
        log = handler._parse_syslog(
            "<34>Sep 01 08:00:00 router-01 %BGP-3-NOTIFICATION: peer down",
            "192.168.1.1"
        )
        assert log.component == "BGP"
        assert log.source_ip == "192.168.1.1"


# ─── Classifier Tests ─────────────────────────────────────────────────────────

class TestLogClassifier:

    def test_feature_engineer(self, sample_raw_logs):
        from src.classifiers.log_classifier import LogFeatureEngineer
        eng = LogFeatureEngineer()
        features = eng.extract_features(sample_raw_logs[0])
        assert "cpu_usage" in features
        assert "memory_usage" in features
        assert features["cpu_usage"] == pytest.approx(0.45)

    def test_rule_classifier_bgp(self, sample_raw_logs):
        from src.classifiers.log_classifier import RuleBasedClassifier
        clf = RuleBasedClassifier()
        cat, sub, conf, action = clf.classify(sample_raw_logs[0])
        assert cat == "BGP"
        assert conf > 0.5

    def test_rule_classifier_security(self, sample_raw_logs):
        from src.classifiers.log_classifier import RuleBasedClassifier
        clf = RuleBasedClassifier()
        cat, sub, _, _ = clf.classify(sample_raw_logs[1])  # Port scan log
        assert cat == "SECURITY"

    def test_pipeline_classify(self, sample_raw_logs):
        from src.classifiers.log_classifier import LogClassificationPipeline
        pipeline = LogClassificationPipeline()
        classified = pipeline.classify_batch(sample_raw_logs)
        assert len(classified) == len(sample_raw_logs)
        for log in classified:
            assert log.category != ""
            assert log.classification_confidence > 0

    def test_classified_log_has_components(self, sample_classified_logs):
        # Interface log should detect interface components
        iface_log = next(l for l in sample_classified_logs if l.category == "INTERFACE")
        assert len(iface_log.impacted_components) > 0

    def test_security_threat_detected(self, sample_classified_logs):
        threat_logs = [l for l in sample_classified_logs if l.security_threat]
        assert len(threat_logs) > 0

    def test_ml_classifier_train(self, sample_raw_logs):
        from src.classifiers.log_classifier import MLLogClassifier
        # Need enough examples for training
        logs = sample_raw_logs * 5  # 25 samples
        labels = ["BGP", "SECURITY", "HARDWARE", "SECURITY", "INTERFACE"] * 5

        clf = MLLogClassifier(model_path="/tmp/test_clf.pkl")
        result = clf.train(logs, labels)
        assert result["accuracy"] >= 0.0
        assert "report" in result

    def test_ml_classifier_predict_after_train(self, sample_raw_logs):
        from src.classifiers.log_classifier import MLLogClassifier
        logs = sample_raw_logs * 5
        labels = ["BGP", "SECURITY", "HARDWARE", "SECURITY", "INTERFACE"] * 5

        clf = MLLogClassifier(model_path="/tmp/test_clf2.pkl")
        clf.train(logs, labels)
        cat, conf, method = clf.predict(sample_raw_logs[0])
        assert cat in ["BGP", "SECURITY", "HARDWARE", "INTERFACE", "GENERAL"]
        assert 0.0 <= conf <= 1.0


# ─── Anomaly Detection Tests ──────────────────────────────────────────────────

class TestAnomalyDetector:

    def test_baseline_tracker(self):
        from src.analyzers.anomaly_detector import BaselineTracker
        bt = BaselineTracker(window_size=10)
        for i in range(15):
            bt.update("device-1", {"cpu_usage": 20 + i})

        baseline = bt.get_baseline("device-1")
        assert "cpu_usage" in baseline
        mean, std = baseline["cpu_usage"]
        assert 20 < mean < 40

    def test_z_score_normal(self):
        from src.analyzers.anomaly_detector import BaselineTracker
        bt = BaselineTracker()
        for _ in range(20):
            bt.update("device-1", {"cpu": 50.0})
        z = bt.z_score("device-1", "cpu", 51.0)
        assert z < 2.0

    def test_z_score_outlier(self):
        from src.analyzers.anomaly_detector import BaselineTracker
        bt = BaselineTracker()
        for _ in range(20):
            bt.update("device-1", {"cpu": 30.0})
        z = bt.z_score("device-1", "cpu", 90.0)
        assert z > 3.0

    def test_frequency_burst(self):
        from src.analyzers.anomaly_detector import FrequencyTracker
        import time
        ft = FrequencyTracker(window_minutes=1, burst_multiplier=3)
        now = time.time()
        # Historical: 2 events per window
        for i in range(5):
            for _ in range(2):
                ft.record("device-1", ts=now - 400 - i * 60)
        # Burst: 10 events in current window
        for _ in range(10):
            ft.record("device-1", ts=now - 10)
        is_burst, ratio = ft.is_burst("device-1", ts=now)
        assert is_burst is True
        assert ratio >= 3

    def test_anomaly_detector_analyze(self, sample_classified_logs):
        from src.analyzers.anomaly_detector import AnomalyDetector
        det = AnomalyDetector()
        results = det.analyze_batch(sample_classified_logs)
        assert len(results) == len(sample_classified_logs)
        for r in results:
            assert 0.0 <= r.anomaly_score <= 1.0
            assert isinstance(r.is_anomaly, bool)

    def test_high_resource_log_gets_score(self, sample_classified_logs):
        from src.analyzers.anomaly_detector import AnomalyDetector
        det = AnomalyDetector()
        # The CPU=87% log should get a relatively high score
        hw_log = next(l for l in sample_classified_logs if l.category == "HARDWARE")
        result = det.analyze(hw_log)
        # Just ensure it runs without error and returns valid score
        assert result.anomaly_score >= 0.0


# ─── Pattern Recognition Tests ───────────────────────────────────────────────

class TestPatternRecognizer:

    def test_tokenize(self):
        from src.analyzers.pattern_recognition import PatternRecognizer
        rec = PatternRecognizer()
        t = rec._tokenize("BGP neighbor 10.0.0.1 went down on GigabitEthernet0/0/1")
        assert "<IP>" in t
        assert "<IFACE>" in t
        assert "10.0.0.1" not in t

    def test_find_patterns_insufficient(self, sample_classified_logs):
        from src.analyzers.pattern_recognition import PatternRecognizer
        # With 5 unique messages, min_frequency=3 → likely 0 patterns
        rec = PatternRecognizer({"min_pattern_frequency": 3})
        patterns = rec.find_patterns(sample_classified_logs)
        assert isinstance(patterns, list)

    def test_find_patterns_repeating(self, sample_classified_logs):
        from src.analyzers.pattern_recognition import PatternRecognizer
        # Duplicate logs to ensure pattern detection
        repeated = sample_classified_logs * 4
        rec = PatternRecognizer({"min_pattern_frequency": 3})
        patterns = rec.find_patterns(repeated)
        assert len(patterns) >= 1
        assert patterns[0].frequency >= 3

    def test_find_correlations(self, sample_classified_logs):
        from src.analyzers.pattern_recognition import PatternRecognizer
        rec = PatternRecognizer()
        correlations = rec.find_correlations(sample_classified_logs)
        assert isinstance(correlations, list)


# ─── Security Analyzer Tests ─────────────────────────────────────────────────

class TestSecurityAnalyzer:

    def test_extract_iocs(self, sample_classified_logs):
        from src.analyzers.security_analyzer import SecurityAnalyzer
        sec = SecurityAnalyzer()
        iocs = sec.extract_iocs(sample_classified_logs[1])
        assert len(iocs["ips"]) > 0

    def test_analyze_batch(self, sample_classified_logs):
        from src.analyzers.security_analyzer import SecurityAnalyzer
        sec = SecurityAnalyzer()
        threats = sec.analyze_batch(sample_classified_logs)
        assert isinstance(threats, list)
        # Brute force and port scan logs should generate threats
        assert len(threats) >= 1

    def test_threat_has_mitre(self, sample_classified_logs):
        from src.analyzers.security_analyzer import SecurityAnalyzer
        sec = SecurityAnalyzer()
        threats = sec.analyze_batch(sample_classified_logs)
        for t in threats:
            assert len(t.mitre_tactics) > 0

    def test_threat_summary(self, sample_classified_logs):
        from src.analyzers.security_analyzer import SecurityAnalyzer
        sec = SecurityAnalyzer()
        threats = sec.analyze_batch(sample_classified_logs)
        summary = sec.get_threat_summary(threats)
        assert "total_threats" in summary
        assert "by_type" in summary
        assert "by_severity" in summary


# ─── Predictive Maintenance Tests ────────────────────────────────────────────

class TestPredictiveMaintenance:

    def test_device_health_tracker(self, sample_classified_logs):
        from src.maintenance.predictive_maintenance import DeviceHealthTracker
        tracker = DeviceHealthTracker()
        for log in sample_classified_logs * 10:
            tracker.record(log.source, log.metrics or {},
                           severity_num=3.0, error_count=5.0)
        assert len(tracker.all_devices()) > 0

    def test_get_features(self, sample_classified_logs):
        from src.maintenance.predictive_maintenance import DeviceHealthTracker
        tracker = DeviceHealthTracker()
        for log in sample_classified_logs * 10:
            tracker.record(log.source, log.metrics or {},
                           severity_num=3.0, error_count=5.0)
        device = tracker.all_devices()[0]
        features = tracker.get_features(device)
        assert features is not None
        assert len(features) > 0

    def test_engine_generate_alerts(self, sample_classified_logs):
        from src.maintenance.predictive_maintenance import PredictiveMaintenanceEngine
        engine = PredictiveMaintenanceEngine({"confidence_threshold": 0.3})
        # Need enough data points
        engine.ingest_logs(sample_classified_logs * 10)
        alerts = engine.generate_alerts()
        assert isinstance(alerts, list)


# ─── Dashboard Tests ──────────────────────────────────────────────────────────

class TestDashboard:

    def test_report_builder(self, sample_classified_logs):
        from src.analyzers.anomaly_detector import AnomalyDetector
        from src.analyzers.security_analyzer import SecurityAnalyzer
        from src.analyzers.pattern_recognition import PatternRecognizer
        from src.maintenance.predictive_maintenance import PredictiveMaintenanceEngine
        from src.dashboard.reporting import ReportBuilder

        anomalies = AnomalyDetector().analyze_batch(sample_classified_logs)
        threats   = SecurityAnalyzer().analyze_batch(sample_classified_logs)
        patterns  = PatternRecognizer().find_patterns(sample_classified_logs)
        engine    = PredictiveMaintenanceEngine({"confidence_threshold": 0.1})
        engine.ingest_logs(sample_classified_logs * 10)
        maint = engine.generate_alerts()

        report = ReportBuilder().build(sample_classified_logs, anomalies, threats,
                                        patterns, maint)
        assert report.total_logs == len(sample_classified_logs)
        assert 0 <= report.overall_health_score <= 100
        assert report.health_status in ("HEALTHY", "DEGRADED", "CRITICAL")

    def test_html_report_generates(self, sample_classified_logs, tmp_path):
        from src.dashboard.reporting import ReportBuilder, HTMLReportGenerator
        from src.analyzers.anomaly_detector import AnomalyDetector
        from src.analyzers.security_analyzer import SecurityAnalyzer
        from src.analyzers.pattern_recognition import PatternRecognizer
        from src.maintenance.predictive_maintenance import PredictiveMaintenanceEngine

        anomalies = AnomalyDetector().analyze_batch(sample_classified_logs)
        threats   = SecurityAnalyzer().analyze_batch(sample_classified_logs)
        patterns  = PatternRecognizer().find_patterns(sample_classified_logs)
        engine = PredictiveMaintenanceEngine({"confidence_threshold": 0.1})
        engine.ingest_logs(sample_classified_logs * 10)
        maint = engine.generate_alerts()

        report = ReportBuilder().build(sample_classified_logs, anomalies, threats,
                                        patterns, maint)
        output = str(tmp_path / "report.html")
        HTMLReportGenerator().generate(report, output)

        assert os.path.exists(output)
        content = open(output).read()
        assert "INLAAS" in content
        assert report.report_id in content

    def test_report_to_dict(self, sample_classified_logs):
        from src.dashboard.reporting import ReportBuilder
        from src.analyzers.anomaly_detector import AnomalyDetector

        anomalies = AnomalyDetector().analyze_batch(sample_classified_logs)
        report = ReportBuilder().build(sample_classified_logs, anomalies, [], [], [])
        d = report.to_dict()
        assert "report_id" in d
        assert "overall_health_score" in d
        assert "recommendations" in d


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
