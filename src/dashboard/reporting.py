"""
Dashboard & Reporting Module
=============================
Generates real-time network health dashboards, HTML reports, and structured
JSON summaries with actionable recommendations.
"""

import json
import logging
import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.classifiers.log_classifier import ClassifiedLog
from src.analyzers.anomaly_detector import AnomalyResult
from src.analyzers.security_analyzer import SecurityThreat
from src.analyzers.pattern_recognition import LogPattern
from src.maintenance.predictive_maintenance import MaintenanceAlert

logger = logging.getLogger(__name__)


# ─── Health Report ───────────────────────────────────────────────────────────

@dataclass
class NetworkHealthReport:
    report_id: str
    generated_at: str
    period_start: str
    period_end: str
    overall_health_score: float        # 0-100
    health_status: str                 # HEALTHY | DEGRADED | CRITICAL

    # Counts
    total_logs: int = 0
    total_anomalies: int = 0
    total_threats: int = 0
    total_patterns: int = 0
    maintenance_alerts: int = 0

    # Breakdowns
    logs_by_severity: Dict[str, int] = field(default_factory=dict)
    logs_by_category: Dict[str, int] = field(default_factory=dict)
    logs_by_device: Dict[str, int] = field(default_factory=dict)
    top_anomalous_devices: List[Dict] = field(default_factory=list)
    threat_summary: Dict = field(default_factory=dict)
    pattern_summary: List[Dict] = field(default_factory=list)
    maintenance_summary: List[Dict] = field(default_factory=list)

    # Actionable items
    critical_alerts: List[Dict] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "overall_health_score": self.overall_health_score,
            "health_status": self.health_status,
            "summary": {
                "total_logs": self.total_logs,
                "total_anomalies": self.total_anomalies,
                "total_threats": self.total_threats,
                "total_patterns": self.total_patterns,
                "maintenance_alerts": self.maintenance_alerts,
            },
            "logs_by_severity": self.logs_by_severity,
            "logs_by_category": self.logs_by_category,
            "logs_by_device": self.logs_by_device,
            "top_anomalous_devices": self.top_anomalous_devices,
            "threat_summary": self.threat_summary,
            "pattern_summary": self.pattern_summary,
            "maintenance_summary": self.maintenance_summary,
            "critical_alerts": self.critical_alerts,
            "recommendations": self.recommendations,
        }


# ─── Report Builder ──────────────────────────────────────────────────────────

class ReportBuilder:
    """Assembles NetworkHealthReport from analysis outputs."""

    def build(
        self,
        logs: List[ClassifiedLog],
        anomalies: List[AnomalyResult],
        threats: List[SecurityThreat],
        patterns: List[LogPattern],
        maintenance_alerts: List[MaintenanceAlert],
    ) -> NetworkHealthReport:

        now = datetime.now(timezone.utc).isoformat()
        period_start = min((l.timestamp for l in logs), default=now)
        period_end   = max((l.timestamp for l in logs), default=now)

        severity_counts = Counter(l.severity for l in logs)
        category_counts = Counter(l.category for l in logs)
        device_counts   = Counter(l.source for l in logs)

        # Anomalous device ranking
        anomaly_by_device: Dict[str, List[float]] = defaultdict(list)
        for a in anomalies:
            if a.is_anomaly:
                anomaly_by_device[a.source].append(a.anomaly_score)
        top_anomalous = sorted(
            [{"device": d, "anomaly_count": len(s), "avg_score": round(sum(s)/len(s), 3)}
             for d, s in anomaly_by_device.items()],
            key=lambda x: x["avg_score"], reverse=True
        )[:10]

        # Health score calculation
        health_score = self._calc_health_score(
            logs, anomalies, threats, maintenance_alerts)

        status = ("HEALTHY" if health_score >= 80
                  else "DEGRADED" if health_score >= 50
                  else "CRITICAL")

        # Critical alerts
        critical_alerts = []
        for threat in [t for t in threats if t.severity in ("CRITICAL", "HIGH")]:
            critical_alerts.append({
                "type": "SECURITY",
                "id": threat.threat_id,
                "description": threat.description[:150],
                "severity": threat.severity,
                "action": threat.recommended_actions[0] if threat.recommended_actions else "",
            })
        for alert in [a for a in maintenance_alerts if a.risk_level in ("CRITICAL", "HIGH")]:
            critical_alerts.append({
                "type": "MAINTENANCE",
                "id": alert.alert_id,
                "description": f"Predicted {alert.predicted_failure_type} on {alert.device}",
                "severity": alert.risk_level,
                "action": alert.recommended_actions[0] if alert.recommended_actions else "",
            })

        recommendations = self._generate_recommendations(
            logs, anomalies, threats, patterns, maintenance_alerts, health_score)

        return NetworkHealthReport(
            report_id=f"RPT-{abs(hash(now)) % 100000:05d}",
            generated_at=now,
            period_start=period_start,
            period_end=period_end,
            overall_health_score=round(health_score, 1),
            health_status=status,
            total_logs=len(logs),
            total_anomalies=sum(1 for a in anomalies if a.is_anomaly),
            total_threats=len(threats),
            total_patterns=len(patterns),
            maintenance_alerts=len(maintenance_alerts),
            logs_by_severity=dict(severity_counts),
            logs_by_category=dict(category_counts),
            logs_by_device=dict(device_counts.most_common(20)),
            top_anomalous_devices=top_anomalous,
            threat_summary=self._threat_summary(threats),
            pattern_summary=[{"id": p.pattern_id, "description": p.description[:100],
                               "frequency": p.frequency, "severity": p.severity}
                              for p in patterns[:5]],
            maintenance_summary=[{"device": a.device, "risk": a.risk_level,
                                   "type": a.predicted_failure_type,
                                   "probability": a.failure_probability}
                                  for a in maintenance_alerts[:10]],
            critical_alerts=critical_alerts[:20],
            recommendations=recommendations,
        )

    # ── Helpers ───────────────────────────────────────────────

    @staticmethod
    def _calc_health_score(logs, anomalies, threats, maintenance_alerts) -> float:
        score = 100.0
        # Deduct for anomalies
        anomaly_count = sum(1 for a in anomalies if a.is_anomaly)
        score -= min(anomaly_count * 3, 20)
        # Deduct for threats
        for t in threats:
            deduction = {"CRITICAL": 15, "HIGH": 10, "MEDIUM": 5, "LOW": 2}.get(t.severity, 2)
            score -= deduction
        # Deduct for maintenance alerts
        for a in maintenance_alerts:
            deduction = {"CRITICAL": 12, "HIGH": 8, "MEDIUM": 4, "LOW": 1}.get(a.risk_level, 1)
            score -= deduction
        # Deduct for critical/error severity logs
        critical_count = sum(1 for l in logs if l.severity in ("CRITICAL", "ERROR"))
        score -= min(critical_count * 0.5, 15)
        return max(0.0, min(100.0, score))

    @staticmethod
    def _threat_summary(threats: List[SecurityThreat]) -> Dict:
        by_type = Counter(t.threat_type for t in threats)
        by_sev  = Counter(t.severity for t in threats)
        return {
            "total": len(threats),
            "by_type": dict(by_type),
            "by_severity": dict(by_sev),
            "critical_count": by_sev.get("CRITICAL", 0),
        }

    @staticmethod
    def _generate_recommendations(logs, anomalies, threats, patterns,
                                   maintenance_alerts, health_score) -> List[str]:
        recs = []

        if health_score < 50:
            recs.append("🔴 Network health is CRITICAL. Immediate intervention required.")

        critical_threats = [t for t in threats if t.severity == "CRITICAL"]
        if critical_threats:
            recs.append(f"🔴 {len(critical_threats)} critical security threat(s) active. "
                        "Engage SOC team immediately.")

        critical_maint = [a for a in maintenance_alerts if a.risk_level == "CRITICAL"]
        if critical_maint:
            devices = ", ".join(a.device for a in critical_maint[:3])
            recs.append(f"⚠️ Imminent failure predicted for: {devices}. "
                        "Schedule emergency maintenance.")

        high_anomaly_devices = [a for a in anomalies if a.is_anomaly and a.anomaly_score > 0.80]
        if len(high_anomaly_devices) >= 3:
            recs.append(f"📊 {len(high_anomaly_devices)} devices showing high anomaly scores. "
                        "Investigate for systemic issues.")

        security_patterns = [p for p in patterns if "security" in p.categories]
        if security_patterns:
            recs.append(f"🔍 {len(security_patterns)} recurring security patterns detected. "
                        "Review firewall and access policies.")

        if not recs:
            recs.append("✅ Network operating within normal parameters. Continue monitoring.")

        return recs


# ─── HTML Report Generator ───────────────────────────────────────────────────

class HTMLReportGenerator:
    """Renders NetworkHealthReport as a self-contained HTML dashboard."""

    TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>INLAAS — Network Health Report {report_id}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #e2e8f0; }}
  .header {{ background: linear-gradient(135deg, #1e3a5f, #0f172a);
             padding: 2rem; border-bottom: 2px solid #3b82f6; }}
  .header h1 {{ font-size: 1.8rem; color: #60a5fa; letter-spacing: 1px; }}
  .header p  {{ color: #94a3b8; font-size: 0.9rem; margin-top: 0.3rem; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}
  .grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin: 1.5rem 0; }}
  .grid-2 {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; margin: 1.5rem 0; }}
  .card {{ background: #1e293b; border-radius: 12px; padding: 1.5rem;
           border: 1px solid #334155; }}
  .stat-card {{ text-align: center; }}
  .stat-card .num {{ font-size: 2.5rem; font-weight: 700; }}
  .stat-card .label {{ color: #94a3b8; font-size: 0.85rem; margin-top: 0.25rem; }}
  .blue {{ color: #60a5fa; }} .red {{ color: #f87171; }}
  .yellow {{ color: #fbbf24; }} .green {{ color: #4ade80; }}
  .health-badge {{ display: inline-block; padding: 0.5rem 1.5rem;
                   border-radius: 20px; font-weight: 700; font-size: 1.1rem; }}
  .HEALTHY  {{ background: #166534; color: #4ade80; }}
  .DEGRADED {{ background: #713f12; color: #fbbf24; }}
  .CRITICAL {{ background: #7f1d1d; color: #f87171; }}
  .score-bar {{ height: 12px; background: #334155; border-radius: 6px; overflow: hidden; margin-top: 0.5rem; }}
  .score-fill {{ height: 100%; border-radius: 6px;
                background: linear-gradient(90deg, #3b82f6, #60a5fa); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
  th {{ background: #1e3a5f; padding: 0.75rem 1rem; text-align: left;
        color: #93c5fd; border-bottom: 1px solid #334155; }}
  td {{ padding: 0.65rem 1rem; border-bottom: 1px solid #1e293b; }}
  tr:hover td {{ background: #1e293b; }}
  .badge {{ padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
  .sev-CRITICAL {{ background: #7f1d1d; color: #fca5a5; }}
  .sev-HIGH     {{ background: #78350f; color: #fcd34d; }}
  .sev-ERROR    {{ background: #7f1d1d; color: #fca5a5; }}
  .sev-MEDIUM   {{ background: #713f12; color: #fcd34d; }}
  .sev-WARNING  {{ background: #713f12; color: #fcd34d; }}
  .sev-LOW      {{ background: #1e3a5f; color: #93c5fd; }}
  .sev-INFO     {{ background: #1e3a5f; color: #93c5fd; }}
  .rec-item {{ padding: 0.75rem 1rem; background: #0f172a; border-radius: 8px;
               border-left: 3px solid #3b82f6; margin-bottom: 0.5rem;
               font-size: 0.9rem; line-height: 1.5; }}
  h2 {{ color: #93c5fd; font-size: 1.2rem; margin-bottom: 1rem; }}
  .footer {{ text-align: center; padding: 2rem; color: #475569; font-size: 0.8rem; }}
</style>
</head>
<body>
<div class="header">
  <div class="container">
    <h1>⚡ INLAAS — Intelligent Network Log Analysis System</h1>
    <p>Report ID: {report_id} &nbsp;|&nbsp; Generated: {generated_at}
       &nbsp;|&nbsp; Period: {period_start} → {period_end}</p>
  </div>
</div>

<div class="container">

  <!-- Health Score -->
  <div class="card" style="margin-bottom:1.5rem;">
    <div style="display:flex; align-items:center; gap:2rem;">
      <div>
        <h2>Network Health Status</h2>
        <span class="health-badge {health_status}">{health_status}</span>
      </div>
      <div style="flex:1">
        <div style="font-size:3rem;font-weight:700;color:#60a5fa;">{health_score}%</div>
        <div class="score-bar">
          <div class="score-fill" style="width:{health_score}%"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- Stats Grid -->
  <div class="grid-4">
    <div class="card stat-card"><div class="num blue">{total_logs}</div>
      <div class="label">Total Logs</div></div>
    <div class="card stat-card"><div class="num yellow">{total_anomalies}</div>
      <div class="label">Anomalies Detected</div></div>
    <div class="card stat-card"><div class="num red">{total_threats}</div>
      <div class="label">Security Threats</div></div>
    <div class="card stat-card"><div class="num green">{maintenance_alerts}</div>
      <div class="label">Maintenance Alerts</div></div>
  </div>

  <div class="grid-2">
    <!-- Recommendations -->
    <div class="card">
      <h2>🎯 Actionable Recommendations</h2>
      {recommendations_html}
    </div>

    <!-- Critical Alerts -->
    <div class="card">
      <h2>🚨 Critical Alerts</h2>
      {critical_alerts_html}
    </div>
  </div>

  <!-- Log Breakdown -->
  <div class="grid-2">
    <div class="card">
      <h2>📊 Logs by Category</h2>
      <table>
        <tr><th>Category</th><th>Count</th></tr>
        {category_rows}
      </table>
    </div>
    <div class="card">
      <h2>⚠️ Logs by Severity</h2>
      <table>
        <tr><th>Severity</th><th>Count</th></tr>
        {severity_rows}
      </table>
    </div>
  </div>

  <!-- Top Anomalous Devices -->
  <div class="card" style="margin-top:1rem;">
    <h2>🔍 Top Anomalous Devices</h2>
    <table>
      <tr><th>Device</th><th>Anomaly Count</th><th>Avg Score</th></tr>
      {anomaly_rows}
    </table>
  </div>

  <!-- Maintenance -->
  <div class="card" style="margin-top:1rem;">
    <h2>🔧 Predictive Maintenance Alerts</h2>
    <table>
      <tr><th>Device</th><th>Risk Level</th><th>Predicted Failure</th><th>Probability</th></tr>
      {maintenance_rows}
    </table>
  </div>

</div>
<div class="footer">
  INLAAS v1.0.0 — Intelligent Network Log Automation & Analysis System<br>
  Report generated automatically. For issues, contact the Network Engineering Team.
</div>
</body></html>"""

    def generate(self, report: NetworkHealthReport, output_path: str) -> str:
        def rec_html(recs):
            return "".join(f'<div class="rec-item">{r}</div>' for r in recs) \
                   or '<div class="rec-item">No recommendations at this time.</div>'

        def alert_html(alerts):
            if not alerts:
                return '<div class="rec-item">No critical alerts.</div>'
            rows = ""
            for a in alerts[:8]:
                sev_class = f"sev-{a.get('severity','INFO')}"
                rows += (f'<div class="rec-item">'
                         f'<span class="badge {sev_class}">{a.get("severity")}</span> '
                         f'<strong>{a.get("type")}</strong> — {a.get("description","")}<br>'
                         f'<small style="color:#94a3b8">↳ {a.get("action","")}</small></div>')
            return rows

        def table_rows(data: Dict) -> str:
            rows = ""
            for key, val in sorted(data.items(), key=lambda x: -x[1]):
                rows += f"<tr><td>{key}</td><td><strong>{val}</strong></td></tr>"
            return rows or "<tr><td colspan='2'>No data</td></tr>"

        def anomaly_rows(devices):
            if not devices:
                return "<tr><td colspan='3'>No anomalous devices detected.</td></tr>"
            rows = ""
            for d in devices[:10]:
                rows += (f"<tr><td>{d['device']}</td>"
                         f"<td>{d['anomaly_count']}</td>"
                         f"<td>{d['avg_score']:.3f}</td></tr>")
            return rows

        def maint_rows(alerts):
            if not alerts:
                return "<tr><td colspan='4'>No maintenance alerts.</td></tr>"
            rows = ""
            for a in alerts:
                sev_class = f"sev-{a.get('risk','LOW')}"
                rows += (f"<tr><td>{a['device']}</td>"
                         f"<td><span class='badge {sev_class}'>{a['risk']}</span></td>"
                         f"<td>{a['type']}</td>"
                         f"<td>{a['probability']:.1%}</td></tr>")
            return rows

        html = self.TEMPLATE.format(
            report_id=report.report_id,
            generated_at=report.generated_at[:19].replace("T", " "),
            period_start=report.period_start[:19].replace("T", " "),
            period_end=report.period_end[:19].replace("T", " "),
            health_status=report.health_status,
            health_score=report.overall_health_score,
            total_logs=report.total_logs,
            total_anomalies=report.total_anomalies,
            total_threats=report.total_threats,
            maintenance_alerts=report.maintenance_alerts,
            recommendations_html=rec_html(report.recommendations),
            critical_alerts_html=alert_html(report.critical_alerts),
            category_rows=table_rows(report.logs_by_category),
            severity_rows=table_rows(report.logs_by_severity),
            anomaly_rows=anomaly_rows(report.top_anomalous_devices),
            maintenance_rows=maint_rows(report.maintenance_summary),
        )

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html)

        logger.info("HTML report saved to %s", output_path)
        return output_path


# ─── Dashboard Controller ────────────────────────────────────────────────────

class DashboardController:
    """Orchestrates report generation across all output formats."""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.builder = ReportBuilder()
        self.html_gen = HTMLReportGenerator()
        self.output_dir = self.config.get("output_dir", "reports")

    def generate_report(
        self,
        logs: List[ClassifiedLog],
        anomalies: List[AnomalyResult],
        threats: List[SecurityThreat],
        patterns: List[LogPattern],
        maintenance_alerts: List[MaintenanceAlert],
        formats: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        """
        Generate report in one or more formats.
        Returns {format: output_path}.
        """
        formats = formats or ["json", "html"]
        report = self.builder.build(logs, anomalies, threats, patterns, maintenance_alerts)

        outputs = {}
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        if "json" in formats:
            path = os.path.join(self.output_dir, f"report_{ts}.json")
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w") as fh:
                json.dump(report.to_dict(), fh, indent=2, default=str)
            outputs["json"] = path
            logger.info("JSON report saved to %s", path)

        if "html" in formats:
            path = os.path.join(self.output_dir, f"report_{ts}.html")
            self.html_gen.generate(report, path)
            outputs["html"] = path

        return outputs
