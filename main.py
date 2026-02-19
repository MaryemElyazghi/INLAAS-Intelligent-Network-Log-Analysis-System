#!/usr/bin/env python3
"""
INLAAS — Intelligent Network Log Automation & Analysis System
=============================================================
Main entry point. Supports three modes:
  analyze  — Run full analysis pipeline on a log file and generate a report
  api      — Start the REST API server
  demo     — Run the complete demo with sample data

Usage:
  python main.py analyze --input data/sample_logs.json
  python main.py api --port 8000
  python main.py demo
"""

import json
import logging
import os
import sys
from pathlib import Path

import yaml

# ─── Logging Setup ───────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("inlaas")


def load_config(path: str = "config/config.yaml") -> dict:
    if os.path.exists(path):
        with open(path) as fh:
            return yaml.safe_load(fh) or {}
    return {}


# ─── Demo Pipeline ───────────────────────────────────────────────────────────

def run_demo():
    """Run the full analysis pipeline on the bundled sample data."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    console = Console()

    console.print(Panel.fit(
        "[bold cyan]⚡ INLAAS — Intelligent Network Log Analysis System[/bold cyan]\n"
        "[dim]Demo Run — Sample Network Logs[/dim]",
        border_style="cyan",
    ))

    config = load_config()

    # ── 1. Collection ─────────────────────────────────────────
    console.print("\n[bold yellow]📥 Step 1: Collecting Logs[/bold yellow]")
    from src.collectors.log_collector import LogCollectionOrchestrator
    orchestrator = LogCollectionOrchestrator(config)
    raw_logs = orchestrator.ingest_file("data/sample_logs.json")
    console.print(f"  ✅ Collected [green]{len(raw_logs)}[/green] logs from sample file")

    # ── 2. Classification ─────────────────────────────────────
    console.print("\n[bold yellow]🤖 Step 2: AI Classification[/bold yellow]")
    from src.classifiers.log_classifier import LogClassificationPipeline
    pipeline = LogClassificationPipeline(config.get("ml", {}))
    classified_logs = pipeline.classify_batch(raw_logs)

    cat_table = Table(box=box.SIMPLE, show_header=True)
    cat_table.add_column("Log ID", style="cyan")
    cat_table.add_column("Source")
    cat_table.add_column("Category", style="yellow")
    cat_table.add_column("Severity", style="red")
    cat_table.add_column("Method", style="dim")
    cat_table.add_column("Confidence")

    for log in classified_logs:
        cat_table.add_row(
            log.log_id, log.source, log.category, log.severity,
            log.classification_method, f"{log.classification_confidence:.0%}"
        )
    console.print(cat_table)

    # ── 3. Anomaly Detection ──────────────────────────────────
    console.print("\n[bold yellow]🔍 Step 3: Anomaly Detection[/bold yellow]")
    from src.analyzers.anomaly_detector import AnomalyDetector
    anomaly_det = AnomalyDetector(config.get("ml", {}).get("anomaly_detection", {}))
    anomaly_results = anomaly_det.analyze_batch(classified_logs)
    anomaly_det.enrich_logs(classified_logs)

    anomalies_found = [r for r in anomaly_results if r.is_anomaly]
    console.print(f"  ✅ Detected [red]{len(anomalies_found)}[/red] anomalies "
                  f"from {len(anomaly_results)} logs")

    for a in anomalies_found:
        factors = "; ".join(a.contributing_factors[:2]) or "Pattern deviation"
        console.print(f"    ⚠️  [red]{a.source}[/red] | score={a.anomaly_score:.3f} "
                      f"| {factors}")

    # ── 4. Pattern Recognition ────────────────────────────────
    console.print("\n[bold yellow]📊 Step 4: Pattern Recognition[/bold yellow]")
    from src.analyzers.pattern_recognition import PatternRecognizer
    recognizer = PatternRecognizer(config.get("ml", {}).get("pattern_recognition", {}))
    patterns = recognizer.find_patterns(classified_logs)
    correlations = recognizer.find_correlations(classified_logs)

    console.print(f"  ✅ Found [green]{len(patterns)}[/green] recurring patterns "
                  f"and [yellow]{len(correlations)}[/yellow] correlated event chains")

    # ── 5. Security Analysis ──────────────────────────────────
    console.print("\n[bold yellow]🔒 Step 5: Security Threat Analysis[/bold yellow]")
    from src.analyzers.security_analyzer import SecurityAnalyzer
    sec = SecurityAnalyzer(config.get("security", {}))
    threats = sec.analyze_batch(classified_logs)
    summary = sec.get_threat_summary(threats)

    console.print(f"  ✅ Identified [red]{len(threats)}[/red] security threats")
    for threat in threats:
        console.print(f"    🔴 [{threat.severity}] {threat.threat_type} "
                      f"| score={threat.score:.2f} | device={', '.join(threat.affected_devices)}")
        if threat.recommended_actions:
            console.print(f"       → {threat.recommended_actions[0]}")

    # ── 6. Predictive Maintenance ─────────────────────────────
    console.print("\n[bold yellow]🔧 Step 6: Predictive Maintenance[/bold yellow]")
    from src.maintenance.predictive_maintenance import PredictiveMaintenanceEngine
    engine = PredictiveMaintenanceEngine(
        config.get("ml", {}).get("predictive_maintenance", {}))
    engine.ingest_logs(classified_logs)
    maint_alerts = engine.generate_alerts()

    console.print(f"  ✅ Generated [yellow]{len(maint_alerts)}[/yellow] maintenance predictions")
    for alert in maint_alerts:
        console.print(f"    ⚙️  [yellow]{alert.device}[/yellow] | risk={alert.risk_level} "
                      f"| type={alert.predicted_failure_type} "
                      f"| prob={alert.failure_probability:.1%}")
        console.print(f"       🕐 {alert.maintenance_window}")

    # ── 7. Dashboard Report ───────────────────────────────────
    console.print("\n[bold yellow]📈 Step 7: Generating Dashboard Report[/bold yellow]")
    from src.dashboard.reporting import DashboardController
    dash = DashboardController({"output_dir": "reports"})
    outputs = dash.generate_report(
        logs=classified_logs,
        anomalies=anomaly_results,
        threats=threats,
        patterns=patterns,
        maintenance_alerts=maint_alerts,
        formats=["json", "html"],
    )

    for fmt, path in outputs.items():
        console.print(f"  ✅ [{fmt.upper()}] Report saved: [green]{path}[/green]")

    # ── Final Summary ─────────────────────────────────────────
    from src.dashboard.reporting import ReportBuilder
    report = ReportBuilder().build(classified_logs, anomaly_results, threats,
                                    patterns, maint_alerts)

    console.print(Panel(
        f"[bold]Overall Health Score:[/bold] "
        f"[{'green' if report.health_status == 'HEALTHY' else 'yellow' if report.health_status == 'DEGRADED' else 'red'}]"
        f"{report.overall_health_score:.1f}% ({report.health_status})[/]\n\n"
        + "\n".join(f"  {r}" for r in report.recommendations),
        title="[bold cyan]Network Health Summary[/bold cyan]",
        border_style="cyan",
    ))

    console.print(f"\n[bold green]✅ Demo complete![/bold green] "
                  f"Open [cyan]reports/[/cyan] to view the generated HTML dashboard.\n")


# ─── Analysis Mode ────────────────────────────────────────────────────────────

def run_analysis(input_file: str, output_dir: str = "reports"):
    """Analyse a log file and produce JSON + HTML reports."""
    config = load_config()

    logger.info("Loading logs from %s", input_file)
    from src.collectors.log_collector import FileLogCollector
    collector = FileLogCollector()
    raw_logs = collector.collect_from_json(input_file) if input_file.endswith(".json") \
        else collector.collect_from_syslog_file(input_file)

    from src.classifiers.log_classifier import LogClassificationPipeline
    classified = LogClassificationPipeline(config.get("ml", {})).classify_batch(raw_logs)

    from src.analyzers.anomaly_detector import AnomalyDetector
    anomaly_det = AnomalyDetector()
    anomalies = anomaly_det.analyze_batch(classified)
    anomaly_det.enrich_logs(classified)

    from src.analyzers.pattern_recognition import PatternRecognizer
    patterns = PatternRecognizer().find_patterns(classified)

    from src.analyzers.security_analyzer import SecurityAnalyzer
    threats = SecurityAnalyzer().analyze_batch(classified)

    from src.maintenance.predictive_maintenance import PredictiveMaintenanceEngine
    engine = PredictiveMaintenanceEngine()
    engine.ingest_logs(classified)
    maint_alerts = engine.generate_alerts()

    from src.dashboard.reporting import DashboardController
    outputs = DashboardController({"output_dir": output_dir}).generate_report(
        classified, anomalies, threats, patterns, maint_alerts, formats=["json", "html"]
    )

    logger.info("Reports generated:")
    for fmt, path in outputs.items():
        logger.info("  [%s] %s", fmt.upper(), path)

    return outputs


# ─── API Mode ─────────────────────────────────────────────────────────────────

def run_api(host: str = "0.0.0.0", port: int = 8000):
    """Start the FastAPI server."""
    try:
        import uvicorn
        from src.api.rest_api import create_app
        config = load_config()
        app = create_app(config)
        logger.info("Starting INLAAS API on %s:%d", host, port)
        uvicorn.run(app, host=host, port=port, reload=False)
    except ImportError as e:
        logger.error("Missing dependency: %s. Run: pip install fastapi uvicorn", e)
        sys.exit(1)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="INLAAS — Intelligent Network Log Analysis System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py demo
  python main.py analyze --input data/sample_logs.json
  python main.py api --port 8000
        """
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # demo
    subparsers.add_parser("demo", help="Run full demo with sample data")

    # analyze
    analyze_p = subparsers.add_parser("analyze", help="Analyze a log file")
    analyze_p.add_argument("--input",  required=True, help="Path to log file (JSON or syslog)")
    analyze_p.add_argument("--output", default="reports", help="Output directory for reports")

    # api
    api_p = subparsers.add_parser("api", help="Start REST API server")
    api_p.add_argument("--host", default="0.0.0.0")
    api_p.add_argument("--port", type=int, default=8000)

    args = parser.parse_args()

    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        run_analysis(args.input, args.output)
    elif args.command == "api":
        run_api(args.host, args.port)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
