"""
REST API Module
===============
FastAPI-based REST API exposing all INLAAS capabilities over HTTP.
Endpoints for log ingestion, analysis queries, reports, and system health.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# FastAPI & Pydantic
try:
    from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, FileResponse
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

from src.collectors.log_collector import LogCollectionOrchestrator, RawLog
from src.classifiers.log_classifier import LogClassificationPipeline
from src.analyzers.anomaly_detector import AnomalyDetector
from src.analyzers.pattern_recognition import PatternRecognizer
from src.analyzers.security_analyzer import SecurityAnalyzer
from src.maintenance.predictive_maintenance import PredictiveMaintenanceEngine
from src.dashboard.reporting import DashboardController

logger = logging.getLogger(__name__)


# ─── Pydantic Schemas ────────────────────────────────────────────────────────

if FASTAPI_AVAILABLE:

    class LogIngestionRequest(BaseModel):
        logs: List[Dict[str, Any]] = Field(..., description="List of raw log dicts")

    class AnalysisRequest(BaseModel):
        log_ids: Optional[List[str]] = None
        run_anomaly:    bool = True
        run_security:   bool = True
        run_patterns:   bool = True
        run_prediction: bool = True

    class TrainRequest(BaseModel):
        labels: List[str] = Field(..., description="Category label per log in the buffer")

    class ReportRequest(BaseModel):
        formats: List[str] = Field(default=["json", "html"])


# ─── App Factory ─────────────────────────────────────────────────────────────

def create_app(config: Optional[Dict] = None) -> Any:
    """Create and configure the FastAPI application."""
    if not FASTAPI_AVAILABLE:
        raise ImportError("FastAPI is required. Run: pip install fastapi uvicorn")

    cfg = config or {}

    app = FastAPI(
        title="INLAAS — Intelligent Network Log Analysis System",
        description=(
            "REST API for automated network log collection, ML classification, "
            "anomaly detection, security threat analysis, predictive maintenance, "
            "and real-time health dashboards."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.get("cors_origins", ["*"]),
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Component Initialisation ──────────────────────────────
    collector   = LogCollectionOrchestrator(cfg)
    classifier  = LogClassificationPipeline(cfg.get("ml", {}))
    anomaly_det = AnomalyDetector(cfg.get("ml", {}).get("anomaly_detection", {}))
    pattern_rec = PatternRecognizer(cfg.get("ml", {}).get("pattern_recognition", {}))
    security    = SecurityAnalyzer(cfg.get("security", {}))
    maintenance = PredictiveMaintenanceEngine(cfg.get("ml", {}).get("predictive_maintenance", {}))
    dashboard   = DashboardController({"output_dir": "reports"})

    # In-memory store (replace with DB in production)
    _store: Dict[str, List] = {
        "classified_logs":    [],
        "anomaly_results":    [],
        "security_threats":   [],
        "patterns":           [],
        "maintenance_alerts": [],
    }

    # ── Health Check ──────────────────────────────────────────
    @app.get("/health", tags=["system"])
    async def health_check():
        return {
            "status": "ok",
            "service": "INLAAS",
            "version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {
                "classifier":  "ready" if classifier.ml_classifier.is_trained else "rule-based",
                "anomaly_det": "ready" if anomaly_det.if_detector.is_trained else "heuristic",
                "maintenance": "ready" if maintenance.model.is_trained else "heuristic",
            },
        }

    # ── Log Ingestion ─────────────────────────────────────────
    @app.post("/api/v1/logs/ingest", tags=["ingestion"],
              summary="Ingest raw logs via JSON payload")
    async def ingest_logs(request: LogIngestionRequest):
        raw_logs = []
        for item in request.logs:
            raw_logs.append(RawLog(
                log_id=item.get("log_id", ""),
                timestamp=item.get("timestamp", datetime.now(timezone.utc).isoformat()),
                source=item.get("source", ""),
                source_ip=item.get("source_ip", ""),
                platform=item.get("platform", "api"),
                component=item.get("component", ""),
                version=item.get("version", ""),
                severity=item.get("severity", "INFO"),
                description=item.get("description", ""),
                raw_message=item.get("raw_message", ""),
                metrics=item.get("metrics", {}),
            ))

        classified = classifier.classify_batch(raw_logs)
        _store["classified_logs"].extend(classified)
        return {
            "status": "ingested",
            "count": len(classified),
            "log_ids": [l.log_id for l in classified],
        }

    @app.post("/api/v1/logs/ingest/file", tags=["ingestion"],
              summary="Ingest logs from a file path on the server")
    async def ingest_file(file_path: str):
        try:
            raw_logs = collector.ingest_file(file_path)
            classified = classifier.classify_batch(raw_logs)
            _store["classified_logs"].extend(classified)
            return {"status": "ingested", "count": len(classified)}
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"File not found: {file_path}")
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    # ── Query Logs ────────────────────────────────────────────
    @app.get("/api/v1/logs", tags=["logs"],
             summary="List classified logs with optional filters")
    async def list_logs(
        category: Optional[str] = None,
        severity: Optional[str] = None,
        source:   Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ):
        logs = _store["classified_logs"]
        if category: logs = [l for l in logs if l.category == category.upper()]
        if severity: logs = [l for l in logs if l.severity == severity.upper()]
        if source:   logs = [l for l in logs if source.lower() in l.source.lower()]
        total = len(logs)
        page  = logs[offset:offset + limit]
        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "logs": [l.to_dict() for l in page],
        }

    @app.get("/api/v1/logs/{log_id}", tags=["logs"])
    async def get_log(log_id: str):
        for log in _store["classified_logs"]:
            if log.log_id == log_id:
                return log.to_dict()
        raise HTTPException(status_code=404, detail=f"Log {log_id} not found")

    # ── Analysis ──────────────────────────────────────────────
    @app.post("/api/v1/analysis/run", tags=["analysis"],
              summary="Run full analysis pipeline on buffered logs")
    async def run_analysis(request: AnalysisRequest, background: BackgroundTasks):
        logs = _store["classified_logs"]
        if not logs:
            raise HTTPException(status_code=400, detail="No logs available for analysis.")

        results: Dict[str, Any] = {"log_count": len(logs)}

        if request.run_anomaly:
            anomaly_results = anomaly_det.analyze_batch(logs)
            _store["anomaly_results"] = anomaly_results
            anomaly_det.enrich_logs(logs)
            results["anomalies"] = sum(1 for a in anomaly_results if a.is_anomaly)

        if request.run_security:
            threats = security.analyze_batch(logs)
            _store["security_threats"] = threats
            results["threats"] = len(threats)

        if request.run_patterns:
            patterns = pattern_rec.find_patterns(logs)
            _store["patterns"] = patterns
            results["patterns"] = len(patterns)

        if request.run_prediction:
            maintenance.ingest_logs(logs)
            alerts = maintenance.generate_alerts()
            _store["maintenance_alerts"] = alerts
            results["maintenance_alerts"] = len(alerts)

        return {"status": "analysis_complete", "results": results}

    @app.get("/api/v1/analysis/anomalies", tags=["analysis"])
    async def get_anomalies(anomalous_only: bool = True):
        results = _store["anomaly_results"]
        if anomalous_only:
            results = [r for r in results if r.is_anomaly]
        return {"total": len(results), "anomalies": [r.to_dict() for r in results]}

    @app.get("/api/v1/analysis/threats", tags=["analysis"])
    async def get_threats():
        threats = _store["security_threats"]
        return {
            "total": len(threats),
            "summary": security.get_threat_summary(threats),
            "threats": [t.to_dict() for t in threats],
        }

    @app.get("/api/v1/analysis/patterns", tags=["analysis"])
    async def get_patterns():
        patterns = _store["patterns"]
        return {"total": len(patterns), "patterns": [p.to_dict() for p in patterns]}

    @app.get("/api/v1/analysis/maintenance", tags=["analysis"])
    async def get_maintenance_alerts():
        alerts = _store["maintenance_alerts"]
        return {"total": len(alerts), "alerts": [a.to_dict() for a in alerts]}

    # ── Reports ───────────────────────────────────────────────
    @app.post("/api/v1/reports/generate", tags=["reports"])
    async def generate_report(request: ReportRequest):
        if not _store["classified_logs"]:
            raise HTTPException(status_code=400, detail="No logs available for reporting.")

        outputs = dashboard.generate_report(
            logs=_store["classified_logs"],
            anomalies=_store["anomaly_results"],
            threats=_store["security_threats"],
            patterns=_store["patterns"],
            maintenance_alerts=_store["maintenance_alerts"],
            formats=request.formats,
        )
        return {"status": "generated", "outputs": outputs}

    @app.get("/api/v1/reports/dashboard", tags=["reports"],
             summary="Get current network health summary")
    async def get_dashboard():
        from src.dashboard.reporting import ReportBuilder
        rb = ReportBuilder()
        report = rb.build(
            logs=_store["classified_logs"],
            anomalies=_store["anomaly_results"],
            threats=_store["security_threats"],
            patterns=_store["patterns"],
            maintenance_alerts=_store["maintenance_alerts"],
        )
        return report.to_dict()

    # ── ML Training ───────────────────────────────────────────
    @app.post("/api/v1/ml/train/classifier", tags=["ml"],
              summary="Retrain the log classifier with provided labels")
    async def train_classifier(request: TrainRequest):
        logs = _store["classified_logs"]
        if len(logs) < 20:
            raise HTTPException(status_code=400,
                                detail="Need at least 20 classified logs to train.")
        if len(request.labels) != len(logs):
            raise HTTPException(status_code=400,
                                detail="labels length must match log count.")

        # Convert ClassifiedLog → RawLog for training
        from src.collectors.log_collector import RawLog as RL
        raw = [RL(log_id=l.log_id, source=l.source, severity=l.severity,
                  description=l.description, raw_message=l.raw_message,
                  metrics=l.metrics) for l in logs]
        result = classifier.ml_classifier.train(raw, request.labels)
        return {"status": "trained", "metrics": result}

    @app.post("/api/v1/ml/train/anomaly", tags=["ml"])
    async def train_anomaly_detector():
        logs = _store["classified_logs"]
        if len(logs) < 20:
            raise HTTPException(status_code=400, detail="Need at least 20 logs to train.")
        result = anomaly_det.train(logs)
        return {"status": "trained", "metrics": result}

    # ── Statistics ────────────────────────────────────────────
    @app.get("/api/v1/stats", tags=["system"])
    async def get_statistics():
        logs = _store["classified_logs"]
        from collections import Counter
        return {
            "total_logs":        len(logs),
            "by_category":       dict(Counter(l.category  for l in logs)),
            "by_severity":       dict(Counter(l.severity  for l in logs)),
            "by_source":         dict(Counter(l.source    for l in logs).most_common(20)),
            "anomaly_count":     sum(1 for l in logs if l.is_anomaly),
            "threat_count":      sum(1 for l in logs if l.security_threat),
            "analyzed_logs":     len(_store["anomaly_results"]),
            "active_threats":    len(_store["security_threats"]),
            "patterns_found":    len(_store["patterns"]),
            "maintenance_alerts":len(_store["maintenance_alerts"]),
        }

    return app


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
