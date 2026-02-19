#  INLAAS — Intelligent Network Log Automation & Analysis System

> **Automated log collection · ML-powered classification · Anomaly detection · Security threat analysis · Predictive maintenance · Real-time dashboard**

---

## Overview

INLAAS is a production-grade Python system that automates the full network log analysis lifecycle:

| Stage | What it does |
|---|---|
| **Collection** | Ingests logs from Syslog (UDP/TCP), SNMP, NETCONF, REST APIs, SolarWinds, PRTG, Nagios, Zabbix, and JSON/text files |
| **Classification** | AI/ML classifier (Random Forest) tags each log by category, impacted components, and OS version; rule-based fallback ensures 100% coverage |
| **Anomaly Detection** | Isolation Forest + statistical z-score baselines + frequency burst detection flag deviations from normal |
| **Pattern Recognition** | Template matching identifies recurring issues; cascade correlation detects root-cause chains (e.g., interface down → BGP drop) |
| **Security Threats** | Classifies port scans, brute-force, DoS, DNS amplification, ARP spoofing; extracts IOCs; maps to MITRE ATT&CK |
| **Predictive Maintenance** | Gradient Boosting model predicts device failures up to 24 hours ahead using rolling health metrics |
| **Dashboard & Reporting** | Real-time health score, HTML dashboard, JSON reports with actionable recommendations |
| **REST API** | Full FastAPI REST interface for integration with NOC toolchains |

---

## Project Structure

```
network-log-analyzer/
├── main.py                          # CLI entry point (demo / analyze / api)
├── requirements.txt
├── config/
│   └── config.yaml                  # All system configuration
├── data/
│   └── sample_logs.json             # 10 realistic sample network logs
├── src/
│   ├── collectors/
│   │   └── log_collector.py         # Syslog, NMS, file collectors + orchestrator
│   ├── classifiers/
│   │   └── log_classifier.py        # ML + rule-based classification pipeline
│   ├── analyzers/
│   │   ├── anomaly_detector.py      # Isolation Forest + baseline + frequency
│   │   ├── pattern_recognition.py   # Template matching + cascade correlation
│   │   └── security_analyzer.py     # Threat analysis + IOC extraction + MITRE
│   ├── maintenance/
│   │   └── predictive_maintenance.py # GBM failure prediction
│   ├── dashboard/
│   │   └── reporting.py             # HTML + JSON report generation
│   └── api/
│       └── rest_api.py              # FastAPI REST API
├── models/                          # Trained ML model files (auto-created)
├── reports/                         # Generated reports (auto-created)
├── tests/
│   └── test_all.py                  # Full pytest test suite (40+ tests)
└── docs/
    ├── architecture.md              # System architecture & data flow
    └── user_guide.md                # Installation, configuration, API reference
```

---

## Quick Start

```bash
# 1. Install dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Run the full demo pipeline
python main.py demo

# 3. Open the generated HTML dashboard
open reports/report_*.html
```

---

## Modes

### Demo (sample data)
```bash
python main.py demo
```

### Analyze a log file
```bash
python main.py analyze --input data/sample_logs.json --output reports/
```

### Start the REST API
```bash
python main.py api --port 8000
# Docs: http://localhost:8000/docs
```

---

## Key API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | System status & component readiness |
| POST | `/api/v1/logs/ingest` | Ingest JSON logs |
| GET | `/api/v1/logs` | Query classified logs |
| POST | `/api/v1/analysis/run` | Run full ML analysis pipeline |
| GET | `/api/v1/analysis/anomalies` | Get anomaly results |
| GET | `/api/v1/analysis/threats` | Get security threats |
| GET | `/api/v1/analysis/maintenance` | Get predictive maintenance alerts |
| GET | `/api/v1/reports/dashboard` | Real-time network health summary |
| POST | `/api/v1/reports/generate` | Generate JSON + HTML reports |
| POST | `/api/v1/ml/train/classifier` | Retrain the log classifier |

---

## ML Models

| Model | Algorithm | Purpose |
|---|---|---|
| Log Classifier | Random Forest | Category + component classification |
| Anomaly Detector | Isolation Forest | Detect out-of-distribution events |
| Predictive Model | Gradient Boosting | Predict device failures 24h ahead |

All models are trained on-demand and persisted to `models/`. Rule-based fallbacks ensure full coverage before models are trained.

---

## Running Tests

```bash
pytest tests/ -v
pytest tests/ -v --cov=src --cov-report=html
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| ML | scikit-learn, numpy, pandas |
| API | FastAPI, Pydantic, uvicorn |
| Database | SQLAlchemy (SQLite / PostgreSQL) |
| Network | pysnmp, netmiko, ncclient, paramiko |
| Scheduling | APScheduler |
| Testing | pytest, pytest-cov |
| Config | PyYAML, python-dotenv |
| Logging | structlog, Python logging |

---

## Documentation

- [Architecture & Data Flow](docs/architecture.md)
- [User Guide & API Reference](docs/user_guide.md)

---

## License

MIT License — See LICENSE file for details.

---

*Built as part of Network Engineering Automation initiative — September 2025*
