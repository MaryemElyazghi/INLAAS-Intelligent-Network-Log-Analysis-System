# INLAAS — System Architecture

## Overview

INLAAS (Intelligent Network Log Automation & Analysis System) is a layered,
modular platform that collects network logs from heterogeneous sources,
classifies them using ML, detects anomalies, identifies security threats,
predicts equipment failures, and surfaces insights through a REST API and
HTML dashboard.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         INLAAS Platform                             │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                      Data Sources                            │  │
│  │  Syslog(UDP/TCP)  SNMP  NETCONF  REST API  File(JSON/log)   │  │
│  └──────────────────────┬───────────────────────────────────────┘  │
│                         │                                           │
│  ┌──────────────────────▼───────────────────────────────────────┐  │
│  │                  Collection Layer                             │  │
│  │  SyslogCollector  NMSCollector  FileLogCollector             │  │
│  │  LogCollectionOrchestrator                                   │  │
│  └──────────────────────┬───────────────────────────────────────┘  │
│                         │  RawLog[]                                 │
│  ┌──────────────────────▼───────────────────────────────────────┐  │
│  │               Classification Layer (AI/ML)                   │  │
│  │  LogFeatureEngineer  →  MLLogClassifier (Random Forest)      │  │
│  │                      →  RuleBasedClassifier (fallback)       │  │
│  │  LogClassificationPipeline → ClassifiedLog[]                │  │
│  └──────────────────────┬───────────────────────────────────────┘  │
│                         │  ClassifiedLog[]                          │
│  ┌──────────────────────▼───────────────────────────────────────┐  │
│  │                  Analysis Layer                               │  │
│  │  ┌──────────────────┐  ┌──────────────────┐                 │  │
│  │  │ AnomalyDetector  │  │ SecurityAnalyzer  │                 │  │
│  │  │ IsolationForest  │  │ IOC Extraction    │                 │  │
│  │  │ BaselineTracker  │  │ MITRE Mapping     │                 │  │
│  │  │ FrequencyTracker │  │ Threat Scoring    │                 │  │
│  │  └──────────────────┘  └──────────────────┘                 │  │
│  │  ┌──────────────────────────────────────┐                   │  │
│  │  │         PatternRecognizer            │                   │  │
│  │  │  Template Matching  Cascade Correl.  │                   │  │
│  │  └──────────────────────────────────────┘                   │  │
│  └──────────────────────┬───────────────────────────────────────┘  │
│                         │                                           │
│  ┌──────────────────────▼───────────────────────────────────────┐  │
│  │           Predictive Maintenance Layer                        │  │
│  │  DeviceHealthTracker → PredictiveMaintenanceModel (GBM)     │  │
│  │  PredictiveMaintenanceEngine → MaintenanceAlert[]           │  │
│  └──────────────────────┬───────────────────────────────────────┘  │
│                         │                                           │
│  ┌──────────────────────▼───────────────────────────────────────┐  │
│  │              Dashboard & Reporting Layer                      │  │
│  │  ReportBuilder  HTMLReportGenerator  DashboardController     │  │
│  │  Outputs: JSON report  HTML dashboard                        │  │
│  └──────────────────────┬───────────────────────────────────────┘  │
│                         │                                           │
│  ┌──────────────────────▼───────────────────────────────────────┐  │
│  │                    REST API Layer                             │  │
│  │  FastAPI  /api/v1/logs  /api/v1/analysis  /api/v1/reports   │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Module Reference

### `src/collectors/` — Data Collection

| Class | Responsibility |
|---|---|
| `RawLog` | Dataclass representing a raw, un-classified log entry |
| `SyslogHandler` | RFC3164/5424 syslog parser (UDP/TCP) |
| `SyslogCollector` | Threaded UDP syslog server |
| `NMSCollector` | REST API poller for SolarWinds, PRTG, Nagios, Zabbix |
| `FileLogCollector` | Batch ingestion from JSON / plain-text syslog files |
| `LogCollectionOrchestrator` | Central coordinator for all collectors |

### `src/classifiers/` — AI Classification

| Class | Responsibility |
|---|---|
| `LogFeatureEngineer` | Text → numerical feature extraction |
| `RuleBasedClassifier` | Pattern-matching fallback classifier |
| `MLLogClassifier` | Random Forest ML classifier with joblib persistence |
| `LogClassificationPipeline` | End-to-end `RawLog → ClassifiedLog` pipeline |

**Classification categories:** BGP, OSPF, STP, INTERFACE, SECURITY, HARDWARE, QOS, DNS, DHCP, VPN, GENERAL

### `src/analyzers/` — Analysis & Detection

#### `anomaly_detector.py`
| Class | Algorithm |
|---|---|
| `BaselineTracker` | Rolling mean/std z-score per device/metric |
| `FrequencyTracker` | Sliding-window burst detection |
| `IsolationForestDetector` | sklearn IsolationForest |
| `AnomalyDetector` | Combined ML + statistical + frequency scoring |

#### `pattern_recognition.py`
| Class | Function |
|---|---|
| `PatternRecognizer` | Template extraction + cascade correlation |

#### `security_analyzer.py`
| Class | Function |
|---|---|
| `SecurityAnalyzer` | IOC extraction, MITRE ATT&CK mapping, threat consolidation |

### `src/maintenance/` — Predictive Maintenance

| Class | Function |
|---|---|
| `DeviceHealthTracker` | Rolling health metrics per device |
| `PredictiveMaintenanceModel` | Gradient Boosting failure predictor |
| `PredictiveMaintenanceEngine` | Orchestrates tracking, scoring, and alerting |

### `src/dashboard/` — Reporting

| Class | Function |
|---|---|
| `ReportBuilder` | Assembles `NetworkHealthReport` from all analysis outputs |
| `HTMLReportGenerator` | Self-contained HTML dashboard renderer |
| `DashboardController` | Multi-format output orchestrator |

### `src/api/` — REST API

FastAPI application with endpoints:
- `GET /health` — System health check
- `POST /api/v1/logs/ingest` — Ingest JSON logs
- `GET /api/v1/logs` — Query classified logs
- `POST /api/v1/analysis/run` — Run analysis pipeline
- `GET /api/v1/analysis/anomalies` — Get anomaly results
- `GET /api/v1/analysis/threats` — Get security threats
- `GET /api/v1/analysis/patterns` — Get patterns
- `GET /api/v1/analysis/maintenance` — Get maintenance alerts
- `POST /api/v1/reports/generate` — Generate reports
- `GET /api/v1/reports/dashboard` — Current health summary
- `POST /api/v1/ml/train/classifier` — Retrain classifier
- `POST /api/v1/ml/train/anomaly` — Retrain anomaly detector
- `GET /api/v1/stats` — System statistics

---

## Data Flow

```
Raw Log (syslog / API / file)
        ↓
LogCollectionOrchestrator
        ↓
LogClassificationPipeline
    ├── MLLogClassifier (Random Forest)
    └── RuleBasedClassifier (fallback)
        ↓
ClassifiedLog
    ├── AnomalyDetector
    │       ├── IsolationForest score
    │       ├── Z-score deviation
    │       └── Frequency burst
    ├── SecurityAnalyzer
    │       ├── IOC extraction
    │       ├── Threat consolidation
    │       └── MITRE ATT&CK mapping
    ├── PatternRecognizer
    │       ├── Template matching
    │       └── Cascade correlation
    └── PredictiveMaintenanceEngine
            ├── DeviceHealthTracker
            └── GBM failure prediction
                        ↓
                NetworkHealthReport
                    ├── JSON output
                    └── HTML dashboard
```

---

## ML Models

### Log Classifier (Random Forest)
- **Features:** TF-IDF keyword counts, severity encoding, component keyword hits, metric ratios
- **Training data:** Labeled network logs (min 20 samples, recommended 500+)
- **Persistence:** `models/log_classifier.pkl`
- **Fallback:** Rule-based classifier using regex patterns

### Anomaly Detector (Isolation Forest)
- **Features:** CPU, memory, interface errors, severity, IP presence
- **Contamination:** 5% (configurable)
- **Persistence:** `models/anomaly_detector.pkl`
- **Fallback:** Heuristic threshold scoring

### Predictive Maintenance (Gradient Boosting)
- **Features:** Rolling mean, std, trend, last value for all health metrics
- **Prediction horizon:** 24 hours (configurable)
- **Persistence:** `models/predictive_model.pkl`
- **Fallback:** Weighted heuristic scoring

---

## Scalability Considerations

- **Batch processing:** All pipelines support batch input for high-throughput ingestion
- **Async:** FastAPI with uvicorn supports async I/O for non-blocking endpoints
- **Stateless API:** The REST API is designed to be stateless; replace in-memory store with PostgreSQL for production
- **Model updates:** Models support online retraining via `/api/v1/ml/train/*` endpoints
- **Horizontal scaling:** Multiple API workers supported via `uvicorn --workers N`
