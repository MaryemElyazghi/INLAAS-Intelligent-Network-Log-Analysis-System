# INLAAS — User Guide

## Quick Start

### 1. Installation

```bash
# Clone / extract the project
cd network-log-analyzer

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt
```

### 2. Run the Demo

The fastest way to see INLAAS in action:

```bash
python main.py demo
```

This runs the full pipeline on the bundled `data/sample_logs.json` and generates:
- `reports/report_YYYYMMDD_HHMMSS.json` — Structured JSON report
- `reports/report_YYYYMMDD_HHMMSS.html` — Interactive HTML dashboard

Open the HTML file in any browser to see the network health dashboard.

---

## Modes of Operation

### Mode 1: Command-Line Analysis

Analyze any JSON or syslog file and generate reports:

```bash
# Analyze a JSON log file
python main.py analyze --input data/sample_logs.json

# Analyze a plain syslog file
python main.py analyze --input /var/log/syslog --output /tmp/reports
```

### Mode 2: REST API Server

Start the API server:

```bash
python main.py api --port 8000
```

Then visit:
- http://localhost:8000/docs — Interactive API documentation (Swagger UI)
- http://localhost:8000/redoc — ReDoc documentation

### Mode 3: Python Library

Use INLAAS as a library in your own code:

```python
from src.collectors.log_collector import FileLogCollector
from src.classifiers.log_classifier import LogClassificationPipeline
from src.analyzers.anomaly_detector import AnomalyDetector
from src.analyzers.security_analyzer import SecurityAnalyzer
from src.maintenance.predictive_maintenance import PredictiveMaintenanceEngine
from src.dashboard.reporting import DashboardController

# 1. Collect logs
collector = FileLogCollector()
raw_logs  = collector.collect_from_json("data/my_logs.json")

# 2. Classify
pipeline  = LogClassificationPipeline()
classified = pipeline.classify_batch(raw_logs)

# 3. Detect anomalies
detector  = AnomalyDetector()
anomalies = detector.analyze_batch(classified)
detector.enrich_logs(classified)   # Sets is_anomaly on each log

# 4. Security analysis
security  = SecurityAnalyzer()
threats   = security.analyze_batch(classified)

# 5. Predictive maintenance
engine    = PredictiveMaintenanceEngine()
engine.ingest_logs(classified)
alerts    = engine.generate_alerts()

# 6. Generate dashboard report
dashboard = DashboardController({"output_dir": "reports"})
outputs   = dashboard.generate_report(
    logs=classified, anomalies=anomalies, threats=threats,
    patterns=[], maintenance_alerts=alerts, formats=["html", "json"]
)
print(outputs)
```

---

## Configuration

Edit `config/config.yaml` to customize behaviour:

### Key Settings

| Section | Key | Default | Description |
|---|---|---|---|
| `collection` | `poll_interval_seconds` | 30 | NMS polling interval |
| `collection` | `batch_size` | 500 | Max logs per batch |
| `ml.classifier` | `model_path` | `models/log_classifier.pkl` | Classifier model file |
| `ml.anomaly_detection` | `contamination` | 0.05 | Expected anomaly fraction |
| `ml.predictive_maintenance` | `prediction_horizon_hours` | 24 | Failure prediction window |
| `thresholds` | `cpu_usage_critical` | 90 | CPU critical threshold % |
| `thresholds` | `anomaly_score_alert` | 0.65 | Min score to flag anomaly |
| `api` | `port` | 8000 | API server port |

### Environment Variables

Sensitive credentials are read from environment variables:

```bash
export SOLARWINDS_USER="admin"
export SOLARWINDS_PASS="secret"
export ZABBIX_USER="api_user"
export ZABBIX_PASS="secret"
export API_SECRET_KEY="your-jwt-secret"
```

---

## Log Input Formats

### JSON Format

```json
[
  {
    "log_id": "LOG-001",
    "timestamp": "2025-09-01T08:00:00Z",
    "source": "router-core-01",
    "component": "BGP",
    "version": "IOS-XE 17.3.4",
    "severity": "WARNING",
    "description": "BGP neighbor went down",
    "raw_message": "%BGP-3-NOTIFICATION: ...",
    "metrics": {
      "cpu_usage": 45,
      "memory_usage": 60,
      "interface_errors": 2
    }
  }
]
```

### Syslog Format (plain text)

```
<34>Sep 01 08:00:00 router-01 %BGP-3-NOTIFICATION: sent to neighbor 10.0.0.2
```

### REST API Ingestion

```bash
curl -X POST http://localhost:8000/api/v1/logs/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [
      {
        "source": "router-01",
        "severity": "WARNING",
        "description": "BGP neighbor down",
        "raw_message": "%BGP-3-NOTIFICATION...",
        "metrics": {"cpu_usage": 45}
      }
    ]
  }'
```

---

## Training the ML Models

### Training the Log Classifier

Provide labeled examples via the API:

```bash
# First ingest some logs...
curl -X POST http://localhost:8000/api/v1/logs/ingest -d '{"logs": [...]}'

# Then train with labels (one label per ingested log, in order)
curl -X POST http://localhost:8000/api/v1/ml/train/classifier \
  -H "Content-Type: application/json" \
  -d '{"labels": ["BGP", "SECURITY", "HARDWARE", ...]}'
```

Or via Python:

```python
from src.classifiers.log_classifier import MLLogClassifier
from src.collectors.log_collector import FileLogCollector

raw_logs = FileLogCollector().collect_from_json("data/labeled_logs.json")
labels   = ["BGP", "SECURITY", "HARDWARE", ...]  # One per log

clf = MLLogClassifier()
result = clf.train(raw_logs, labels)
print(f"Accuracy: {result['accuracy']:.1%}")
```

### Training the Anomaly Detector

```bash
curl -X POST http://localhost:8000/api/v1/ml/train/anomaly
```

The anomaly detector trains on all currently ingested (normal-operation) logs.
It is recommended to train on at least 200 logs captured during a stable period.

---

## REST API Reference

### Ingest Logs
```
POST /api/v1/logs/ingest
Body: {"logs": [<log_object>, ...]}
```

### Query Logs
```
GET /api/v1/logs?category=BGP&severity=WARNING&limit=100
```

### Run Analysis
```
POST /api/v1/analysis/run
Body: {"run_anomaly": true, "run_security": true, "run_patterns": true, "run_prediction": true}
```

### Get Anomalies
```
GET /api/v1/analysis/anomalies?anomalous_only=true
```

### Get Security Threats
```
GET /api/v1/analysis/threats
```

### Get Maintenance Alerts
```
GET /api/v1/analysis/maintenance
```

### Generate Report
```
POST /api/v1/reports/generate
Body: {"formats": ["json", "html"]}
```

### Network Health Dashboard (real-time summary)
```
GET /api/v1/reports/dashboard
```

### System Statistics
```
GET /api/v1/stats
```

---

## Integrating with Network Management Systems

### SolarWinds

```yaml
# config/config.yaml
collection:
  nms_integrations:
    solarwinds:
      enabled: true
      base_url: "http://solarwinds-nms:17778/SolarWinds/InformationService/v3/Json"
      username: "${SOLARWINDS_USER}"
      password: "${SOLARWINDS_PASS}"
```

```python
from src.collectors.log_collector import NMSCollector
collector = NMSCollector(config)
logs = collector.collect_from_solarwinds(
    base_url="http://solarwinds-nms:17778/SolarWinds/InformationService/v3/Json",
    username="admin",
    password="secret"
)
```

### Zabbix

```python
logs = collector.collect_from_zabbix(
    base_url="http://zabbix-server/zabbix/api_jsonrpc.php",
    username="api_user",
    password="secret"
)
```

### Syslog Listener

To receive syslog messages in real time (requires root or CAP_NET_BIND_SERVICE for port 514):

```python
from src.collectors.log_collector import LogCollectionOrchestrator
orch = LogCollectionOrchestrator(config)
orch.start_syslog_listener(host="0.0.0.0", port=514)

# Or use a high port (no root required):
orch.start_syslog_listener(host="0.0.0.0", port=5514)
```

Configure network devices to forward syslog to this host:
```
! Cisco IOS
logging host <INLAAS_IP> transport udp port 5514
```

---

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=src --cov-report=html

# Run a specific test class
pytest tests/test_all.py::TestLogClassifier -v
```

---

## Production Deployment

### Environment Variables

```bash
export API_SECRET_KEY="strong-random-secret"
export DB_HOST="postgres-server"
export DB_NAME="network_logs"
export DB_USER="inlaas"
export DB_PASS="secure-password"
```

### Systemd Service

```ini
[Unit]
Description=INLAAS Network Log Analysis System
After=network.target

[Service]
Type=simple
User=inlaas
WorkingDirectory=/opt/inlaas
ExecStart=/opt/inlaas/.venv/bin/python main.py api --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

### Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["python", "main.py", "api", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
docker build -t inlaas:1.0.0 .
docker run -p 8000:8000 -v $(pwd)/reports:/app/reports inlaas:1.0.0
```
