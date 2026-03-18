# CORE-HIDS 🛡️
## Overview 🔍

CORE-HIDS is a research-oriented Host-based Intrusion Detection System (HIDS) for monitoring system behavior and detecting anomalies.

It is modular and flexible, separating event acquisition, analysis, alerting, and persistence. This makes it easy to extend with rule-based, statistical, or ML-based detection methods.

CORE-HIDS works both as a practical monitoring tool and as a research platform for studying host-based threat detection and automated response strategies.

## Project Structure 🗂️
```bash
CORE-HIDS/
├── src/
│   ├── __init__.py
│   ├── alerts.py
│   ├── baseline.py
│   ├── config.py
│   ├── detection_context.py
│   ├── detector.py
│   ├── executor.py
│   ├── log_monitor.py
│   ├── logger.py
│   ├── main.py
│   ├── persistence.py
│   └── worker.py
├── tests/
│   ├── __init__.py
│   ├── test_alerts.py
│   ├── test_baseline.py
│   ├── test_detector.py
│   └── test_log_monitor.py
├── .gitignore
├── LICENSE
├── README.md
├── pyproject.toml
└── requirements.txt
```
## Architecture ⚙️

#### CORE-HIDS uses a modular detection pipeline:

Event Acquisition → Analysis → Alert Generation → Logging & Persistence → Concurrent Processing

log_monitor.py – real-time host event acquisition

detector.py – orchestrates the detection workflow

baseline.py – behavioral profiling for anomaly detection

alerts.py – generates actionable alerts

persistence.py – stores telemetry and event history

worker.py – supports parallel processing for high performance

## Installation 💻
```bash
# Cloning the repo
git clone https://github.com/SirTeggun/CORE-HIDS.git
```

```bash
# Go into the project folder
cd CORE-HIDS
```
```bash
# Create a virtual environment
python -m venv .venv
```
```bash
# Activate the virtual environment
# Linux / Mac
source .venv/bin/activate
# Windows
.venv\Scripts\activate
```
```bash
# Install dependencies
pip install -r requirements.txt
```

## Usage ▶️
python -m src.main
Configuration ⚙️

### System parameters can be customized in:

src/config.py

### Roadmap 🛠️

Modular pipeline improvements

DetectionEngine refactor

Rule abstraction & severity/escalation management

Persistence upgrades & performance optimization

### Contributing 🤝

Fork the repository

Create a feature branch

Implement and test changes

Open a Pull Request with detailed explanation

### Tests ✅
pytest tests/test_detector.py -v

Covers alerts, baseline/anomaly detection, detection engine, and log monitoring.

### License 📄

See the LICENSE file.

### Security Notice ⚠️

CORE-HIDS is a research project. Avoid exposing sensitive components without proper hardening and access control.