# CORE-HIDS
Overview

CORE-HIDS is a research-oriented Host-based Intrusion Detection System (HIDS) designed to monitor system behavior and detect anomalies.

It is modular and flexible, separating event acquisition, analysis, alerting, and persistence, making it easy to extend and integrate new detection techniques based on rules, statistics, or machine learning.

CORE-HIDS serves as both a practical monitoring solution and a research platform for studying host-based threat detection and automated security response.

## Project Structure
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

## Architecture

CORE-HIDS follows a modular pipeline:

Event Acquisition → Analysis → Alert Generation → Logging & Persistence → Concurrent Processing

log_monitor.py – real-time host event acquisition

detector.py – orchestrates the detection workflow

baseline.py – behavioral profiling for anomaly detection

alerts.py – manages alert generation and notifications

persistence.py – stores data and system telemetry

worker.py – supports parallel execution for high performance

## Installation
git clone https://github.com/SirTeggun/CORE-HIDS.git
cd CORE-HIDS
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
Usage
python -m src.main
Configuration

System parameters can be customized in:

src/config.py
Roadmap

Full modularization of the detection pipeline

DetectionEngine refactor

Rule abstraction and severity/escalation handling

Persistence improvements and performance optimization

### Contributing

Fork the repository

Create a feature branch

Implement and test your changes

Open a Pull Request with a detailed explanation

### Tests
pytest tests/test_detector.py -v

Tests cover alerts, baseline/anomaly detection, detection engine, and log monitoring.

### License

See the LICENSE file.

### Security Notice

CORE-HIDS is a research project. Avoid exposing sensitive components without proper hardening and access control.