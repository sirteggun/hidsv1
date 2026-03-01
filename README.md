# CORE TEST

## Overview

CORE-HIDS is an advanced research-oriented Host-Based Intrusion Detection framework designed to explore modern approaches to system-level security monitoring and behavioral anomaly detection.

The project focuses on constructing a flexible detection environment capable of analyzing host activity through a modular and extensible processing pipeline. Rather than implementing a rigid detection strategy, CORE-HIDS is architected as an experimental security platform where detection logic, profiling mechanisms, and response policies can evolve independently.

The system is developed in Python following a strict separation-of-concerns design philosophy, enabling long-term maintainability and supporting progressive enhancement of detection capabilities. The architecture is optimized for extensibility, allowing future integration of rule-based detection engines, statistical anomaly models, and severity-driven escalation workflows.

CORE-HIDS is intended to function both as a practical monitoring solution and as a security research framework for studying host-based threat detection methodologies, behavioral baseline modeling, and automated security response orchestration.

---

## Project Structure

```bash
CORE-HIDS/
├── src/
│   ├── __init__.py
│   ├── alerts.py
│   ├── baseline.py
│   ├── config.py
│   ├── detector.py
│   ├── detection_context.py
│   ├── executor.py
│   ├── log_monitor.py
│   ├── logger.py
│   ├── main.py
│   ├── persistence.py
│   └── worker.py
│
├── tests/
│   ├── __init__.py
│   ├── test_alerts.py
│   ├── test_baseline.py
│   ├── test_detector.py
│   └── test_log_monitor.py
│
├── pyproject.toml
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

---

## Architecture

CORE-HIDS is designed around a modular and extensible detection architecture that separates data acquisition, analysis logic, response handling, and storage management.

The system follows a pipeline-based processing model where security events are progressively transformed and evaluated through multiple abstraction layers.

### Detection Workflow

The detection pipeline operates through the following stages:

- Event Acquisition – System activity is collected using the log_monitor module, which is responsible for   monitoring host-level signals and security-relevant events.

- Analysis Processing – Events are evaluated through behavioral profiling techniques or rule-based detection logic implemented inside the detection subsystem.

- Alert Generation – When suspicious patterns are identified, the alerts module handles security notification and reporting workflows.

- Logging and Persistence – Detection outcomes and system telemetry can be recorded for historical analysis through the persistence layer.

- Concurrent Processing – The worker module supports asynchronous execution to improve pipeline throughput and reduce detection latency.

## Core Modules

### detector.py

Implements the primary detection orchestration logic of the system and acts as the interface layer toward the future DetectionEngine architecture.

This module currently manages detection workflow execution, event evaluation coordination, and integration between monitoring components and response subsystems.

The design anticipates migration toward a more structured engine-based detection core in future releases.

### log_monitor.py

Responsible for host-level event acquisition and system activity monitoring.

The module collects security-relevant signals that may include process behavior, system logs, or other telemetry sources depending on configuration.

Its primary objective is to ensure reliable and continuous observation of runtime system events.

### baseline.py

Implements behavioral baseline profiling mechanisms used to support anomaly-based detection strategies.

The module is designed to model normal system behavior patterns, enabling the detection pipeline to identify deviations that may indicate suspicious or malicious activity.

Baseline modeling approaches can be extended in future versions to incorporate more advanced statistical or learning-based techniques.

### alerts.py

Handles security alert generation, formatting, and workflow integration for detection outcomes.

This module is responsible for translating detection signals into actionable security notifications or reporting events.

Future extensions may include multi-channel notification delivery and policy-driven response automation.

### persistence.py

Provides data storage and historical event management capabilities.

The persistence layer is intended to support long-term security telemetry retention, forensic analysis preparation, and detection performance evaluation.

Backend storage implementations may be extended to support different database engines or scalable archival solutions.

### worker.py

Supports asynchronous and concurrent processing of detection pipeline tasks.

The worker subsystem is designed to improve system throughput and reduce latency in event analysis by enabling parallel execution where appropriate.

This layer is particularly important for maintaining performance under high monitoring workloads.

---

## Installation

```bash
git clone https://github.com/SirTeggun/CORE-HIDS.git
```
```bash
cd CORE-HIDS
```
```bash
python -m venv .venv
```
```bash
source .venv/bin/activate # or .venv\Scripts\activate on Windows
```
```bash
pip install -r requirements.txt
```

---

## Usage

Run the HIDS system using:

```bash
python -m src.main
```

---

## Configuration

System parameters can be customized inside:

```bash
src/config.py
```

---

## Roadmap

🔧 Modular detection pipeline

🔧 DetectionEngine refactor

🔧 Rule abstraction layer

🔧 Severity & escalation engine

🔧 Persistence layer enhancement

🔧 Performance optimization for real-time monitoring

## Contributing

1. Fork the repository

2. Create a feature branch

3. Implement and test your changes

4. Submit a Pull Request with detailed explanation

## License

Specify the project license inside the LICENSE file.

## Security Notice

CORE-HIDS is a security research project. Avoid exposing sensitive monitoring components without proper hardening and access control.

## Tests

### Alert Generation Module

The alert generation component is responsible for transforming raw security events into structured alert objects enriched with metadata such as severity classification, timestamps, and contextual information.

### ✅ Features Covered by Tests

The module is validated through automated unit tests that verify:

Proper alert structure enforcement

Required field validation (type, message)

Severity mapping based on event categories

Automatic timestamp generation in ISO format

Context propagation from input events

Consistent uppercase severity normalization

Handling of invalid or unexpected inputs

Support for custom timestamps

### Anomaly Detection and Baseline Profiling Module.

### ✅ Features Covered by Tests

The baseline and anomaly detection components are implemented to provide statistical event profiling and security signal validation. The module leverages windowed baseline tracking, variance-based modeling, and threshold-driven anomaly evaluation to ensure reliable detection of abnormal behavioral patterns. Unit tests using GitHub Actions-compatible workflows verify correctness across edge cases, input validation scenarios, and statistical decision logic.

### Detection Engine Module

### ✅ Features Covered by Tests

The detection engine is the core behavioral security component of the project, designed to identify suspicious activities through stateful scoring, statistical baseline profiling, and burst pattern analysis. The module implements a hybrid rule-based anomaly detection pipeline combining temporal decay modeling, threshold-driven intrusion scoring, and adaptive history tracking.

### Log Monitoring Module

### ✅ Features Covered by Tests

The log monitoring component provides real-time log ingestion and event extraction capabilities for the HIDS pipeline. It supports safe file handling, Unicode log processing, timestamp annotation, and bounded event collection to prevent memory overload.

### Running Tests

```bash
pytest tests/test_detector.py -v
```