import logging
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = "system.log"

ALERT_LOG_FILE = os.path.join(LOG_DIR, "alerts.log")

MAX_FAILED_ATTEMPTS = 5
TIME_WINDOW = 60

LOG_LEVEL = logging.DEBUG if os.getenv("DEBUG_MODE", "true").lower() == "true" else logging.INFO

HIDS_LOG_FILE = "hids_main.log"

QUEUE_TIMEOUT = 1.0

WORKER_SHUTDOWN_TIMEOUT = 10.0

MAX_QUEUE_SIZE = 10000
QUEUE_MAXSIZE = MAX_QUEUE_SIZE

NUM_WORKERS = 1

ALERT_QUEUE_MAXSIZE = 5000
DLQ_MAXSIZE = 1000
WORKER_TIMEOUT = 1.0
WORKER_REPORT_INTERVAL = 60
MAX_RETRIES = 3

BACKPRESSURE_LOW = 500
BACKPRESSURE_HIGH = 1000
BACKPRESSURE_CRITICAL = 2000

PROMETHEUS_ENABLED = True
PROMETHEUS_PORT = 8000

LOG_PATTERNS_PATH = os.path.join(BASE_DIR, "config", "log_patterns.json")