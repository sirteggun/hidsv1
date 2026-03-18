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

NUM_WORKERS = 1