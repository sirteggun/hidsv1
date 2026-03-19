import os
import sys
import logging
import threading
import signal
import atexit
import time
import queue
from logging.handlers import RotatingFileHandler

from src.alerts import setup_alert_system
from src.worker import detection_worker
from src.config import (
    LOG_DIR, LOG_FILE, HIDS_LOG_FILE, QUEUE_MAXSIZE, QUEUE_TIMEOUT,
    WORKER_SHUTDOWN_TIMEOUT, LOG_PATTERNS_PATH, NUM_WORKERS,
    ALERT_QUEUE_MAXSIZE, DLQ_MAXSIZE
)
from src.detector import DetectionEngine
from src.collectors.log_collector import LogCollector
from src.pipeline.queue_manager import PrioritizedQueue
from src.utils import load_patterns_from_yaml

event_queue = PrioritizedQueue(maxsize=QUEUE_MAXSIZE)
alert_queue = queue.Queue(maxsize=ALERT_QUEUE_MAXSIZE)
dlq = queue.Queue(maxsize=DLQ_MAXSIZE)
shutdown_event = threading.Event()
logger = logging.getLogger("HIDS.Main")
exit_code = 0

def _setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    log_path = os.path.join(LOG_DIR, HIDS_LOG_FILE)
    handler = RotatingFileHandler(log_path, maxBytes=10*1024*1024, backupCount=5)
    handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    logging.basicConfig(level=logging.INFO, handlers=[handler, console])
    
    # Crea file di log vuoto per evitare warning
    system_log_path = os.path.join(LOG_DIR, LOG_FILE)
    if not os.path.exists(system_log_path):
        with open(system_log_path, 'w') as f:
            f.write("")

def _signal_handler(signum, frame):
    logger.info("Received shutdown signal %d", signum)
    shutdown_event.set()

def _thread_excepthook(args):
    logger.critical("Unhandled exception in thread: %s", args.exc_value)
    shutdown_event.set()

def _worker_wrapper(target, args, kwargs):
    try:
        target(*args, **kwargs)
    except Exception as e:
        logger.exception("Worker thread crashed: %s", e)
        shutdown_event.set()
    finally:
        logger.info("Worker thread finished")

def _wait_for_shutdown(collector=None, workers=None):
    while not shutdown_event.is_set():
        if collector and not collector._thread.is_alive():
            logger.error("Collector thread died unexpectedly")
            shutdown_event.set()
            global exit_code
            exit_code = 1
        if workers:
            for w in workers:
                if not w.is_alive():
                    logger.error("Worker thread died unexpectedly")
                    shutdown_event.set()
                    exit_code = 1
        time.sleep(0.5)

def main():
    global exit_code
    _setup_logging()
    threading.excepthook = _thread_excepthook
    atexit.register(lambda: logger.info("HIDS terminated with code %d", exit_code))

    collector = None
    worker_threads = []

    try:
        setup_alert_system(os.path.join(LOG_DIR, "alerts.log"))
        logger.info("Alert system initialized")

        engine = DetectionEngine()
        logger.info("Detection engine created")

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        patterns = load_patterns_from_yaml(LOG_PATTERNS_PATH)

        collector = LogCollector(
            event_queue=event_queue,
            file_path=os.path.join(LOG_DIR, LOG_FILE),
            patterns=patterns,
            queue_timeout=QUEUE_TIMEOUT
        )
        collector.start()
        logger.info("Log collector started")

        for i in range(NUM_WORKERS):
            t = threading.Thread(
                target=_worker_wrapper,
                args=(detection_worker, (event_queue, alert_queue, dlq, engine, shutdown_event), {'worker_id': i}),
                daemon=False,
                name=f"DetectionWorker-{i}"
            )
            t.start()
            worker_threads.append(t)
            logger.info(f"Worker thread {i} started")

        _wait_for_shutdown(collector, worker_threads)

    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received")
        shutdown_event.set()
        exit_code = 130
    except Exception as e:
        logger.exception("Fatal error in main: %s", e)
        shutdown_event.set()
        exit_code = 1
    finally:
        logger.info("Shutting down, waiting for threads...")
        shutdown_event.set()

        if collector:
            collector.stop(timeout=5)

        for i, t in enumerate(worker_threads):
            if t.is_alive():
                t.join(timeout=WORKER_SHUTDOWN_TIMEOUT)
                if t.is_alive():
                    logger.warning(f"Worker thread {i} did not finish within timeout")
                    exit_code = 1

        logger.info("HIDS shutdown complete")
        sys.exit(exit_code)

if __name__ == "__main__":
    main()