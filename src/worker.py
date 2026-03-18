import queue
import logging
import time
import threading
from typing import Optional, Dict, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class WorkerMetrics:
    total_processed: int = 0
    success_count: int = 0
    failure_count: int = 0
    ewma_processing_time: Optional[float] = None
    last_reset: float = field(default_factory=time.time)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def update(self, success: bool, processing_time: float) -> None:
        alpha = 0.1
        with self._lock:
            self.total_processed += 1
            if success:
                self.success_count += 1
            else:
                self.failure_count += 1
            if self.ewma_processing_time is None:
                self.ewma_processing_time = processing_time
            else:
                self.ewma_processing_time = (
                    alpha * processing_time + (1 - alpha) * self.ewma_processing_time
                )

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_processed": self.total_processed,
                "success_count": self.success_count,
                "failure_count": self.failure_count,
                "ewma_processing_time": self.ewma_processing_time,
                "uptime": time.time() - self.last_reset,
            }

    def reset(self) -> None:
        with self._lock:
            self.total_processed = 0
            self.success_count = 0
            self.failure_count = 0
            self.ewma_processing_time = None
            self.last_reset = time.time()


class BackpressureMonitor:
    def __init__(self, threshold: int = 1000, check_interval: float = 10.0):
        self.threshold = threshold
        self.check_interval = check_interval
        self._warning_active = False
        self._last_check = 0.0
        self._lock = threading.Lock()

    def check(self, queue_size: int, now: float) -> bool:
        with self._lock:
            if now - self._last_check < self.check_interval:
                return self._warning_active
            self._last_check = now
            if queue_size > self.threshold:
                if not self._warning_active:
                    logger.warning(
                        "Backpressure detected: queue size = %d (threshold %d)",
                        queue_size, self.threshold
                    )
                    self._warning_active = True
            else:
                if self._warning_active:
                    logger.info("Backpressure resolved: queue size = %d", queue_size)
                    self._warning_active = False
            return self._warning_active


class Worker:
    def __init__(
        self,
        event_queue: queue.Queue,
        engine,
        shutdown_event: threading.Event,
        worker_id: int,
        timeout: float = 1.0,
        metrics: Optional[WorkerMetrics] = None,
        backpressure_threshold: int = 1000,
        heartbeat_dict: Optional[Dict[int, float]] = None,
    ):
        self.event_queue = event_queue
        self.engine = engine
        self.shutdown_event = shutdown_event
        self.worker_id = worker_id
        self.timeout = timeout
        self.metrics = metrics or WorkerMetrics()
        self.backpressure_monitor = BackpressureMonitor(threshold=backpressure_threshold)
        self.heartbeat_dict = heartbeat_dict
        self._heartbeat_lock = threading.Lock()
        self._stop_requested = False
        self._thread: Optional[threading.Thread] = None

    def _update_heartbeat(self) -> None:
        if self.heartbeat_dict is not None:
            with self._heartbeat_lock:
                self.heartbeat_dict[self.worker_id] = time.monotonic()

    def _process_item(self, ip: str) -> bool:
        if ip is None or not isinstance(ip, str):
            logger.warning("Invalid item received: %s", ip)
            return False
        logger.debug("Worker %d processing IP: %s", self.worker_id, ip)
        self.engine.process_failed_login(ip)
        return True

    def _run_loop(self) -> None:
        logger.info("Worker %d started", self.worker_id)
        last_report = time.monotonic()
        report_interval = 60

        while not self.shutdown_event.is_set() and not self._stop_requested:
            try:
                self._update_heartbeat()
                ip = self.event_queue.get(timeout=self.timeout)
            except queue.Empty:
                continue
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                logger.exception("Worker %d: unexpected error getting item", self.worker_id)
                continue

            start = time.monotonic()
            success = False
            try:
                success = self._process_item(ip)
            except Exception:
                logger.exception("Worker %d: error processing IP %s", self.worker_id, ip)
            finally:
                elapsed = time.monotonic() - start
                self.metrics.update(success, elapsed)
                self.event_queue.task_done()

            now = time.monotonic()
            self.backpressure_monitor.check(self.event_queue.qsize(), now)

            if now - last_report >= report_interval:
                snap = self.metrics.snapshot()
                logger.info(
                    "Worker %d heartbeat - processed: %d, success: %d, failures: %d, ewma: %.3fs",
                    self.worker_id,
                    snap["total_processed"],
                    snap["success_count"],
                    snap["failure_count"],
                    snap["ewma_processing_time"] or 0.0
                )
                last_report = now

        logger.info("Worker %d stopped", self.worker_id)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            logger.warning("Worker %d already running", self.worker_id)
            return
        self._stop_requested = False
        self._thread = threading.Thread(target=self._run_loop, name=f"Worker-{self.worker_id}", daemon=True)
        self._thread.start()

    def stop(self, timeout: Optional[float] = None) -> None:
        logger.info("Stopping worker %d", self.worker_id)
        self._stop_requested = True
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout)

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def health_status(self) -> Dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "alive": self.is_alive(),
            "metrics": self.metrics.snapshot(),
        }


def detection_worker(
    event_queue: queue.Queue,
    engine,
    shutdown_event: threading.Event,
    timeout: float = 1.0,
    metrics: Optional[WorkerMetrics] = None,
    backpressure_threshold: int = 1000,
    heartbeat_dict: Optional[Dict[int, float]] = None,
    worker_id: int = 0,
) -> None:
    worker = Worker(
        event_queue=event_queue,
        engine=engine,
        shutdown_event=shutdown_event,
        worker_id=worker_id,
        timeout=timeout,
        metrics=metrics,
        backpressure_threshold=backpressure_threshold,
        heartbeat_dict=heartbeat_dict,
    )
    worker._run_loop()