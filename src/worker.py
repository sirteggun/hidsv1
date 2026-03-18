import queue
import logging
import time
import threading
import random
from typing import Optional, Dict, Any, Union
from dataclasses import dataclass, field

from prometheus_client import Counter, Histogram, Gauge

from src.models.event import Event
from src.models.alert import Alert
from src.pipeline.queue_manager import PrioritizedQueue

logger = logging.getLogger(__name__)

events_processed_total = Counter(
    'worker_events_processed_total',
    'Total events processed',
    ['worker_id', 'status']
)
alerts_generated_total = Counter(
    'worker_alerts_generated_total',
    'Total alerts generated',
    ['worker_id']
)
processing_time_histogram = Histogram(
    'worker_event_processing_seconds',
    'Event processing time',
    ['worker_id'],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]
)
input_queue_size = Gauge(
    'input_queue_size',
    'Current size of input queue'
)
dlq_size = Gauge(
    'dead_letter_queue_size',
    'Current size of dead letter queue'
)

@dataclass
class RetryableEvent:
    event: Event
    retries_left: int = 3
    last_error: Optional[str] = None
    next_retry_time: float = 0.0

    def should_retry(self, now: float) -> bool:
        return self.retries_left > 0 and now >= self.next_retry_time

    def compute_backoff(self, base_delay=1.0, factor=2.0, jitter=True):
        delay = base_delay * (factor ** (3 - self.retries_left))
        if jitter:
            delay *= random.uniform(0.8, 1.2)
        return delay

    def mark_failure(self, error_msg: str, now: float):
        self.retries_left -= 1
        self.last_error = error_msg
        if self.retries_left > 0:
            self.next_retry_time = now + self.compute_backoff()

@dataclass
class WorkerMetrics:
    total_processed: int = 0
    success_count: int = 0
    failure_count: int = 0
    alerts_generated: int = 0
    discarded_count: int = 0
    ewma_processing_time: Optional[float] = None
    last_reset: float = field(default_factory=time.time)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def update(self, success: bool, processing_time: float, alerts_count: int = 0) -> None:
        alpha = 0.1
        with self._lock:
            self.total_processed += 1
            if success:
                self.success_count += 1
            else:
                self.failure_count += 1
            self.alerts_generated += alerts_count
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
                "alerts_generated": self.alerts_generated,
                "discarded_count": self.discarded_count,
                "ewma_processing_time": self.ewma_processing_time,
                "uptime": time.time() - self.last_reset,
            }

    def reset(self) -> None:
        with self._lock:
            self.total_processed = 0
            self.success_count = 0
            self.failure_count = 0
            self.alerts_generated = 0
            self.discarded_count = 0
            self.ewma_processing_time = None
            self.last_reset = time.time()

class BackpressureManager:
    def __init__(self, low=500, high=1000, critical=2000):
        self.low = low
        self.high = high
        self.critical = critical
        self.state = 'normal'

    def update(self, qsize):
        if qsize > self.critical:
            self.state = 'shedding'
        elif qsize > self.high:
            self.state = 'throttled'
        elif qsize <= self.low:
            self.state = 'normal'
        return self.state

class Worker:
    def __init__(
        self,
        event_queue: PrioritizedQueue,
        alert_queue: queue.Queue,
        dlq: queue.Queue,
        engine,
        shutdown_event: threading.Event,
        worker_id: int,
        timeout: float = 1.0,
        metrics: Optional[WorkerMetrics] = None,
        backpressure_config: Optional[Dict[str, int]] = None,
        max_retries: int = 3,
        heartbeat_dict: Optional[Dict[int, float]] = None,
        heartbeat_lock: Optional[threading.Lock] = None,
    ):
        self.event_queue = event_queue
        self.alert_queue = alert_queue
        self.dlq = dlq
        self.engine = engine
        self.shutdown_event = shutdown_event
        self.worker_id = worker_id
        self.timeout = timeout
        self.metrics = metrics or WorkerMetrics()
        self.max_retries = max_retries
        self.heartbeat_dict = heartbeat_dict
        self.heartbeat_lock = heartbeat_lock
        self._stop_requested = False
        self._thread: Optional[threading.Thread] = None

        bp_config = backpressure_config or {}
        self.bp_manager = BackpressureManager(
            low=bp_config.get('low', 500),
            high=bp_config.get('high', 1000),
            critical=bp_config.get('critical', 2000)
        )

    def _update_heartbeat(self) -> None:
        if self.heartbeat_dict is not None and self.heartbeat_lock is not None:
            with self.heartbeat_lock:
                self.heartbeat_dict[self.worker_id] = time.monotonic()

    def _process_event(self, event: Event) -> int:
        if not isinstance(event, Event):
            logger.warning("Worker %d received non-Event item: %s", self.worker_id, type(event))
            return 0
        logger.debug("Worker %d processing event: %s", self.worker_id, event.id, extra={"trace_id": event.id})
        alerts = self.engine.process_event(event)
        if alerts:
            for alert in alerts:
                try:
                    self.alert_queue.put(alert, timeout=1.0)
                except queue.Full:
                    logger.warning("Alert queue full, dropping alert %s", alert.id, extra={"trace_id": event.id})
        return len(alerts)

    def _run_loop(self) -> None:
        logger.info("Worker %d started", self.worker_id)
        last_report = time.monotonic()
        report_interval = 60

        while not self.shutdown_event.is_set() and not self._stop_requested:
            self._update_heartbeat()
            qsize = self.event_queue.qsize()
            input_queue_size.set(qsize)
            dlq_size.set(self.dlq.qsize())

            state = self.bp_manager.update(qsize)

            get_timeout = self.timeout
            if state == 'shedding':
                if random.random() < 0.5:
                    try:
                        self.event_queue.get_nowait()
                        self.event_queue.task_done()
                        self.metrics.discarded_count += 1
                    except queue.Empty:
                        pass
                    continue
                get_timeout = 0.1
            elif state == 'throttled':
                get_timeout = 0.5

            try:
                retry_event = self.event_queue.get(timeout=get_timeout)
            except queue.Empty:
                continue
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                logger.exception("Worker %d: unexpected error getting item", self.worker_id)
                continue

            now = time.time()
            if isinstance(retry_event, RetryableEvent):
                if not retry_event.should_retry(now):
                    self.event_queue.put(retry_event, priority='low')
                    self.event_queue.task_done()
                    continue
                event = retry_event.event
            else:
                event = retry_event
                retry_event = RetryableEvent(event=event, retries_left=self.max_retries)

            start = time.monotonic()
            success = False
            alerts_count = 0
            try:
                alerts_count = self._process_event(event)
                success = True
                self.event_queue.task_done()
                status = 'success'
            except Exception as e:
                logger.exception("Worker %d: error processing event %s", self.worker_id, event.id, extra={"trace_id": event.id})
                retry_event.mark_failure(str(e), now)
                if retry_event.retries_left > 0:
                    self.event_queue.put(retry_event, priority='low')
                else:
                    self.dlq.put(retry_event)
                self.event_queue.task_done()
                status = 'failure'
            finally:
                elapsed = time.monotonic() - start
                self.metrics.update(success, elapsed, alerts_count)
                events_processed_total.labels(worker_id=self.worker_id, status=status).inc()
                if alerts_count:
                    alerts_generated_total.labels(worker_id=self.worker_id).inc(alerts_count)
                processing_time_histogram.labels(worker_id=self.worker_id).observe(elapsed)

            now_mono = time.monotonic()
            if now_mono - last_report >= report_interval:
                snap = self.metrics.snapshot()
                logger.info(
                    "Worker %d heartbeat - processed: %d, success: %d, failures: %d, alerts: %d, discarded: %d, ewma: %.3fs",
                    self.worker_id,
                    snap["total_processed"],
                    snap["success_count"],
                    snap["failure_count"],
                    snap["alerts_generated"],
                    snap["discarded_count"],
                    snap["ewma_processing_time"] or 0.0
                )
                last_report = now_mono

        logger.info("Worker %d stopped", self.worker_id)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            logger.warning("Worker %d already running", self.worker_id)
            return
        self._stop_requested = False
        self._thread = threading.Thread(target=self._run_loop, name=f"Worker-{self.worker_id}")
        self._thread.daemon = False
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
    event_queue: PrioritizedQueue,
    alert_queue: queue.Queue,
    dlq: queue.Queue,
    engine,
    shutdown_event: threading.Event,
    timeout: float = 1.0,
    metrics: Optional[WorkerMetrics] = None,
    backpressure_config: Optional[Dict[str, int]] = None,
    max_retries: int = 3,
    heartbeat_dict: Optional[Dict[int, float]] = None,
    heartbeat_lock: Optional[threading.Lock] = None,
    worker_id: int = 0,
) -> None:
    worker = Worker(
        event_queue=event_queue,
        alert_queue=alert_queue,
        dlq=dlq,
        engine=engine,
        shutdown_event=shutdown_event,
        worker_id=worker_id,
        timeout=timeout,
        metrics=metrics,
        backpressure_config=backpressure_config,
        max_retries=max_retries,
        heartbeat_dict=heartbeat_dict,
        heartbeat_lock=heartbeat_lock,
    )
    worker._run_loop()