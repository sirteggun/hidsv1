import threading
import time
import logging
import os
import re
import json
from typing import List, Dict, Any, Optional, Callable, Union, Tuple
from dataclasses import dataclass, field
from collections import deque
from enum import Enum
from pathlib import Path

from src.pipeline.queue_manager import PrioritizedQueue, Priority
from src.models.event import Event, EventType, create_failed_login_event, create_process_event

logger = logging.getLogger(__name__)

class LogLevel(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    DEBUG = "DEBUG"

@dataclass
class CollectorMetrics:
    events_collected: int = 0
    events_discarded: int = 0
    backpressure_discards: int = 0
    parse_errors: int = 0
    last_event_time: float = 0.0
    _timestamps: deque = field(default_factory=lambda: deque(maxlen=1000))

    def record_event(self) -> None:
        now = time.time()
        self.events_collected += 1
        self.last_event_time = now
        self._timestamps.append(now)

    def record_discard(self, backpressure: bool = False) -> None:
        self.events_discarded += 1
        if backpressure:
            self.backpressure_discards += 1

    def record_parse_error(self) -> None:
        self.parse_errors += 1

    @property
    def rate(self) -> float:
        if len(self._timestamps) < 2:
            return 0.0
        window = self._timestamps[-1] - self._timestamps[0]
        if window <= 0:
            return 0.0
        return (len(self._timestamps) - 1) / window

    def to_dict(self) -> Dict[str, Any]:
        return {
            "events_collected": self.events_collected,
            "events_discarded": self.events_discarded,
            "backpressure_discards": self.backpressure_discards,
            "parse_errors": self.parse_errors,
            "last_event_time": self.last_event_time,
            "current_rate": self.rate,
        }

class BaseParser:
    def parse_line(self, line: str) -> Optional[Event]:
        raise NotImplementedError

    def register_pattern(self, pattern: str, handler: Callable) -> None:
        raise NotImplementedError

class DefaultParser(BaseParser):
    def __init__(self, patterns: Optional[Dict[str, Callable]] = None):
        self.patterns = patterns or {}
        self._compiled = {re.compile(p): h for p, h in self.patterns.items()}

    def register_pattern(self, pattern: str, handler: Callable) -> None:
        self._compiled[re.compile(pattern)] = handler

    def parse_line(self, line: str) -> Optional[Event]:
        line = line.strip()
        if not line:
            return None

        for regex, handler in self._compiled.items():
            match = regex.search(line)
            if match:
                try:
                    return handler(line, match)
                except Exception as e:
                    logger.error(f"Handler error for pattern {regex.pattern}: {e}")
                    return None

        failed_login = r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)"
        m = re.search(failed_login, line)
        if m:
            return create_failed_login_event(ip=m.group(1), source="auth.log", raw_line=line)

        process = r"EXEC: (.*) \[PID: (\d+)\]"
        m = re.search(process, line)
        if m:
            return create_process_event(pid=int(m.group(2)), name=m.group(1), cmdline=line, source="audit.log")

        return None

class LogCollector:
    def __init__(
        self,
        output_queue: Optional[PrioritizedQueue] = None,
        event_queue: Optional[PrioritizedQueue] = None,
        file_path: Optional[str] = None,
        sources: Union[str, List[str], None] = None,
        poll_interval: float = 1.0,
        batch_size: int = 100,
        filters: Optional[Dict[str, Any]] = None,
        patterns: Optional[Dict[str, Any]] = None,
        parser: Optional[BaseParser] = None,
        on_event: Optional[Callable[[Event], None]] = None,
        on_error: Optional[Callable[[Exception, Union[str, Event]], None]] = None,
        auto_start: bool = False,
        persist_path: Optional[str] = None,
        virtual_source: Optional[Callable[[], List[str]]] = None,
        queue_timeout: Optional[float] = None,
    ) -> None:
        if output_queue is None and event_queue is None:
            raise ValueError("Either output_queue or event_queue must be provided")
        self.output_queue = output_queue or event_queue

        if sources is None and file_path is not None:
            sources = file_path
        self.sources = [sources] if isinstance(sources, str) else (sources or [])
        self.poll_interval = poll_interval
        self.batch_size = batch_size
        self.filters = filters or {}
        self.patterns = patterns

        if parser is not None:
            self.parser = parser
        else:
            if patterns is not None:
                logger.debug("Initializing DefaultParser with provided patterns")
                self.parser = DefaultParser(patterns=patterns)
            else:
                self.parser = DefaultParser()

        self.on_event = on_event
        self.on_error = on_error
        self.persist_path = persist_path
        self.virtual_source = virtual_source

        if queue_timeout is not None:
            logger.debug(f"queue_timeout parameter ignored (not used)")

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._metrics = CollectorMetrics()
        self._file_positions: Dict[str, int] = {}
        self._known_files: set = set()
        self._buffer: List[Event] = []

        if persist_path:
            self._load_buffer()

        if auto_start:
            self.start()

    def _load_buffer(self) -> None:
        if not self.persist_path or not os.path.exists(self.persist_path):
            return
        try:
            with open(self.persist_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                for item in data:
                    try:
                        event = Event.from_dict(item)
                        self._buffer.append(event)
                    except Exception as e:
                        logger.warning(f"Failed to load persisted event: {e}")
                logger.info(f"Loaded {len(self._buffer)} events from persistence")
        except Exception as e:
            logger.error(f"Error loading persistence file: {e}")

    def _save_buffer(self) -> None:
        if not self.persist_path or not self._buffer:
            return
        try:
            os.makedirs(os.path.dirname(self.persist_path), exist_ok=True)
            with open(self.persist_path, "w", encoding="utf-8") as f:
                json.dump([e.to_dict() for e in self._buffer], f, default=str)
        except Exception as e:
            logger.error(f"Failed to persist events: {e}")

    def _filter_event(self, event: Event) -> bool:
        if self.filters.get("level"):
            if hasattr(event, "severity") and event.severity not in self.filters["level"]:
                return False
        if self.filters.get("keywords"):
            msg = event.message or str(event.data)
            for kw in self.filters["keywords"]:
                if kw.lower() not in msg.lower():
                    return False
        return True

    def _read_file(self, filepath: str) -> List[str]:
        lines = []
        try:
            if not os.path.exists(filepath):
                logger.warning(f"File {filepath} not found, skipping.")
                return lines

            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                last_pos = self._file_positions.get(filepath, 0)
                if last_pos > 0:
                    f.seek(last_pos)
                for line in f:
                    lines.append(line.rstrip("\n"))
                self._file_positions[filepath] = f.tell()
        except Exception as e:
            logger.error(f"Error reading {filepath}: {e}")
            if self.on_error:
                self.on_error(e, filepath)
            self._metrics.record_parse_error()
        return lines

    def _scan_directory(self, directory: str) -> List[str]:
        files = []
        try:
            for root, _, filenames in os.walk(directory):
                for fn in filenames:
                    if fn.endswith(".log"):
                        full = os.path.join(root, fn)
                        files.append(full)
                        if full not in self._known_files:
                            self._known_files.add(full)
                            logger.info(f"New log file detected: {full}")
        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {e}")
        return files

    def _flush_batch(self, events: List[Event]) -> None:
        if not events:
            return
        for event in events:
            try:
                priority = Priority.NORMAL
                if hasattr(event, "severity") and event.severity:
                    sev = event.severity
                    if sev in ("CRITICAL", "ERROR"):
                        priority = Priority.HIGH
                    elif sev == "INFO":
                        priority = Priority.LOW

                success = self.output_queue.put(event, priority=priority, allow_discard=True)
                if success:
                    logger.debug(f"Event {event.id} queued with priority {priority.name}")
                else:
                    logger.warning(f"Event {event.id} discarded due to backpressure")
                    self._metrics.record_discard(backpressure=True)
                    if self.on_error:
                        self.on_error(Exception("Backpressure discard"), event)
                if self.on_event:
                    self.on_event(event)
            except Exception as e:
                logger.exception(f"Error queueing event {event.id}")
                self._metrics.record_discard()
                if self.on_error:
                    self.on_error(e, event)

    def _collect_cycle(self) -> None:
        batch = []
        all_lines: List[Tuple[str, str]] = []

        if self.virtual_source:
            try:
                lines = self.virtual_source()
                for line in lines:
                    all_lines.append(("virtual", line))
            except Exception as e:
                logger.error(f"Virtual source error: {e}")
                self._metrics.record_parse_error()

        for source in self.sources:
            if os.path.isfile(source):
                lines = self._read_file(source)
                for line in lines:
                    all_lines.append((source, line))
            elif os.path.isdir(source):
                files = self._scan_directory(source)
                for f in files:
                    lines = self._read_file(f)
                    for line in lines:
                        all_lines.append((f, line))
            else:
                logger.warning(f"Unknown source: {source}")

        for src, line in all_lines:
            try:
                event = self.parser.parse_line(line)
                if event and self._filter_event(event):
                    batch.append(event)
                    self._metrics.record_event()
                else:
                    self._metrics.record_discard()
            except Exception as e:
                logger.exception(f"Parse error on line from {src}: {line[:100]}")
                self._metrics.record_parse_error()
                if self.on_error:
                    self.on_error(e, line)

            if len(batch) >= self.batch_size:
                self._flush_batch(batch)
                batch = []

        if batch:
            self._flush_batch(batch)

        if self.persist_path:
            self._save_buffer()

    def _run(self) -> None:
        logger.info("LogCollector started")
        while not self._stop_event.is_set():
            try:
                self._collect_cycle()
            except Exception as e:
                logger.exception("Fatal error in collection cycle")
                if self.on_error:
                    self.on_error(e, "collect_cycle")
            self._stop_event.wait(self.poll_interval)
        logger.info("LogCollector stopped")

    def start(self) -> None:
        with self._lock:
            if self._running:
                logger.warning("LogCollector already running")
                return
            self._running = True
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._run, name="LogCollector", daemon=True)
            self._thread.start()
            logger.info("LogCollector thread started")

    def stop(self, timeout: Optional[float] = None) -> None:
        with self._lock:
            if not self._running:
                return
            self._stop_event.set()
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout)
            self._running = False
            logger.info("LogCollector stopped")

    def metrics(self) -> Dict[str, Any]:
        with self._lock:
            return self._metrics.to_dict()

    def health_check(self) -> bool:
        return self._running and (self._thread is not None and self._thread.is_alive())

__all__ = ["LogCollector", "BaseParser", "DefaultParser"]