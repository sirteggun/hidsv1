import time
import re
import os
import queue
import threading
import ipaddress
from collections import OrderedDict
from typing import List, Dict, Any, Optional, Pattern

from src.logger import setup_logger
from src.executor import PipelineExecutor

logger = setup_logger("LogMonitor")

DEFAULT_FAILED_LOGIN_PATTERN = re.compile(
    r"failed|failure|invalid password|authentication error|login failed|authentication rejected",
    re.IGNORECASE
)

IP_REGEX = re.compile(
    r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|"
    r"(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,7}:|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}|"
    r"[A-Fa-f0-9]{1,4}:(?:(?::[A-Fa-f0-9]{1,4}){1,6})|"
    r":(?:(?::[A-Fa-f0-9]{1,4}){1,7}|:)"
)

DEFAULT_LOG_FILE = "hids.log"
DEFAULT_POLL_INTERVAL = 0.5
DEFAULT_CACHE_TTL = 2.0
DEFAULT_CACHE_MAXSIZE = 10000


class TimedLRUCache:
    def __init__(self, ttl: float, maxsize: int):
        self.ttl = ttl
        self.maxsize = maxsize
        self._cache = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[float]:
        with self._lock:
            timestamp = self._cache.get(key)
            if timestamp is None:
                return None
            if time.time() - timestamp > self.ttl:
                del self._cache[key]
                return None
            self._cache.move_to_end(key)
            return timestamp

    def put(self, key: str) -> None:
        with self._lock:
            now = time.time()
            self._cache[key] = now
            self._cache.move_to_end(key)
            while len(self._cache) > self.maxsize:
                self._cache.popitem(last=False)

    def cleanup(self) -> None:
        with self._lock:
            now = time.time()
            expired = [k for k, ts in self._cache.items() if now - ts > self.ttl]
            for k in expired:
                del self._cache[k]

    def size(self) -> int:
        with self._lock:
            return len(self._cache)


class LogFileHandler:
    def __init__(self, file_path: str, encoding: str = "utf-8", errors: str = "ignore"):
        self.file_path = file_path
        self.encoding = encoding
        self.errors = errors
        self._file = None
        self._inode = None
        self._size = 0
        self._position = 0

    def open(self) -> bool:
        try:
            self._file = open(self.file_path, "r", encoding=self.encoding, errors=self.errors)
            stat = os.fstat(self._file.fileno())
            self._inode = stat.st_ino
            self._size = stat.st_size
            self._position = self._file.tell()
            return True
        except FileNotFoundError:
            self._file = None
            return False
        except Exception as e:
            logger.error(f"Impossibile aprire il file {self.file_path}: {e}")
            return False

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None

    def ensure_open(self) -> bool:
        if self._file is None or self._file.closed:
            return self.open()
        return True

    def check_rotation(self) -> bool:
        if not self._file or self._file.closed:
            return False
        try:
            stat = os.fstat(self._file.fileno())
            current_inode = stat.st_ino
            current_size = stat.st_size
            if current_inode != self._inode or current_size < self._size:
                logger.info(f"Rotazione rilevata per {self.file_path}, riapro")
                self.close()
                if self.open():
                    self.seek_end()
                    return True
        except Exception as e:
            logger.error(f"Errore nel controllo rotazione: {e}")
        return False

    def seek_end(self) -> None:
        if self._file and not self._file.closed:
            self._file.seek(0, os.SEEK_END)
            self._position = self._file.tell()

    def readline(self) -> str:
        if not self._file or self._file.closed:
            return ""
        line = self._file.readline()
        self._position = self._file.tell()
        return line

    def get_position(self) -> int:
        return self._position


class LogMonitor:
    def __init__(
        self,
        event_queue: queue.Queue,
        file_path: str = DEFAULT_LOG_FILE,
        failed_pattern: Pattern = DEFAULT_FAILED_LOGIN_PATTERN,
        ip_regex: Pattern = IP_REGEX,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        cache_ttl: float = DEFAULT_CACHE_TTL,
        cache_maxsize: int = DEFAULT_CACHE_MAXSIZE,
        create_if_missing: bool = True,
    ):
        self.event_queue = event_queue
        self.file_path = file_path
        self.failed_pattern = failed_pattern
        self.ip_regex = ip_regex
        self.poll_interval = poll_interval
        self.create_if_missing = create_if_missing
        self.shutdown_event = threading.Event()
        self.cache = TimedLRUCache(ttl=cache_ttl, maxsize=cache_maxsize)
        self.file_handler = LogFileHandler(file_path)
        self.stats = {
            "lines_read": 0,
            "events_detected": 0,
            "ip_extracted": 0,
            "errors": 0,
            "rotations": 0,
        }
        self._stats_lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

    def _update_stats(self, **kwargs) -> None:
        with self._stats_lock:
            for k, v in kwargs.items():
                if k in self.stats:
                    self.stats[k] += v

    def _extract_ip(self, line: str) -> Optional[str]:
        match = self.ip_regex.search(line)
        if not match:
            return None
        candidate = match.group(0)
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            return None

    def _process_line(self, line: str) -> None:
        self._update_stats(lines_read=1)
        line_stripped = line.strip()
        if not line_stripped:
            return
        if not self.failed_pattern.search(line_stripped):
            return
        self._update_stats(events_detected=1)
        ip = self._extract_ip(line_stripped)
        if not ip:
            return
        self._update_stats(ip_extracted=1)
        cache_key = f"{ip}:{line_stripped}"
        if self.cache.get(cache_key) is not None:
            return
        self.cache.put(cache_key)
        logger.debug(f"IP rilevato: {ip}")
        self.event_queue.put(ip)

    def _ensure_file_exists(self) -> bool:
        if os.path.exists(self.file_path):
            return True
        if not self.create_if_missing:
            logger.warning(f"File {self.file_path} non esiste e create_if_missing è False")
            return False
        try:
            with open(self.file_path, "a"):
                os.utime(self.file_path, None)
            logger.info(f"File {self.file_path} creato vuoto")
            return True
        except Exception as e:
            logger.error(f"Impossibile creare il file {self.file_path}: {e}")
            return False

    def _monitor_loop(self) -> None:
        logger.info(f"Avvio monitoraggio su {self.file_path}")
        if not self._ensure_file_exists():
            logger.error("Monitoraggio interrotto: impossibile accedere al file")
            return
        if not self.file_handler.open():
            logger.error("Monitoraggio interrotto: impossibile aprire il file")
            return
        self.file_handler.seek_end()
        while not self.shutdown_event.is_set():
            try:
                if self.file_handler.check_rotation():
                    self._update_stats(rotations=1)
                line = self.file_handler.readline()
                if line:
                    self._process_line(line)
                else:
                    if self.shutdown_event.wait(self.poll_interval):
                        break
            except Exception as e:
                logger.exception(f"Errore nel loop di monitoraggio: {e}")
                self._update_stats(errors=1)
                if self.shutdown_event.wait(1.0):
                    break
        logger.info("Monitoraggio terminato")

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            logger.warning("Monitoraggio già avviato")
            return
        self.shutdown_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, name="LogMonitor", daemon=True)
        self._thread.start()
        logger.info("Thread di monitoraggio avviato")

    def stop(self, timeout: Optional[float] = None) -> None:
        logger.info("Arresto monitoraggio...")
        self.shutdown_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout)
        self.file_handler.close()
        logger.info("Monitoraggio arrestato")

    def get_stats(self) -> Dict[str, int]:
        with self._stats_lock:
            return dict(self.stats)

    def reset_stats(self) -> None:
        with self._stats_lock:
            for k in self.stats:
                self.stats[k] = 0


def extract_ip(text: str) -> Optional[str]:
    match = IP_REGEX.search(text)
    if match:
        try:
            ipaddress.ip_address(match.group(0))
            return match.group(0)
        except ValueError:
            pass
    return None


def monitor_log(
    file_path: str,
    event_queue: queue.Queue,
    shutdown_event,
    poll_interval: float = DEFAULT_POLL_INTERVAL
) -> None:
    monitor = LogMonitor(
        event_queue=event_queue,
        file_path=file_path,
        poll_interval=poll_interval
    )
    monitor.shutdown_event = shutdown_event
    monitor._monitor_loop()


def collect_events(limit: int = 10, log_file: Optional[str] = None) -> List[Dict[str, Any]]:
    if limit <= 0:
        return []
    path = log_file or DEFAULT_LOG_FILE
    if not os.path.exists(path):
        logger.warning(f"File {path} non esistente")
        return []

    def _inner():
        events = []
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            start = max(0, len(lines) - limit)
            for line in lines[start:]:
                line = line.strip()
                if line:
                    events.append({
                        "type": "log_line",
                        "message": line,
                        "timestamp": time.time()
                    })
        return events

    return PipelineExecutor.execute(
        _inner,
        default=[],
        fatal_exceptions=(KeyboardInterrupt, SystemExit)
    )