import time
import re
import os
import queue
import threading
import ipaddress
import uuid
from collections import OrderedDict
from typing import List, Dict, Any, Optional, Pattern, Callable
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class Event:
    id: str
    timestamp: float
    source: str
    raw_data: str
    parsed: Dict[str, Any] = field(default_factory=dict)
    ip: Optional[str] = None
    port: Optional[int] = None
    user: Optional[str] = None
    process: Optional[str] = None
    enriched: Dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    @property
    def time(self):
        return datetime.fromtimestamp(self.timestamp)

from src.logger import setup_logger
logger = setup_logger("LogCollector")

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
DEFAULT_QUEUE_TIMEOUT = 1.0
DEFAULT_BACKOFF_FACTOR = 2.0
DEFAULT_MAX_BACKOFF = 60.0

class TimedLRUCache:
    def __init__(self, ttl: float, maxsize: int):
        self.ttl = ttl
        self.maxsize = maxsize
        self._cache = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[float]:
        with self._lock:
            ts = self._cache.get(key)
            if ts is None:
                return None
            if time.time() - ts > self.ttl:
                del self._cache[key]
                return None
            self._cache.move_to_end(key)
            return ts

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
    def __init__(self, file_path: str, encoding: str = "utf-8", errors: str = "replace"):
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
                return self.open()
        except FileNotFoundError:
            logger.info(f"File {self.file_path} rimosso, attendo ricreazione")
            self.close()
            return False
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

class LogCollector:
    def __init__(
        self,
        event_queue: queue.Queue,
        file_path: str = DEFAULT_LOG_FILE,
        patterns: Optional[List[Dict[str, Any]]] = None,
        ip_regex: Pattern = IP_REGEX,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        cache_ttl: float = DEFAULT_CACHE_TTL,
        cache_maxsize: int = DEFAULT_CACHE_MAXSIZE,
        create_if_missing: bool = True,
        queue_timeout: float = DEFAULT_QUEUE_TIMEOUT,
    ):
        self.event_queue = event_queue
        self.file_path = file_path
        self.patterns = patterns or []
        self.ip_regex = ip_regex
        self.poll_interval = poll_interval
        self.create_if_missing = create_if_missing
        self.queue_timeout = queue_timeout
        self.shutdown_event = threading.Event()
        self.cache = TimedLRUCache(ttl=cache_ttl, maxsize=cache_maxsize)
        self.file_handler = LogFileHandler(file_path)
        self.stats = {
            "lines_read": 0,
            "events_created": 0,
            "events_queued": 0,
            "errors": 0,
            "rotations": 0,
        }
        self._stats_lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._backoff = 1.0

        for p in self.patterns:
            p['compiled'] = re.compile(p['pattern'])

    def _update_stats(self, **kwargs) -> None:
        with self._stats_lock:
            for k, v in kwargs.items():
                if k in self.stats:
                    self.stats[k] += v

    def _extract_ip(self, text: str) -> Optional[str]:
        match = self.ip_regex.search(text)
        if not match:
            return None
        candidate = match.group(0)
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            return None

    def _parse_line(self, line: str) -> Optional[Event]:
        for pattern in self.patterns:
            match = pattern['compiled'].search(line)
            if match:
                parsed = match.groupdict()
                ip = parsed.get('ip') or self._extract_ip(line)
                event = Event(
                    id=str(uuid.uuid4()),
                    timestamp=time.time(),
                    source=f"log:{self.file_path}",
                    raw_data=line.strip(),
                    parsed=parsed,
                    ip=ip,
                    user=parsed.get('user'),
                    process=parsed.get('process'),
                    port=int(parsed['port']) if parsed.get('port') and parsed['port'].isdigit() else None,
                    tags=pattern.get('tags', [])
                )
                return event
        return None

    def _ensure_file_exists(self) -> bool:
        if os.path.exists(self.file_path):
            return True
        if not self.create_if_missing:
            logger.warning(f"File {self.file_path} non esiste e create_if_missing è False")
            return False
        try:
            fd = os.open(self.file_path, os.O_WRONLY | os.O_CREAT, 0o600)
            os.close(fd)
            logger.info(f"File {self.file_path} creato vuoto")
            return True
        except Exception as e:
            logger.error(f"Impossibile creare il file {self.file_path}: {e}")
            return False

    def _collect_loop(self) -> None:
        logger.info(f"Avvio collettore su {self.file_path}")
        if not self._ensure_file_exists():
            logger.error("Collettore interrotto: impossibile accedere al file")
            return

        while not self.shutdown_event.is_set():
            if not self.file_handler.ensure_open():
                self._update_stats(errors=1)
                wait = min(self._backoff, DEFAULT_MAX_BACKOFF)
                if self.shutdown_event.wait(wait):
                    break
                self._backoff *= DEFAULT_BACKOFF_FACTOR
                continue
            self._backoff = 1.0

            try:
                if self.file_handler.check_rotation():
                    self._update_stats(rotations=1)

                line = self.file_handler.readline()
                if line:
                    self._update_stats(lines_read=1)
                    event = self._parse_line(line)
                    if event:
                        self._update_stats(events_created=1)
                        cache_key = f"{event.source}:{event.raw_data}"
                        if self.cache.get(cache_key) is not None:
                            continue
                        self.cache.put(cache_key)

                        try:
                            self.event_queue.put(event, timeout=self.queue_timeout)
                            self._update_stats(events_queued=1)
                        except queue.Full:
                            logger.warning("Coda piena, evento perso")
                else:
                    if self.shutdown_event.wait(self.poll_interval):
                        break

            except Exception as e:
                logger.exception(f"Errore nel loop di collettore: {e}")
                self._update_stats(errors=1)
                self.file_handler.close()
                wait = min(self._backoff, DEFAULT_MAX_BACKOFF)
                if self.shutdown_event.wait(wait):
                    break
                self._backoff *= DEFAULT_BACKOFF_FACTOR

        logger.info("Collettore terminato")

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            logger.warning("Collettore già avviato")
            return
        self.shutdown_event.clear()
        self._thread = threading.Thread(target=self._collect_loop, name="LogCollector")
        self._thread.daemon = False
        self._thread.start()
        logger.info("Thread collettore avviato")

    def stop(self, timeout: Optional[float] = None) -> None:
        logger.info("Arresto collettore...")
        self.shutdown_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout)
        self.file_handler.close()
        logger.info("Collettore arrestato")

    def get_stats(self) -> Dict[str, int]:
        with self._stats_lock:
            return dict(self.stats)

    def reset_stats(self) -> None:
        with self._stats_lock:
            for k in self.stats:
                self.stats[k] = 0

def monitor_log(
    file_path: str,
    event_queue: queue.Queue,
    shutdown_event,
    poll_interval: float = DEFAULT_POLL_INTERVAL
) -> None:
    default_patterns = [
        {
            'name': 'failed_login',
            'pattern': r'failed|failure|invalid password|authentication error|login failed|authentication rejected',
            'tags': ['auth', 'failed']
        }
    ]
    collector = LogCollector(
        event_queue=event_queue,
        file_path=file_path,
        patterns=default_patterns,
        poll_interval=poll_interval
    )
    collector.shutdown_event = shutdown_event
    collector._collect_loop()

def extract_ip(text: str) -> Optional[str]:
    match = IP_REGEX.search(text)
    if match:
        try:
            ipaddress.ip_address(match.group(0))
            return match.group(0)
        except ValueError:
            pass
    return None

def collect_events(limit: int = 10, log_file: Optional[str] = None) -> List[Dict[str, Any]]:
    if limit <= 0:
        return []
    path = log_file or DEFAULT_LOG_FILE
    if not os.path.exists(path):
        logger.warning(f"File {path} non esistente")
        return []

    def _inner():
        events = []
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
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

    from src.executor import PipelineExecutor
    return PipelineExecutor.execute(
        _inner,
        default=[],
        fatal_exceptions=(KeyboardInterrupt, SystemExit)
    )