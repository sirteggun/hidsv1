import sqlite3
import json
import threading
import time
import queue
import logging
import os
from typing import Any, Dict, Optional, Callable, List
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
import hashlib

logger = logging.getLogger(__name__)


class OpType(Enum):
    INSERT_IP = 1
    DELETE_IP = 2
    INSERT_BASELINE = 3
    DELETE_BASELINE = 4


@dataclass
class WriteAheadEntry:
    op_type: OpType
    key: str
    value: Optional[Any]
    timestamp: float
    checksum: str

    def verify(self) -> bool:
        data = f"{self.op_type.value}:{self.key}:{json.dumps(self.value, default=str, sort_keys=True)}:{self.timestamp}"
        computed = hashlib.sha256(data.encode()).hexdigest()
        return computed == self.checksum


class ConnectionPool:
    def __init__(self, db_path: str, max_connections: int = 5, timeout: float = 10.0):
        self.db_path = db_path
        self.max_connections = max_connections
        self.timeout = timeout
        self._pool = queue.Queue(maxsize=max_connections)
        self._active_connections = 0
        self._lock = threading.Lock()
        self._closed = False
        self._closing = False

    def _create_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=self.timeout, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def acquire(self) -> sqlite3.Connection:
        if self._closing:
            raise RuntimeError("Connection pool is closing")
        try:
            conn = self._pool.get_nowait()
        except queue.Empty:
            with self._lock:
                if self._active_connections < self.max_connections:
                    self._active_connections += 1
                    conn = self._create_connection()
                else:
                    conn = self._pool.get(timeout=self.timeout)
        return conn

    def release(self, conn: sqlite3.Connection) -> None:
        if self._closing:
            conn.close()
            with self._lock:
                self._active_connections -= 1
            return
        try:
            self._pool.put_nowait(conn)
        except queue.Full:
            conn.close()
            with self._lock:
                self._active_connections -= 1

    def close_all(self) -> None:
        self._closing = True
        while True:
            with self._lock:
                if self._active_connections == 0:
                    break
            time.sleep(0.1)
        while True:
            try:
                conn = self._pool.get_nowait()
                conn.close()
            except queue.Empty:
                break
        self._closed = True


class RetryStrategy:
    def __init__(self, max_retries: int = 3, base_delay: float = 0.1, max_delay: float = 1.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay

    def execute(self, func: Callable, *args, **kwargs) -> Any:
        last_exception = None
        for attempt in range(self.max_retries):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if attempt == self.max_retries - 1:
                    raise
                last_exception = e
                delay = min(self.base_delay * (2 ** attempt), self.max_delay)
                time.sleep(delay)
        raise last_exception


class PersistenceLayer:
    SCHEMA_VERSION = 2
    SCHEMA_MIGRATIONS = {
        1: """
            CREATE TABLE IF NOT EXISTS ip_state (
                ip TEXT PRIMARY KEY,
                state_json TEXT
            );
            CREATE TABLE IF NOT EXISTS baseline_history (
                ip TEXT PRIMARY KEY,
                history_json TEXT
            );
        """,
        2: """
            ALTER TABLE ip_state ADD COLUMN last_updated REAL DEFAULT 0;
            ALTER TABLE baseline_history ADD COLUMN last_updated REAL DEFAULT 0;
            CREATE TABLE IF NOT EXISTS wal (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                op_type INTEGER,
                key TEXT,
                value_json TEXT,
                timestamp REAL,
                checksum TEXT
            );
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            INSERT OR IGNORE INTO metadata (key, value) VALUES ('schema_version', '2');
        """
    }

    def __init__(self, db_path: str = "hids.db", max_pool_connections: int = 5,
                 flush_interval: float = 2.0, buffer_size: int = 100,
                 wal_enabled: bool = True,
                 maintenance_interval: float = 3600,  
                 vacuum_interval: Optional[float] = None): 
        self.db_path = os.path.abspath(db_path)
        self.flush_interval = flush_interval
        self.buffer_size = buffer_size
        self.wal_enabled = wal_enabled
        self.maintenance_interval = maintenance_interval
        self.vacuum_interval = vacuum_interval or (maintenance_interval * 10)

        self._pool = ConnectionPool(self.db_path, max_connections=max_pool_connections)
        self._retry = RetryStrategy()
        self._stop_event = threading.Event()
        self._flush_thread: Optional[threading.Thread] = None
        self._maintenance_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        self._ip_buffer: Dict[str, Dict[str, Any]] = {}
        self._baseline_buffer: Dict[str, list] = {}
        self._wal_buffer: List[WriteAheadEntry] = []
        self._metrics = {
            "writes": 0,
            "reads": 0,
            "flushes": 0,
            "errors": 0,
            "wal_entries": 0,
            "wal_flushes": 0,
            "buffer_flushes": 0,
            "retry_count": 0,
            "wal_corrupted_entries": 0,
        }
        self._metrics_lock = threading.Lock()

        self._init_schema()
        self._apply_wal_recovery()
        self._start_flush_thread()
        self._start_maintenance_thread()

    def _init_schema(self) -> None:
        def init(conn):
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='metadata'")
            if cursor.fetchone() is None:
                cursor.execute(self.SCHEMA_MIGRATIONS[1])
                cursor.execute(self.SCHEMA_MIGRATIONS[2])
                conn.commit()
                return
            cursor.execute("SELECT value FROM metadata WHERE key='schema_version'")
            row = cursor.fetchone()
            current_version = int(row[0]) if row else 0
            for version in range(current_version + 1, self.SCHEMA_VERSION + 1):
                if version in self.SCHEMA_MIGRATIONS:
                    cursor.executescript(self.SCHEMA_MIGRATIONS[version])
                    cursor.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', ?)", (version,))
            conn.commit()

        conn = self._pool.acquire()
        try:
            self._retry.execute(init, conn)
        finally:
            self._pool.release(conn)

    def _apply_wal_recovery(self) -> None:
        conn = self._pool.acquire()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, op_type, key, value_json, timestamp, checksum FROM wal ORDER BY id")
            rows = cursor.fetchall()
            for row in rows:
                entry = WriteAheadEntry(
                    op_type=OpType(row[1]),
                    key=row[2],
                    value=json.loads(row[3]) if row[3] else None,
                    timestamp=row[4],
                    checksum=row[5]
                )
                if not entry.verify():
                    logger.error(f"WAL entry {row[0]} corrupted, skipping recovery")
                    with self._metrics_lock:
                        self._metrics["wal_corrupted_entries"] += 1
                    continue
                if entry.op_type == OpType.INSERT_IP:
                    cursor.execute(
                        "INSERT OR REPLACE INTO ip_state (ip, state_json, last_updated) VALUES (?, ?, ?)",
                        (entry.key, json.dumps(entry.value, default=str), entry.timestamp)
                    )
                elif entry.op_type == OpType.DELETE_IP:
                    cursor.execute("DELETE FROM ip_state WHERE ip = ?", (entry.key,))
                elif entry.op_type == OpType.INSERT_BASELINE:
                    cursor.execute(
                        "INSERT OR REPLACE INTO baseline_history (ip, history_json, last_updated) VALUES (?, ?, ?)",
                        (entry.key, json.dumps(entry.value, default=str), entry.timestamp)
                    )
                elif entry.op_type == OpType.DELETE_BASELINE:
                    cursor.execute("DELETE FROM baseline_history WHERE ip = ?", (entry.key,))
            cursor.execute("DELETE FROM wal")
            conn.commit()
        finally:
            self._pool.release(conn)

    def _start_flush_thread(self) -> None:
        if self.flush_interval > 0:
            self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
            self._flush_thread.start()

    def _flush_loop(self) -> None:
        while not self._stop_event.wait(self.flush_interval):
            try:
                self.flush()
            except Exception:
                logger.exception("Error in flush loop")

    def _start_maintenance_thread(self) -> None:
        if self.maintenance_interval > 0:
            self._maintenance_thread = threading.Thread(target=self._maintenance_loop, daemon=True)
            self._maintenance_thread.start()

    def _maintenance_loop(self) -> None:
        last_vacuum = time.time()
        while not self._stop_event.wait(self.maintenance_interval):
            try:
                self._checkpoint()
                if time.time() - last_vacuum >= self.vacuum_interval:
                    self.vacuum()
                    last_vacuum = time.time()
            except Exception:
                logger.exception("Error in maintenance loop")

    def _write_wal(self, op_type: OpType, key: str, value: Any = None) -> None:
        if not self.wal_enabled:
            return
        data = f"{op_type.value}:{key}:{json.dumps(value, default=str, sort_keys=True)}:{time.time()}"
        checksum = hashlib.sha256(data.encode()).hexdigest()
        entry = WriteAheadEntry(
            op_type=op_type,
            key=key,
            value=value,
            timestamp=time.time(),
            checksum=checksum
        )
        with self._lock:
            self._wal_buffer.append(entry)
            with self._metrics_lock:
                self._metrics["wal_entries"] += 1
            if len(self._wal_buffer) >= self.buffer_size:
                self.flush()

    @contextmanager
    def _connection(self):
        conn = self._pool.acquire()
        try:
            yield conn
        finally:
            self._pool.release(conn)

    def flush(self) -> None:
        def do_flush(ip_copy, base_copy, wal_copy):
            with self._connection() as conn:
                cursor = conn.cursor()
                if wal_copy:
                    for entry in wal_copy:
                        cursor.execute(
                            "INSERT INTO wal (op_type, key, value_json, timestamp, checksum) VALUES (?, ?, ?, ?, ?)",
                            (entry.op_type.value, entry.key,
                             json.dumps(entry.value, default=str, sort_keys=True),
                             entry.timestamp, entry.checksum)
                        )
                if ip_copy:
                    cursor.executemany(
                        "INSERT OR REPLACE INTO ip_state (ip, state_json, last_updated) VALUES (?, ?, ?)",
                        [(ip, json.dumps(state, default=str), time.time()) for ip, state in ip_copy.items()]
                    )
                if base_copy:
                    cursor.executemany(
                        "INSERT OR REPLACE INTO baseline_history (ip, history_json, last_updated) VALUES (?, ?, ?)",
                        [(ip, json.dumps(hist, default=str), time.time()) for ip, hist in base_copy.items()]
                    )
                conn.commit()

        with self._lock:
            ip_copy = self._ip_buffer.copy()
            base_copy = self._baseline_buffer.copy()
            wal_copy = self._wal_buffer.copy()
            self._ip_buffer.clear()
            self._baseline_buffer.clear()
            self._wal_buffer.clear()

        if not ip_copy and not base_copy and not wal_copy:
            return

        try:
            self._retry.execute(do_flush, ip_copy, base_copy, wal_copy)
            with self._metrics_lock:
                self._metrics["flushes"] += 1
                if wal_copy:
                    self._metrics["wal_flushes"] += 1
                if ip_copy or base_copy:
                    self._metrics["buffer_flushes"] += 1
        except Exception:
            with self._metrics_lock:
                self._metrics["errors"] += 1
                self._metrics["retry_count"] += 1
            logger.exception("Flush failed, re-queueing buffers")
            with self._lock:
                self._ip_buffer.update(ip_copy)
                self._baseline_buffer.update(base_copy)
                self._wal_buffer.extend(wal_copy)
            raise

    def save_ip_state(self, ip: str, state: Dict[str, Any]) -> None:
        self._write_wal(OpType.INSERT_IP, ip, state)
        with self._lock:
            self._ip_buffer[ip] = state
            with self._metrics_lock:
                self._metrics["writes"] += 1
            if len(self._ip_buffer) >= self.buffer_size:
                self.flush()

    def load_ip_states(self) -> Dict[str, Dict[str, Any]]:
        def do_load(conn):
            cursor = conn.cursor()
            cursor.execute("SELECT ip, state_json FROM ip_state")
            result = {ip: json.loads(state) for ip, state in cursor.fetchall()}
            with self._lock:
                for ip, state in self._ip_buffer.items():
                    result[ip] = state
            return result

        with self._connection() as conn:
            try:
                res = self._retry.execute(do_load, conn)
                with self._metrics_lock:
                    self._metrics["reads"] += 1
                return res
            except Exception:
                with self._metrics_lock:
                    self._metrics["errors"] += 1
                raise

    def save_baseline(self, ip: str, history: list) -> None:
        self._write_wal(OpType.INSERT_BASELINE, ip, history)
        with self._lock:
            self._baseline_buffer[ip] = history
            with self._metrics_lock:
                self._metrics["writes"] += 1
            if len(self._baseline_buffer) >= self.buffer_size:
                self.flush()

    def load_baselines(self) -> Dict[str, list]:
        def do_load(conn):
            cursor = conn.cursor()
            cursor.execute("SELECT ip, history_json FROM baseline_history")
            result = {ip: json.loads(hist) for ip, hist in cursor.fetchall()}
            with self._lock:
                for ip, hist in self._baseline_buffer.items():
                    result[ip] = hist
            return result

        with self._connection() as conn:
            try:
                res = self._retry.execute(do_load, conn)
                with self._metrics_lock:
                    self._metrics["reads"] += 1
                return res
            except Exception:
                with self._metrics_lock:
                    self._metrics["errors"] += 1
                raise

    def delete_ip(self, ip: str) -> None:
        self._write_wal(OpType.DELETE_IP, ip)
        with self._lock:
            self._ip_buffer.pop(ip, None)
            self._baseline_buffer.pop(ip, None)

        def do_delete(conn):
            cursor = conn.cursor()
            cursor.execute("DELETE FROM ip_state WHERE ip = ?", (ip,))
            cursor.execute("DELETE FROM baseline_history WHERE ip = ?", (ip,))
            conn.commit()

        with self._connection() as conn:
            try:
                self._retry.execute(do_delete, conn)
                with self._metrics_lock:
                    self._metrics["writes"] += 1
            except Exception:
                with self._metrics_lock:
                    self._metrics["errors"] += 1
                raise

    def close(self) -> None:
        logger.info("Closing persistence layer")
        self._stop_event.set()
        if self._flush_thread:
            self._flush_thread.join(timeout=5)
        if self._maintenance_thread:
            self._maintenance_thread.join(timeout=5)
        self.flush()
        self._pool.close_all()
        logger.info("Persistence layer closed")

    def get_metrics(self) -> Dict[str, Any]:
        with self._metrics_lock:
            return self._metrics.copy()

    def reset_metrics(self) -> None:
        with self._metrics_lock:
            for k in self._metrics:
                self._metrics[k] = 0

    def vacuum(self) -> None:
        with self._connection() as conn:
            self._retry.execute(conn.execute, "VACUUM")

    def _checkpoint(self) -> None:
        with self._connection() as conn:
            self._retry.execute(conn.execute, "PRAGMA wal_checkpoint(TRUNCATE)")

    def get_pending_wal_entries(self) -> List[WriteAheadEntry]:
        with self._lock:
            return self._wal_buffer.copy()

    def get_buffered_ips(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return self._ip_buffer.copy()

    def get_buffered_baselines(self) -> Dict[str, list]:
        with self._lock:
            return self._baseline_buffer.copy()