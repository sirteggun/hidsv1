import ipaddress
import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional, Union, List, Set

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    FAILED_LOGIN = "failed_login"
    PROCESS_ACTIVITY = "process_activity"
    FILE_CHANGE = "file_change"
    NETWORK_CONNECTION = "network_connection"
    SYSTEM_CALL = "system_call"
    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value):
        logger.warning(f"Unknown event type encountered: {value}. Using UNKNOWN.")
        return cls.UNKNOWN

    @classmethod
    def register_custom_type(cls, name: str):
        if name not in cls._value2member_map_:
            new_member = str(name)
            setattr(cls, name.upper(), new_member)
            cls._value2member_map_[new_member] = cls.UNKNOWN
        return name


CUSTOM_EVENT_TYPES: Set[str] = set()


def register_custom_event_type(type_name: str):
    CUSTOM_EVENT_TYPES.add(type_name)


def is_valid_event_type(type_str: str) -> bool:
    return type_str in EventType._value2member_map_ or type_str in CUSTOM_EVENT_TYPES


MIN_TIMESTAMP = 1_600_000_000
MAX_TIMESTAMP = 2_200_000_000
MAX_STR_LEN = 4096
ALLOWED_EXTRA_TYPES = (str, int, float, bool, type(None))


@dataclass
class Event:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    type: str = EventType.UNKNOWN.value
    data: Dict[str, Any] = field(default_factory=dict)

    source: Optional[str] = None
    hostname: Optional[str] = None
    pid: Optional[int] = None
    severity: Optional[int] = None
    correlation_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    _created_at: float = field(default_factory=time.time, repr=False, compare=False)
    _validation_lock: threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)

    def __post_init__(self):
        with self._validation_lock:
            if not self.id:
                self.id = str(uuid.uuid4())

            self._normalize_timestamp()
            self._normalize_type()

            if not isinstance(self.data, dict):
                self.data = {"raw": str(self.data)} if self.data else {}

            self._sanitize_data()

            if self.pid is not None:
                try:
                    self.pid = int(self.pid)
                    if self.pid <= 0:
                        logger.warning(f"Invalid pid {self.pid}, setting to None")
                        self.pid = None
                except (TypeError, ValueError):
                    logger.warning(f"Non-integer pid {self.pid}, setting to None")
                    self.pid = None

            if self.severity is not None:
                try:
                    self.severity = int(self.severity)
                    if self.severity < 1 or self.severity > 10:
                        logger.warning(f"Severity {self.severity} out of range 1-10, clamping")
                        self.severity = max(1, min(10, self.severity))
                except (TypeError, ValueError):
                    logger.warning(f"Non-integer severity {self.severity}, setting to None")
                    self.severity = None

            if not isinstance(self.tags, list):
                self.tags = [str(self.tags)] if self.tags else []

    def _normalize_timestamp(self):
        try:
            ts = float(self.timestamp)
        except (TypeError, ValueError):
            logger.warning(f"Invalid timestamp {self.timestamp}, using current time")
            ts = time.time()

        if ts < MIN_TIMESTAMP:
            logger.debug(f"Timestamp {ts} too old, clamping to {MIN_TIMESTAMP}")
            ts = MIN_TIMESTAMP
        elif ts > MAX_TIMESTAMP:
            logger.debug(f"Timestamp {ts} too far in future, clamping to {MAX_TIMESTAMP}")
            ts = MAX_TIMESTAMP

        self.timestamp = ts

    def _normalize_type(self):
        if isinstance(self.type, EventType):
            self.type = self.type.value
        elif not isinstance(self.type, str):
            self.type = str(self.type)

        if not is_valid_event_type(self.type):
            logger.warning(f"Unrecognized event type '{self.type}', using UNKNOWN")
            self.type = EventType.UNKNOWN.value

    def _sanitize_data(self):
        sanitized = {}
        for k, v in self.data.items():
            if not isinstance(k, str):
                k = str(k)

            if isinstance(v, ALLOWED_EXTRA_TYPES):
                sanitized[k] = v
            elif isinstance(v, (list, tuple, set)):
                sanitized[k] = [self._sanitize_scalar(x) for x in v if self._sanitize_scalar(x) is not None]
            elif isinstance(v, dict):
                sanitized[k] = {sk: self._sanitize_scalar(sv) for sk, sv in v.items()
                                if isinstance(sk, str) and self._sanitize_scalar(sv) is not None}
            else:
                logger.debug(f"Dropping non-serializable value in data['{k}']: {type(v)}")
                continue
        self.data = sanitized

    @staticmethod
    def _sanitize_scalar(value):
        if isinstance(value, ALLOWED_EXTRA_TYPES):
            return value
        if isinstance(value, (datetime, time.struct_time)):
            return value.isoformat() if hasattr(value, 'isoformat') else str(value)
        if isinstance(value, Enum):
            return value.value
        try:
            return str(value)
        except Exception:
            return None

    def validate(self) -> bool:
        with self._validation_lock:
            if not self.id:
                raise ValueError("Event id cannot be empty")

            if self.type == EventType.FAILED_LOGIN.value:
                self._validate_failed_login()
            elif self.type == EventType.PROCESS_ACTIVITY.value:
                self._validate_process_activity()

            if self.severity is not None and not (1 <= self.severity <= 10):
                raise ValueError(f"Severity {self.severity} out of range 1-10")

            return True

    def _validate_failed_login(self):
        ip = self.data.get("ip")
        if ip:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                raise ValueError(f"Invalid IP address in failed_login data: {ip}")

        username = self.data.get("username")
        if username and len(username) > 256:
            raise ValueError(f"Username too long ({len(username)} chars)")

    def _validate_process_activity(self):
        pid = self.data.get("pid")
        if pid is not None:
            try:
                pid = int(pid)
                if pid <= 0:
                    raise ValueError(f"PID must be positive, got {pid}")
            except (TypeError, ValueError):
                raise ValueError(f"Invalid PID value: {pid}")

    def to_dict(self, clean_none: bool = True, flatten_data: bool = False) -> Dict[str, Any]:
        with self._validation_lock:
            d = asdict(self)
            d.pop("_created_at", None)
            d.pop("_validation_lock", None)

            for k, v in d.items():
                if isinstance(v, Enum):
                    d[k] = v.value
                elif k == "tags" and isinstance(v, list):
                    d[k] = [str(t) for t in v]

            if flatten_data and "data" in d and isinstance(d["data"], dict):
                data_dict = d.pop("data")
                d.update(data_dict)

            if clean_none:
                d = {k: v for k, v in d.items() if v is not None}

            return d

    def to_json(self, **kwargs) -> str:
        d = self.to_dict(clean_none=True)
        return json.dumps(d, default=self._json_default, **kwargs)

    @staticmethod
    def _json_default(obj):
        if isinstance(obj, (datetime, time.struct_time)):
            return obj.isoformat() if hasattr(obj, 'isoformat') else str(obj)
        if isinstance(obj, Enum):
            return obj.value
        if isinstance(obj, uuid.UUID):
            return str(obj)
        raise TypeError(f"Type {type(obj)} not serializable")

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Event":
        from dataclasses import fields
        known_fields = {f.name for f in fields(cls)}
        filtered = {}
        for key, value in d.items():
            if key in known_fields:
                filtered[key] = value
            else:
                if "data" not in filtered:
                    filtered["data"] = {}
                if isinstance(filtered["data"], dict):
                    filtered["data"][key] = value

        if "type" in filtered and isinstance(filtered["type"], str):
            pass

        return cls(**filtered)

    @classmethod
    def from_json(cls, json_str: str) -> "Event":
        d = json.loads(json_str)
        return cls.from_dict(d)

    def __str__(self):
        return f"Event(id={self.id}, type={self.type}, time={self.timestamp:.3f})"


def create_event(
    event_type: Union[str, EventType],
    data: Dict[str, Any],
    timestamp: Optional[float] = None,
    source: Optional[str] = None,
    hostname: Optional[str] = None,
    pid: Optional[int] = None,
    severity: Optional[int] = None,
    correlation_id: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> Event:
    return Event(
        type=event_type,
        timestamp=timestamp or time.time(),
        data=data,
        source=source,
        hostname=hostname,
        pid=pid,
        severity=severity,
        correlation_id=correlation_id,
        tags=tags or [],
    )


def create_failed_login_event(
    ip: str,
    username: Optional[str] = None,
    timestamp: Optional[float] = None,
    source: str = "auth.log",
    hostname: Optional[str] = None,
    severity: int = 5,
    correlation_id: Optional[str] = None,
    tags: Optional[List[str]] = None,
    **extra
) -> Event:
    data = {
        "ip": ip,
        "username": username,
        **extra
    }
    return create_event(
        event_type=EventType.FAILED_LOGIN,
        data=data,
        timestamp=timestamp,
        source=source,
        hostname=hostname,
        severity=severity,
        correlation_id=correlation_id,
        tags=tags,
    )


def create_process_event(
    pid: int,
    name: str,
    cmdline: Optional[str] = None,
    timestamp: Optional[float] = None,
    source: str = "auditd",
    hostname: Optional[str] = None,
    severity: int = 3,
    correlation_id: Optional[str] = None,
    tags: Optional[List[str]] = None,
    **extra
) -> Event:
    data = {
        "pid": pid,
        "name": name,
        "cmdline": cmdline,
        **extra
    }
    return create_event(
        event_type=EventType.PROCESS_ACTIVITY,
        data=data,
        timestamp=timestamp,
        source=source,
        hostname=hostname,
        severity=severity,
        correlation_id=correlation_id,
        tags=tags,
    )


def create_file_change_event(
    path: str,
    operation: str,
    timestamp: Optional[float] = None,
    source: str = "auditd",
    hostname: Optional[str] = None,
    severity: int = 4,
    correlation_id: Optional[str] = None,
    tags: Optional[List[str]] = None,
    **extra
) -> Event:
    data = {
        "path": path,
        "operation": operation,
        **extra
    }
    return create_event(
        event_type=EventType.FILE_CHANGE,
        data=data,
        timestamp=timestamp,
        source=source,
        hostname=hostname,
        severity=severity,
        correlation_id=correlation_id,
        tags=tags,
    )


def create_network_event(
    src_ip: str,
    dst_ip: str,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    protocol: str = "tcp",
    timestamp: Optional[float] = None,
    source: str = "network",
    hostname: Optional[str] = None,
    severity: int = 2,
    correlation_id: Optional[str] = None,
    tags: Optional[List[str]] = None,
    **extra
) -> Event:
    data = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        **extra
    }
    return create_event(
        event_type=EventType.NETWORK_CONNECTION,
        data=data,
        timestamp=timestamp,
        source=source,
        hostname=hostname,
        severity=severity,
        correlation_id=correlation_id,
        tags=tags,
    )


def create_syscall_event(
    syscall_name: str,
    pid: int,
    args: Optional[Dict[str, Any]] = None,
    timestamp: Optional[float] = None,
    source: str = "syscall",
    hostname: Optional[str] = None,
    severity: int = 3,
    correlation_id: Optional[str] = None,
    tags: Optional[List[str]] = None,
    **extra
) -> Event:
    data = {
        "syscall": syscall_name,
        "pid": pid,
        "args": args or {},
        **extra
    }
    return create_event(
        event_type=EventType.SYSTEM_CALL,
        data=data,
        timestamp=timestamp,
        source=source,
        hostname=hostname,
        severity=severity,
        correlation_id=correlation_id,
        tags=tags,
    )