import json
import logging
import threading
import time
import uuid
import re
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional, List, Union, Set

logger = logging.getLogger(__name__)


class AlertSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

    @classmethod
    def _missing_(cls, value):
        logger.warning("Unknown severity '%s', defaulting to INFO", value)
        return cls.INFO


_SEVERITY_REGISTRY: Set[str] = set()


def register_custom_severity(severity: str):
    _SEVERITY_REGISTRY.add(severity.upper())


def is_valid_severity(severity: str) -> bool:
    return severity.upper() in AlertSeverity._value2member_map_ or severity.upper() in _SEVERITY_REGISTRY


MAX_ID_LEN = 36
MAX_MESSAGE_LEN = 4096
MAX_SOURCE_LEN = 256
MAX_EVENT_ID_LEN = 36
MAX_CORRELATION_ID_LEN = 256
MAX_DEDUP_KEY_LEN = 1024
MAX_METADATA_KEYS = 100
MAX_METADATA_VALUE_LEN = 10000
TIMESTAMP_MIN = 1_600_000_000
TIMESTAMP_MAX = 2_200_000_000


@dataclass
class Alert:
    """
    Modello dati per un allarme HIDS.
    Thread-safe, con validazione e serializzazione avanzate.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    severity: Union[str, AlertSeverity] = AlertSeverity.INFO
    message: str = ""
    event_id: Optional[str] = None
    source: Optional[str] = None
    correlation_id: Optional[str] = None
    dedup_key: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    acknowledged: bool = False
    acknowledged_at: Optional[float] = None
    resolved: bool = False
    resolved_at: Optional[float] = None
    version: int = 1

    _created_at: float = field(default_factory=time.time, repr=False, compare=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)
    _hash: Optional[str] = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        with self._lock:
            self._normalize_id()
            self._normalize_timestamp()
            self._normalize_severity()
            self._normalize_message()
            self._normalize_string_fields()
            self._sanitize_metadata()
            self._normalize_workflow_dates()
            self._validate_cross_fields()
            self._update_dedup_key()
            self._compute_hash()
            self._log_creation()

    def _normalize_id(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        else:
            try:
                uuid.UUID(self.id)
            except (ValueError, AttributeError):
                logger.warning("Invalid UUID format for id '%s', generating new", self.id)
                self.id = str(uuid.uuid4())
        if len(self.id) > MAX_ID_LEN:
            logger.warning("ID too long, truncating")
            self.id = self.id[:MAX_ID_LEN]

    def _normalize_timestamp(self):
        try:
            ts = float(self.timestamp)
        except (TypeError, ValueError):
            logger.warning("Invalid timestamp %s, using current time", self.timestamp)
            ts = time.time()
        if ts < TIMESTAMP_MIN or ts > TIMESTAMP_MAX:
            logger.debug("Timestamp %s out of reasonable range, adjusting to current time", ts)
            ts = time.time()
        self.timestamp = ts

    def _normalize_severity(self):
        if isinstance(self.severity, str):
            orig = self.severity
            self.severity = self.severity.upper()
            if not is_valid_severity(self.severity):
                logger.warning("Invalid severity string '%s', using INFO", orig)
                self.severity = AlertSeverity.INFO
        elif not isinstance(self.severity, AlertSeverity):
            self.severity = AlertSeverity.INFO

    def _normalize_message(self):
        if not isinstance(self.message, str):
            self.message = str(self.message) if self.message is not None else ""
        if len(self.message) > MAX_MESSAGE_LEN:
            logger.warning("Message too long (%d chars), truncating", len(self.message))
            self.message = self.message[:MAX_MESSAGE_LEN]

    def _normalize_string_fields(self):
        if self.source and len(self.source) > MAX_SOURCE_LEN:
            logger.warning("Source too long, truncating")
            self.source = self.source[:MAX_SOURCE_LEN]
        if self.event_id and len(self.event_id) > MAX_EVENT_ID_LEN:
            logger.warning("Event_id too long, truncating")
            self.event_id = self.event_id[:MAX_EVENT_ID_LEN]
        if self.correlation_id and len(self.correlation_id) > MAX_CORRELATION_ID_LEN:
            logger.warning("Correlation_id too long, truncating")
            self.correlation_id = self.correlation_id[:MAX_CORRELATION_ID_LEN]

    def _sanitize_metadata(self):
        if not isinstance(self.metadata, dict):
            self.metadata = {"raw": str(self.metadata)} if self.metadata else {}
            return
        if len(self.metadata) > MAX_METADATA_KEYS:
            logger.warning("Metadata too many keys, truncating")
            self.metadata = dict(list(self.metadata.items())[:MAX_METADATA_KEYS])

        sanitized = {}
        for k, v in self.metadata.items():
            if not isinstance(k, str):
                k = str(k)

            def sanitize_value(val):
                if val is None or isinstance(val, (str, int, float, bool)):
                    if isinstance(val, str) and len(val) > MAX_METADATA_VALUE_LEN:
                        logger.debug("Metadata value too long, truncating")
                        return val[:MAX_METADATA_VALUE_LEN]
                    return val
                if isinstance(val, (datetime, time.struct_time)):
                    return val.isoformat() if hasattr(val, 'isoformat') else str(val)
                if isinstance(val, Enum):
                    return val.value
                if isinstance(val, (list, tuple, set)):
                    return [sanitize_value(x) for x in val if sanitize_value(x) is not None]
                if isinstance(val, dict):
                    return {str(sk): sanitize_value(sv) for sk, sv in val.items() if sanitize_value(sv) is not None}
                try:
                    s = str(val)
                    if len(s) > MAX_METADATA_VALUE_LEN:
                        s = s[:MAX_METADATA_VALUE_LEN]
                    return s
                except Exception:
                    logger.debug("Dropping non-serializable metadata key '%s'", k)
                    return None

            sv = sanitize_value(v)
            if sv is not None:
                sanitized[k] = sv
            else:
                logger.debug("Skipping metadata key '%s' due to sanitization failure", k)

        self.metadata = sanitized

    def _normalize_workflow_dates(self):
        if self.acknowledged and self.acknowledged_at is None:
            self.acknowledged_at = time.time()
        if self.resolved and self.resolved_at is None:
            self.resolved_at = time.time()

    def _validate_cross_fields(self):
        if self.resolved and not self.acknowledged:
            raise ValueError("resolved=True requires acknowledged=True")
        if self.acknowledged_at is not None and not self.acknowledged:
            raise ValueError("acknowledged_at present but acknowledged=False")
        if self.resolved_at is not None and not self.resolved:
            raise ValueError("resolved_at present but resolved=False")

    def _update_dedup_key(self):
        parts = [self.severity.value if isinstance(self.severity, AlertSeverity) else str(self.severity), self.message]
        if self.source:
            parts.append(self.source)
        if self.event_id:
            parts.append(self.event_id)
        if self.correlation_id:
            parts.append(self.correlation_id)
        for key in sorted(self.metadata.keys()):
            val = self.metadata[key]
            if isinstance(val, (str, int, float, bool)):
                parts.append(f"{key}:{val}")
            else:
                try:
                    parts.append(f"{key}:{json.dumps(val, sort_keys=True)}")
                except Exception:
                    parts.append(f"{key}:{str(val)}")
        key = "|".join(parts)
        if len(key) > MAX_DEDUP_KEY_LEN:
            logger.debug("Dedup key too long, hashing")
            key = hashlib.sha256(key.encode('utf-8')).hexdigest()
        self.dedup_key = key

    def _compute_hash(self):
        data = self.to_dict(clean_none=True)
        data.pop("_hash", None)
        data.pop("_created_at", None)
        data.pop("_lock", None)
        serialized = json.dumps(data, sort_keys=True, default=str)
        self._hash = hashlib.sha256(serialized.encode('utf-8')).hexdigest()

    def _log_creation(self):
        logger.info(
            "Alert created: id=%s severity=%s dedup_key=%s metadata=%s",
            self.id,
            self.severity.value if isinstance(self.severity, AlertSeverity) else self.severity,
            self.dedup_key,
            {k: type(v).__name__ for k, v in self.metadata.items()}
        )

    @property
    def timestamp_utc(self) -> datetime:
        """Restituisce il timestamp come datetime UTC."""
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc)

    def acknowledge(self, timestamp: Optional[float] = None) -> None:
        """Marca l'alert come riconosciuto."""
        with self._lock:
            self.acknowledged = True
            self.acknowledged_at = timestamp or time.time()
            logger.info("Alert %s acknowledged at %s", self.id, self.acknowledged_at)

    def resolve(self, timestamp: Optional[float] = None) -> None:
        """Marca l'alert come risolto."""
        with self._lock:
            if not self.acknowledged:
                raise RuntimeError("Cannot resolve an alert that has not been acknowledged")
            self.resolved = True
            self.resolved_at = timestamp or time.time()
            logger.info("Alert %s resolved at %s", self.id, self.resolved_at)

    def update_metadata(self, key: str, value: Any) -> None:
        """Aggiorna un campo metadata in modo thread-safe."""
        with self._lock:
            if not isinstance(key, str):
                key = str(key)
            self.metadata[key] = value
            self._sanitize_metadata()
            self._update_dedup_key()
            self.version += 1
            self._compute_hash()
            logger.debug("Alert %s metadata updated: %s", self.id, key)

    def remove_metadata(self, key: str) -> None:
        """Rimuove una chiave metadata in modo thread-safe."""
        with self._lock:
            self.metadata.pop(key, None)
            self._update_dedup_key()
            self.version += 1
            self._compute_hash()
            logger.debug("Alert %s metadata removed: %s", self.id, key)

    def clone(self) -> "Alert":
        """Crea una copia profonda e indipendente dell'alert."""
        with self._lock:
            data = self.to_dict(clean_none=True)
            data.pop("id", None)
            data.pop("_hash", None)
            data.pop("_created_at", None)
            data["version"] = 1
            return Alert.from_dict(data)

    def validate(self) -> bool:
        """Validazione approfondita. Solleva eccezioni se malformato."""
        with self._lock:
            if not self.id:
                raise ValueError("Alert id cannot be empty")
            if not is_valid_severity(self.severity.value if isinstance(self.severity, AlertSeverity) else self.severity):
                raise ValueError(f"Invalid severity: {self.severity}")
            if self.acknowledged and self.acknowledged_at is None:
                raise ValueError("acknowledged=True requires acknowledged_at")
            if self.resolved and self.resolved_at is None:
                raise ValueError("resolved=True requires resolved_at")
            self._validate_cross_fields()
            return True

    def to_dict(self, clean_none: bool = True) -> Dict[str, Any]:
        with self._lock:
            d = asdict(self)
            d.pop("_created_at", None)
            d.pop("_lock", None)
            if "severity" in d and isinstance(d["severity"], AlertSeverity):
                d["severity"] = d["severity"].value
            if clean_none:
                d = {k: v for k, v in d.items() if v is not None}
            return d

    def to_json(self, indent: int = 2, sort_keys: bool = True, **kwargs) -> str:
        d = self.to_dict(clean_none=True)
        return json.dumps(d, default=self._json_default, indent=indent, sort_keys=sort_keys, **kwargs)

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
    def from_dict(cls, d: Dict[str, Any]) -> "Alert":
        from dataclasses import fields
        known_fields = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in d.items() if k in known_fields}
        return cls(**filtered)

    @classmethod
    def from_json(cls, json_str: str) -> "Alert":
        d = json.loads(json_str)
        return cls.from_dict(d)

    def __str__(self):
        return f"Alert(id={self.id}, severity={self.severity.value if isinstance(self.severity, AlertSeverity) else self.severity}, msg='{self.message[:50]}')"

    def __repr__(self):
        return self.__str__()


def create_info_alert(message: str, **kwargs) -> Alert:
    return Alert(severity=AlertSeverity.INFO, message=message, **kwargs)


def create_warning_alert(message: str, **kwargs) -> Alert:
    return Alert(severity=AlertSeverity.WARNING, message=message, **kwargs)


def create_error_alert(message: str, **kwargs) -> Alert:
    return Alert(severity=AlertSeverity.ERROR, message=message, **kwargs)


def create_critical_alert(message: str, **kwargs) -> Alert:
    return Alert(severity=AlertSeverity.CRITICAL, message=message, **kwargs)


def create_alert_from_event(event_id: str, severity: Union[str, AlertSeverity], message: str, **kwargs) -> Alert:
    return Alert(event_id=event_id, severity=severity, message=message, **kwargs)