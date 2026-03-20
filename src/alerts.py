import logging
import logging.handlers
import threading
import sys
from datetime import datetime, timezone
from typing import Optional, Any, Dict
from src.executor import PipelineExecutor

_logger: Optional[logging.Logger] = None
_lock = threading.RLock()
_configured = False


class StructuredAlertFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created).isoformat(timespec='milliseconds')
        event_type = getattr(record, "event_type", "SYSTEM")
        severity = getattr(record, "severity", "INFO")
        message = record.getMessage()
        metadata = getattr(record, "metadata", "")

        if metadata is None:
            metadata = ""
        elif isinstance(metadata, dict):
            import json
            metadata = json.dumps(metadata, default=str)

        if record.exc_info:
            message += "\n" + self.formatException(record.exc_info)

        return f"{ts} | {event_type} | {severity} | {message} | {metadata}"


def setup_alert_system(
    log_file: str = "hids_alerts.log",
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
    level: int = logging.INFO
) -> logging.Logger:
    global _logger, _configured
    with _lock:
        if _configured:
            return _logger

        logger = logging.getLogger("HIDSAlert")
        logger.setLevel(level)
        logger.propagate = False

        handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        handler.setFormatter(StructuredAlertFormatter())
        logger.addHandler(handler)

        _logger = logger
        _configured = True
        return _logger


def send_alert(
    message: str,
    event_type: str = "SECURITY",
    severity: str = "WARNING",
    metadata: Optional[Any] = None,
    exc_info: bool = False
) -> None:
    def _inner():
        global _logger, _configured
        with _lock:
            if not _configured:
                setup_alert_system()

            level_map = {
                "INFO": logging.INFO,
                "WARNING": logging.WARNING,
                "ERROR": logging.ERROR,
                "CRITICAL": logging.CRITICAL
            }
            level = level_map.get(severity.upper(), logging.WARNING)

            extra = {
                "event_type": event_type,
                "severity": severity.upper(),
                "metadata": metadata
            }

            _logger.log(level, message, extra=extra, exc_info=exc_info)

    PipelineExecutor.execute(
        _inner,
        default=None,
        fatal_exceptions=(KeyboardInterrupt, SystemExit)
    )


def trigger_alert(message: str) -> None:
    send_alert(
        message,
        event_type="SECURITY",
        severity="WARNING"
    )


def generate_alert(event: Dict[str, Any]) -> Dict[str, Any]:
    def _inner():
        if not isinstance(event, dict):
            raise TypeError("event must be a dictionary")

        if "type" not in event:
            raise ValueError("missing required field: type")
        if "message" not in event:
            raise ValueError("missing required field: message")

        severity_map = {
            "info": "LOW",
            "suspicious_activity": "MEDIUM",
            "multiple_failures": "HIGH",
            "critical_anomaly": "CRITICAL"
        }
        event_type = event["type"]
        normalized_type = event_type.lower()
        mapped_severity = severity_map.get(normalized_type, "LOW")

        custom_severity = event.get("severity")
        valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if custom_severity is not None:
            custom_severity_upper = str(custom_severity).upper()
            if custom_severity_upper in valid_severities:
                severity = custom_severity_upper
            else:
                severity = mapped_severity
        else:
            severity = mapped_severity

        if "timestamp" in event:
            timestamp = event["timestamp"]
        else:
            timestamp = datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')

        description = str(event["message"])

        alert = {
            "severity": severity,
            "timestamp": timestamp,
            "description": description,
            "event_type": event_type,
            "source": event.get("source", "unknown")
        }

        for key, value in event.items():
            if key not in ["type", "message", "timestamp", "severity", "description", "event_type", "source"]:
                alert[key] = value

        send_alert(
            message=description,
            event_type=event_type,
            severity=severity,
            metadata=alert
        )

        return alert

    return PipelineExecutor.execute(
        _inner,
        default={
            "severity": "LOW",
            "timestamp": datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
            "description": "Alert generation failed due to internal error",
            "event_type": "ERROR",
            "source": "internal"
        },
        fatal_exceptions=(KeyboardInterrupt, SystemExit, TypeError, ValueError)
    )


if __name__ == "__main__":
    setup_alert_system("test_alerts.log", max_bytes=1024, backup_count=3)
    send_alert("Ping sweep detected", event_type="NETWORK", severity="WARNING")
    send_alert(
        "Suspicious modification of /etc/passwd",
        severity="CRITICAL",
        metadata={"file": "/etc/passwd", "user": "root"}
    )
    try:
        raise ValueError("Access denied")
    except ValueError:
        send_alert(
            "Exception during authentication",
            severity="ERROR",
            metadata={"username": "admin"},
            exc_info=True
        )
    print("Alerts sent. Check test_alerts.log")