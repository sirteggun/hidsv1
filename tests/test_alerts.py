import pytest
import threading
import time
import logging
from datetime import datetime, timezone
from unittest.mock import patch
from src import alerts

@pytest.fixture
def base_event():
    return {
        "type": "suspicious_activity",
        "message": "unauthorized access detected",
        "source_ip": "192.168.1.100",
        "user": "unknown"
    }

def test_alert_structure_and_required_fields(base_event):
    alert = alerts.generate_alert(base_event)
    
    assert alert is not None
    assert isinstance(alert, dict)
    
    required_fields = {"severity", "timestamp", "description", "event_type", "source"}
    assert required_fields.issubset(alert.keys())
    
    try:
        dt = datetime.fromisoformat(alert["timestamp"].replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        assert (now - dt).total_seconds() < 5  
    except (ValueError, AttributeError):
        pytest.fail("timestamp non è in formato ISO valido")
    
    assert base_event["message"] in alert["description"]
    assert alert["event_type"] == base_event["type"]

@pytest.mark.parametrize("event_type,expected_severity", [
    ("info", "LOW"),
    ("suspicious_activity", "MEDIUM"),
    ("multiple_failures", "HIGH"),
    ("critical_anomaly", "CRITICAL"),
    ("unknown_type", "LOW"),
    ("INFO", "LOW"),
    ("SUSPICIOUS_ACTIVITY", "MEDIUM"),
])
def test_severity_mapping(event_type, expected_severity):
    event = {"type": event_type, "message": "test"}
    alert = alerts.generate_alert(event)
    assert alert["severity"] == expected_severity

def test_custom_severity_override():
    event = {"type": "info", "message": "test", "severity": "CRITICAL"}
    alert = alerts.generate_alert(event)
    assert alert["severity"] == "CRITICAL"

    event = {"type": "info", "message": "test", "severity": "LOW"}
    alert = alerts.generate_alert(event)
    assert alert["severity"] == "LOW"

def test_invalid_custom_severity_falls_back():
    event = {"type": "info", "message": "test", "severity": "INVALID"}
    alert = alerts.generate_alert(event)
    assert alert["severity"] == "LOW"

def test_missing_type_field():
    event = {"message": "no type here"}
    with pytest.raises(ValueError, match="missing required field: type"):
        alerts.generate_alert(event)

def test_missing_message_field():
    event = {"type": "test"}
    with pytest.raises(ValueError, match="missing required field: message"):
        alerts.generate_alert(event)

def test_empty_event():
    with pytest.raises(ValueError):
        alerts.generate_alert({})

def test_non_dict_input():
    with pytest.raises(TypeError):
        alerts.generate_alert("not a dict")

def test_alert_includes_context(base_event):
    alert = alerts.generate_alert(base_event)
    assert "source_ip" in alert
    assert alert["source_ip"] == base_event["source_ip"]
    assert "user" in alert
    assert alert["user"] == base_event["user"]

def test_extra_fields_are_preserved():
    event = {"type": "info", "message": "test", "extra_field": 123, "nested": {"key": "value"}}
    alert = alerts.generate_alert(event)
    assert alert["extra_field"] == 123
    assert alert["nested"] == {"key": "value"}

def test_severity_is_always_uppercase():
    event = {"type": "info", "message": "x"}
    alert = alerts.generate_alert(event)
    assert alert["severity"].isupper()

def test_custom_timestamp():
    custom_time = "2025-01-01T12:00:00+00:00"
    event = {"type": "test", "message": "x", "timestamp": custom_time}
    alert = alerts.generate_alert(event)
    assert alert["timestamp"] == custom_time

def test_default_timestamp_if_not_provided():
    event = {"type": "info", "message": "test"}
    alert = alerts.generate_alert(event)
    dt = datetime.fromisoformat(alert["timestamp"].replace('Z', '+00:00'))
    now = datetime.now(timezone.utc)
    assert (now - dt).total_seconds() < 2

def test_non_string_message():
    event = {"type": "info", "message": 12345}
    alert = alerts.generate_alert(event)
    assert "12345" in alert["description"]

def test_unicode_handling():
    event = {"type": "info", "message": "è una stringa con caratteri speciali 🚀"}
    alert = alerts.generate_alert(event)
    assert "è una stringa con caratteri speciali 🚀" in alert["description"]

def test_large_event_does_not_crash():
    large_event = {"type": "info", "message": "test"}
    for i in range(1000):
        large_event[f"field_{i}"] = "x" * 100
    alert = alerts.generate_alert(large_event)
    assert alert["severity"] == "LOW"
    for i in range(1000):
        assert f"field_{i}" in alert

def test_concurrent_alerts():
    results = []
    errors = []

    def worker():
        try:
            event = {"type": "info", "message": "concurrent"}
            alert = alerts.generate_alert(event)
            results.append(alert)
        except Exception as e:
            errors.append(e)

    threads = []
    for _ in range(50):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    assert len(errors) == 0
    assert len(results) == 50
    for alert in results:
        assert "timestamp" in alert
        assert alert["severity"] == "LOW"

def test_source_and_event_type_defaults():
    event = {"type": "info", "message": "test"}
    alert = alerts.generate_alert(event)
    assert "source" in alert
    assert alert["event_type"] == "info"

def test_alert_logged_on_generation():
    with patch("src.alerts.send_alert") as mock_send:
        event = {"type": "info", "message": "test"}
        alert = alerts.generate_alert(event)
        mock_send.assert_called_once()
        args, kwargs = mock_send.call_args
        assert kwargs.get("message") == "test"
        assert kwargs.get("severity") == "LOW"
        assert kwargs.get("event_type") == "info"