import time
import ipaddress
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from src.alerts import trigger_alert
from src.executor import PipelineExecutor


@dataclass
class DetectionConfig:
    failed_login_score: int = 2
    repeat_penalty: int = 3
    rapid_attempt_bonus: int = 5
    risk_threshold: int = 10
    time_window: int = 60
    burst_window: int = 5
    burst_threshold: int = 3
    alert_cooldown: int = 30
    ip_ttl: int = 600
    max_tracked_ips: int = 10000
    score_decay_per_second: float = 0.5
    baseline_min_samples: int = 10
    baseline_max_history: int = 100
    baseline_default_threshold: int = 5
    baseline_std_multiplier: float = 2.0
    global_time_window: int = 60
    global_threshold: int = 50
    escalation_window: int = 300
    escalation_threshold: int = 10
    subnet_window: int = 60
    subnet_threshold: int = 30
    subnet_prefixlen: int = 24


class DetectionEngine:
    def __init__(self, config: Optional[DetectionConfig] = None, clock=None):
        self.config = config or DetectionConfig()
        self.clock = clock if clock else time.time

        self.ip_state: Dict[str, Dict[str, Any]] = {}
        self.baseline_history: Dict[str, List[float]] = {}
        self.alert_cooldown_state: Dict[str, float] = {}
        self.global_attempts: List[float] = []
        self.escalation_attempts: Dict[str, List[float]] = {}
        self.subnet_attempts: Dict[str, List[float]] = {}

    def _get_baseline_threshold(self, ip: str) -> float:
        history = self.baseline_history.get(ip, [])
        if len(history) < self.config.baseline_min_samples:
            return float(self.config.baseline_default_threshold)
        mean = sum(history) / len(history)
        if len(history) == 1:
            stdev = 1.0
        else:
            variance = sum((x - mean) ** 2 for x in history) / (len(history) - 1)
            stdev = variance ** 0.5
        return mean + self.config.baseline_std_multiplier * stdev

    def _update_baseline(self, ip: str, value: float) -> None:
        if ip not in self.baseline_history:
            self.baseline_history[ip] = []
        history = self.baseline_history[ip]
        history.append(value)
        if len(history) > self.config.baseline_max_history:
            history.pop(0)

    def _ensure_ip_state(self, ip: str, now: float) -> Dict[str, Any]:
        if ip not in self.ip_state:
            self.ip_state[ip] = {
                "attempts": [],
                "score": 0.0,
                "last_seen": now,
                "last_score_update": now
            }
        return self.ip_state[ip]

    def _apply_score_decay(self, ip: str, now: float) -> None:
        state = self.ip_state[ip]
        last_update = state.get("last_score_update", now)
        elapsed = now - last_update
        if elapsed > 0:
            decay = elapsed * self.config.score_decay_per_second
            state["score"] = max(0.0, state["score"] - decay)
            state["last_score_update"] = now

    def _cleanup_expired_attempts(self, state: Dict[str, Any], now: float) -> None:
        state["attempts"] = [
            t for t in state["attempts"]
            if now - t < self.config.time_window
        ]

    def _update_score(self, state: Dict[str, Any], now: float) -> None:
        state["score"] += self.config.failed_login_score
        if state["attempts"]:
            state["score"] += self.config.repeat_penalty
            if now - state["attempts"][-1] < 5:
                state["score"] += self.config.rapid_attempt_bonus

    def _cleanup_ips(self) -> None:
        now = self.clock()
        to_delete = []
        for ip, state in self.ip_state.items():
            if now - state["last_seen"] > self.config.ip_ttl:
                to_delete.append(ip)
        for ip in to_delete:
            del self.ip_state[ip]
            self.baseline_history.pop(ip, None)
            self.escalation_attempts.pop(ip, None)

        if len(self.ip_state) > self.config.max_tracked_ips:
            sorted_ips = sorted(
                self.ip_state.items(),
                key=lambda item: item[1]["last_seen"]
            )
            overflow = len(self.ip_state) - self.config.max_tracked_ips
            for i in range(overflow):
                ip = sorted_ips[i][0]
                del self.ip_state[ip]
                self.baseline_history.pop(ip, None)
                self.escalation_attempts.pop(ip, None)

    def _can_trigger_alert(self, key: str) -> bool:
        now = self.clock()
        last = self.alert_cooldown_state.get(key, 0.0)
        if now - last < self.config.alert_cooldown:
            return False
        self.alert_cooldown_state[key] = now
        return True

    def _trigger_alert(self, message: str) -> None:
        PipelineExecutor.execute(
            trigger_alert,
            message,
            default=None,
            fatal_exceptions=(KeyboardInterrupt, SystemExit)
        )

    def _check_baseline_alert(self, ip: str, failed_count: int, now: float) -> None:
        threshold = self._get_baseline_threshold(ip)
        if failed_count > threshold:
            if self._can_trigger_alert(f"baseline_{ip}"):
                self._trigger_alert(
                    f"Behavioural anomaly detected from IP {ip} "
                    f"(count={failed_count}, threshold={threshold:.2f})"
                )

    def _check_burst_alert(self, ip: str, state: Dict[str, Any], now: float) -> None:
        burst_count = len([
            t for t in state["attempts"]
            if now - t <= self.config.burst_window
        ])
        if burst_count >= self.config.burst_threshold:
            if self._can_trigger_alert(f"burst_{ip}"):
                self._trigger_alert(
                    f"Burst attack detected from IP {ip} "
                    f"(burst_count={burst_count})"
                )

    def _check_risk_alert(self, ip: str, state: Dict[str, Any]) -> None:
        if state["score"] >= self.config.risk_threshold:
            if self._can_trigger_alert(f"risk_{ip}"):
                self._trigger_alert(
                    f"High risk intrusion detected from IP {ip} "
                    f"(score={state['score']})"
                )

    def _check_global_alert(self, now: float) -> None:
        self.global_attempts = [
            t for t in self.global_attempts
            if now - t < self.config.global_time_window
        ]
        if len(self.global_attempts) >= self.config.global_threshold:
            if self._can_trigger_alert("global_bruteforce"):
                self._trigger_alert(
                    f"Distributed brute force attack detected "
                    f"(attempts={len(self.global_attempts)} in last {self.config.global_time_window}s)"
                )

    def _check_escalation_alert(self, ip: str, now: float) -> None:
        history = self.escalation_attempts.setdefault(ip, [])
        history.append(now)
        history[:] = [t for t in history if now - t < self.config.escalation_window]
        if len(history) >= self.config.escalation_threshold:
            if self._can_trigger_alert(f"escalation_{ip}"):
                self._trigger_alert(
                    f"Slow progressive attack detected from IP {ip} "
                    f"(attempts={len(history)} in last {self.config.escalation_window}s)"
                )

    def _check_subnet_alert(self, ip: str, now: float) -> None:
        try:
            network = ipaddress.ip_network(f"{ip}/{self.config.subnet_prefixlen}", strict=False)
            subnet = str(network)
        except Exception:
            return
        history = self.subnet_attempts.setdefault(subnet, [])
        history.append(now)
        history[:] = [t for t in history if now - t < self.config.subnet_window]
        if len(history) >= self.config.subnet_threshold:
            if self._can_trigger_alert(f"subnet_{subnet}"):
                self._trigger_alert(
                    f"Subnet attack detected from {subnet} "
                    f"(attempts={len(history)} in last {self.config.subnet_window}s)"
                )

    def process_failed_login(self, ip: str) -> None:
        now = self.clock()

        self._cleanup_ips()
        state = self._ensure_ip_state(ip, now)
        state["last_seen"] = now

        self._apply_score_decay(ip, now)
        self._cleanup_expired_attempts(state, now)
        self._update_score(state, now)
        state["attempts"].append(now)

        failed_count = len(state["attempts"])
        self._update_baseline(ip, float(failed_count))
        self._check_baseline_alert(ip, failed_count, now)
        self._check_burst_alert(ip, state, now)
        self._check_risk_alert(ip, state)

        self.global_attempts.append(now)
        self._check_global_alert(now)

        self._check_escalation_alert(ip, now)
        self._check_subnet_alert(ip, now)


def analyze_event(event: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")
    if "process" not in event:
        raise KeyError("missing required key: 'process'")
    if "activity_score" not in event:
        raise KeyError("missing required key: 'activity_score'")
    try:
        score = float(event["activity_score"])
    except (TypeError, ValueError):
        raise TypeError("activity_score must be numeric")
    detected = score >= 90
    result = {"detected": detected}
    for key, value in event.items():
        if key not in ("process", "activity_score"):
            result[key] = value
    return result