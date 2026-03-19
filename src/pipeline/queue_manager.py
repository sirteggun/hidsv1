import queue
import threading
import time
import logging
import json
from typing import Generic, TypeVar, Optional, Union, Dict, Any, Callable, List, Deque
from enum import IntEnum
from dataclasses import dataclass, field, asdict
from collections import defaultdict, deque
import uuid

logger = logging.getLogger(__name__)

T = TypeVar('T')


class Priority(IntEnum):
    HIGH = 0
    NORMAL = 1
    LOW = 2


_PRIORITY_REGISTRY: Dict[str, int] = {}
_PRIORITY_LOCK = threading.RLock()


def register_priority(name: str, value: int) -> None:
    with _PRIORITY_LOCK:
        if value in _PRIORITY_REGISTRY.values():
            raise ValueError(f"Priority value {value} already registered")
        _PRIORITY_REGISTRY[name.upper()] = value


def _get_priority_value(priority: Union[str, int, Priority]) -> int:
    if isinstance(priority, Priority):
        return priority.value
    if isinstance(priority, int):
        return priority
    if isinstance(priority, str):
        p_upper = priority.upper()
        if p_upper in Priority.__members__:
            return Priority[p_upper].value
        with _PRIORITY_LOCK:
            if p_upper in _PRIORITY_REGISTRY:
                return _PRIORITY_REGISTRY[p_upper]
        raise ValueError(f"Unknown priority name: {priority}")
    raise TypeError(f"Priority must be int, str or Priority, not {type(priority)}")


class QueueClosedError(Exception):
    pass


class _ItemWrapper(Generic[T]):
    __slots__ = ('item', 'priority', 'timestamp', 'counter', 'uuid')

    def __init__(self, item: T, priority: int, counter: int):
        self.item = item
        self.priority = priority
        self.timestamp = time.monotonic()
        self.counter = counter
        self.uuid = uuid.uuid4().hex

    def __lt__(self, other: '_ItemWrapper') -> bool:
        if self.priority != other.priority:
            return self.priority < other.priority
        return self.counter < other.counter

    def __repr__(self):
        return f"_ItemWrapper(priority={self.priority}, counter={self.counter}, item={self.item!r})"


_SENTINEL = object()


@dataclass
class QueueMetrics:
    put_total: int = 0
    get_total: int = 0
    discarded_total: int = 0
    total_wait_time: float = 0.0
    max_wait_time: float = 0.0
    size_per_priority: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    wait_time_buckets: Dict[str, int] = field(default_factory=dict)
    put_timestamps: Deque[float] = field(default_factory=lambda: deque(maxlen=1000))
    get_timestamps: Deque[float] = field(default_factory=lambda: deque(maxlen=1000))

    def record_put(self, priority: int, now: float):
        self.put_total += 1
        self.size_per_priority[priority] += 1
        self.put_timestamps.append(now)

    def record_get(self, wait_time: float, now: float):
        self.get_total += 1
        self.total_wait_time += wait_time
        if wait_time > self.max_wait_time:
            self.max_wait_time = wait_time
        for bound in [0.001, 0.01, 0.1, 0.5, 1, 5, 10, 30, 60, 300]:
            if wait_time <= bound:
                bucket = f"≤{bound}s"
                self.wait_time_buckets[bucket] = self.wait_time_buckets.get(bucket, 0) + 1
                break
        self.get_timestamps.append(now)

    def record_discard(self, priority: int, now: float):
        self.discarded_total += 1
        self.size_per_priority[priority] -= 1

    def record_priority_decrease(self, priority: int):
        self.size_per_priority[priority] -= 1

    @property
    def avg_wait_time(self) -> float:
        if self.get_total == 0:
            return 0.0
        return self.total_wait_time / self.get_total

    def percentile_wait_time(self, percentile: float) -> float:
        if not self.wait_time_buckets:
            return 0.0
        total = sum(self.wait_time_buckets.values())
        target = total * percentile / 100
        cumulative = 0
        for bound_str, count in sorted(self.wait_time_buckets.items()):
            cumulative += count
            if cumulative >= target:
                try:
                    return float(bound_str.strip('≤s'))
                except:
                    return 0.0
        return self.max_wait_time

    def put_rate(self, window: float = 60.0) -> float:
        now = time.time()
        cutoff = now - window
        count = sum(1 for ts in self.put_timestamps if ts >= cutoff)
        return count / window if window > 0 else 0.0

    def get_rate(self, window: float = 60.0) -> float:
        now = time.time()
        cutoff = now - window
        count = sum(1 for ts in self.get_timestamps if ts >= cutoff)
        return count / window if window > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['avg_wait_time'] = self.avg_wait_time
        d['p50_wait_time'] = self.percentile_wait_time(50)
        d['p95_wait_time'] = self.percentile_wait_time(95)
        d['p99_wait_time'] = self.percentile_wait_time(99)
        d['put_rate_60s'] = self.put_rate()
        d['get_rate_60s'] = self.get_rate()
        d['size_per_priority'] = dict(self.size_per_priority)
        d.pop('put_timestamps', None)
        d.pop('get_timestamps', None)
        return d


class PrioritizedQueue(Generic[T]):

    def __init__(
        self,
        maxsize: int = 0,
        *,
        validate_item: Optional[Callable[[T], bool]] = None,
        on_discard: Optional[Callable[[T, str], None]] = None,
        backpressure_config: Optional[Dict[str, Any]] = None,
    ):
        self._maxsize = maxsize
        self._validate_item = validate_item
        self._on_discard = on_discard
        self._backpressure_config = backpressure_config or {}
        self._closed = False
        self._counter = 0
        self._queue: queue.PriorityQueue = queue.PriorityQueue(maxsize=maxsize)
        self._lock = threading.RLock()
        self._metrics = QueueMetrics()

        self._low_watermark = self._backpressure_config.get('low_watermark', int(maxsize * 0.8) if maxsize else 1000)
        self._high_watermark = self._backpressure_config.get('high_watermark', maxsize if maxsize else 2000)
        self._priority_quotas = self._backpressure_config.get('priority_quotas', {})

    def _next_counter(self) -> int:
        with self._lock:
            self._counter += 1
            return self._counter

    def _check_closed(self):
        if self._closed:
            raise QueueClosedError("Queue is closed")

    def _validate(self, item: T) -> bool:
        if self._validate_item:
            try:
                if not self._validate_item(item):
                    logger.warning("Item validation failed: %s", item)
                    return False
            except Exception as e:
                logger.error("Validation callback raised exception: %s", e)
                return False
        return True

    def _enforce_backpressure(self, priority: int) -> bool:
        if self._maxsize <= 0:
            return False

        with self._lock:
            size = self.qsize()
            if size < self._maxsize:
                if priority in self._priority_quotas:
                    quota = self._priority_quotas[priority]
                    current_count = self._metrics.size_per_priority.get(priority, 0)
                    max_allowed = int(self._maxsize * quota)
                    if current_count < max_allowed:
                        return False
                    logger.warning("Priority %d quota exceeded (%d/%d), discarding items", priority, current_count, max_allowed)
                else:
                    return False

            return self._discard_oldest_internal(1, min_priority=priority + 1) > 0

    def _discard_oldest_internal(self, count: int, min_priority: Optional[int] = None) -> int:
        if self._queue.empty():
            return 0

        temp_items: List[_ItemWrapper[T]] = []
        try:
            while True:
                wrapper = self._queue.get_nowait()
                temp_items.append(wrapper)
        except queue.Empty:
            pass

        to_discard = []
        to_keep = []
        for wrapper in temp_items:
            if len(to_discard) < count and (min_priority is None or wrapper.priority >= min_priority):
                to_discard.append(wrapper)
            else:
                to_keep.append(wrapper)

        for wrapper in to_keep:
            self._queue.put(wrapper, block=False)

        now = time.time()
        for wrapper in to_discard:
            self._metrics.record_discard(wrapper.priority, now)
            if self._on_discard:
                self._on_discard(wrapper.item, "backpressure")
            logger.info("Discarded item with priority %d due to backpressure", wrapper.priority)

        return len(to_discard)

    def put(
        self,
        item: T,
        priority: Union[str, int, Priority] = Priority.NORMAL,
        block: bool = True,
        timeout: Optional[float] = None,
        allow_discard: bool = False,
    ) -> bool:
        with self._lock:
            self._check_closed()
            if not self._validate(item):
                raise ValueError(f"Item validation failed: {item}")

            prio_num = _get_priority_value(priority)
            counter = self._next_counter()
            wrapper = _ItemWrapper(item, prio_num, counter)
            now = time.time()

            if allow_discard and self._maxsize > 0 and self.qsize() >= self._maxsize:
                if self._enforce_backpressure(prio_num):
                    pass
                else:
                    logger.warning("Backpressure: discarding new item with priority %d", prio_num)
                    if self._on_discard:
                        self._on_discard(item, "backpressure_new")
                    self._metrics.record_discard(prio_num, now)
                    return False

            try:
                self._queue.put(wrapper, block=block, timeout=timeout)
            except queue.Full:
                if allow_discard:
                    if self._discard_oldest_internal(1, min_priority=prio_num) > 0:
                        try:
                            self._queue.put(wrapper, block=False)
                        except queue.Full:
                            pass
                        else:
                            self._metrics.record_put(prio_num, now)
                            logger.info("Inserted item after discard, priority %d, size %d", prio_num, self.qsize())
                            return True
                logger.warning("Queue full, item discarded (priority %d)", prio_num)
                if self._on_discard:
                    self._on_discard(item, "queue_full")
                self._metrics.record_discard(prio_num, now)
                return False
            else:
                self._metrics.record_put(prio_num, now)
                logger.debug("Item inserted with priority %d, size %d", prio_num, self.qsize())
                return True

    def put_nowait(self, item: T, priority: Union[str, int, Priority] = Priority.NORMAL) -> bool:
        return self.put(item, priority, block=False, allow_discard=False)

    def get(self, block: bool = True, timeout: Optional[float] = None) -> T:
        start = time.monotonic()
        try:
            wrapper = self._queue.get(block=block, timeout=timeout)
        except queue.Empty:
            with self._lock:
                if self._closed and self._queue.empty():
                    raise QueueClosedError("Queue is closed and empty")
            raise

        if wrapper is _SENTINEL:
            self._queue.put(_SENTINEL)
            raise QueueClosedError("Queue was closed")

        wait_time = time.monotonic() - start
        now = time.time()
        with self._lock:
            self._metrics.record_get(wait_time, now)
            self._metrics.record_priority_decrease(wrapper.priority)
        self._queue.task_done()
        logger.debug("Item extracted with priority %d, wait %.3fs, size %d", wrapper.priority, wait_time, self.qsize())
        return wrapper.item

    def get_nowait(self) -> T:
        return self.get(block=False)

    def task_done(self) -> None:
        self._queue.task_done()

    def join(self) -> None:
        self._queue.join()

    def qsize(self) -> int:
        return self._queue.qsize()

    def empty(self) -> bool:
        return self._queue.empty()

    def full(self) -> bool:
        if self._maxsize <= 0:
            return False
        return self.qsize() >= self._maxsize

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._queue.put(_SENTINEL)
            logger.info("Queue closed")

    @property
    def is_closed(self) -> bool:
        return self._closed

    def metrics(self) -> Dict[str, Any]:
        with self._lock:
            base = self._metrics.to_dict()
            base["size"] = self.qsize()
            base["maxsize"] = self._maxsize
            base["closed"] = self._closed
            return base

    def discard_oldest(self, count: int = 1, min_priority: Optional[int] = None) -> int:
        with self._lock:
            self._check_closed()
            return self._discard_oldest_internal(count, min_priority)

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "maxsize": self._maxsize,
                "closed": self._closed,
                "metrics": self._metrics.to_dict(),
                "backpressure_config": self._backpressure_config,
                "priority_registry": dict(_PRIORITY_REGISTRY),
            }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


def create_prioritized_queue(
    maxsize: int = 0,
    priorities: Dict[str, int] = None,
    **kwargs
) -> PrioritizedQueue:
    if priorities:
        for name, value in priorities.items():
            register_priority(name, value)
    return PrioritizedQueue(maxsize, **kwargs)