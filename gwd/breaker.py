"""Circuit breaker state machine and retry policy. Both are clock injected."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional

CLOSED = "closed"
OPEN = "open"
HALF_OPEN = "half_open"
TRANSPORT_ERROR = 0


@dataclass
class CircuitBreaker:
    """closed -> open -> half_open -> closed, driven only by ``now_ms``."""

    name: str = "default"
    failure_threshold: int = 5
    open_ms: int = 30000
    half_open_max_probes: int = 1
    success_threshold: int = 2

    def __post_init__(self) -> None:
        self.state = CLOSED
        self.failures = 0
        self.successes = 0
        self.probes = 0
        self.opened_at_ms: Optional[int] = None
        self.last_change_ms: Optional[int] = None
        self.trips = 0
        self.rejected = 0

    def _trip(self, now_ms: int) -> None:
        self.state = OPEN
        self.opened_at_ms = int(now_ms)
        self.last_change_ms = int(now_ms)
        self.failures = 0
        self.successes = 0
        self.probes = 0
        self.trips += 1

    def allow(self, now_ms: int) -> bool:
        """Admit a call, promoting open -> half_open once ``open_ms`` elapsed."""
        now_ms = int(now_ms)
        if self.state == OPEN:
            assert self.opened_at_ms is not None
            if now_ms - self.opened_at_ms < self.open_ms:
                self.rejected += 1
                return False
            self.state = HALF_OPEN
            self.last_change_ms = now_ms
            self.probes = 0
            self.successes = 0
        if self.state == HALF_OPEN:
            if self.probes >= self.half_open_max_probes:
                self.rejected += 1
                return False
            self.probes += 1
        return True

    def record(self, ok: bool, now_ms: int) -> str:
        """Record the outcome of an admitted call and return the new state."""
        now_ms = int(now_ms)
        if self.state == HALF_OPEN:
            self.probes = max(0, self.probes - 1)
            if ok:
                self.successes += 1
                self.failures = 0
                if self.successes >= self.success_threshold:
                    self.state = CLOSED
                    self.last_change_ms = now_ms
                    self.successes = 0
                    self.failures = 0
                    self.opened_at_ms = None
            else:
                self._trip(now_ms)
            return self.state
        if ok:
            self.failures = 0
        else:
            self.failures += 1
            if self.failures >= self.failure_threshold:
                self._trip(now_ms)
        return self.state

    def snapshot(self) -> Dict[str, Any]:
        return {"name": self.name, "state": self.state, "failures": self.failures,
                "successes": self.successes, "probes": self.probes,
                "failure_threshold": self.failure_threshold, "open_ms": self.open_ms,
                "half_open_max_probes": self.half_open_max_probes,
                "success_threshold": self.success_threshold,
                "opened_at_ms": self.opened_at_ms, "last_change_ms": self.last_change_ms,
                "trips": self.trips, "rejected": self.rejected}


class BreakerRegistry:
    """One breaker per upstream name, created lazily from shared settings."""

    SETTINGS = ("failure_threshold", "open_ms", "half_open_max_probes", "success_threshold")

    def __init__(self, **settings: Any) -> None:
        unknown = set(settings) - set(self.SETTINGS)
        if unknown:
            raise TypeError("unknown breaker setting(s): %s" % ", ".join(sorted(unknown)))
        self._settings = settings
        self._items: Dict[str, CircuitBreaker] = {}

    def get(self, name: str) -> CircuitBreaker:
        breaker = self._items.get(name)
        if breaker is None:
            breaker = CircuitBreaker(name=name, **self._settings)
            self._items[name] = breaker
        return breaker

    def reset(self, name: Optional[str] = None) -> List[str]:
        names = [name] if name else list(self._items)
        for item in names:
            self._items.pop(item, None)
        return names

    def snapshot(self) -> Dict[str, Dict[str, Any]]:
        return {name: breaker.snapshot() for name, breaker in sorted(self._items.items())}


@dataclass
class RetryPolicy:
    """Exponential backoff, no jitter by default so delays are reproducible."""

    max_attempts: int = 3
    base_ms: int = 100
    max_ms: int = 2000
    jitter_ratio: float = 0.0
    retry_on: FrozenSet[int] = field(
        default_factory=lambda: frozenset({408, 429, 500, 502, 503, 504}))

    def should_retry(self, attempt: int, status: int) -> bool:
        """``attempt`` is 1 based; status 0 means a transport error."""
        if attempt >= self.max_attempts:
            return False
        if status == TRANSPORT_ERROR:
            return True
        return int(status) in self.retry_on

    def delay_ms(self, attempt: int) -> int:
        base = min(self.max_ms, self.base_ms * (2 ** max(0, attempt - 1)))
        if self.jitter_ratio > 0:
            digest = hashlib.sha256(("attempt:%d" % attempt).encode("utf-8")).digest()
            fraction = int.from_bytes(digest[:4], "big") / float(1 << 32)
            base = base * (1.0 - self.jitter_ratio * fraction)
        return int(base)
