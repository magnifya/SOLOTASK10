"""Rate limit algorithms plus the append only usage ledger and audit trail.

Every algorithm is a pure function of the injected ``now_ms``: no wall clock,
no sleeping and no randomness, so behaviour is fully reproducible in tests.
"""

from __future__ import annotations

import json
import math
import os
import threading
from collections import deque
from typing import Any, Deque, Dict, Iterable, List, Optional

from .config import GatewayError, QuotaPolicy

#: The single partition used by the historical policy-wide sharing mode.
POLICY_PARTITION = "-"


def _append_jsonl(path: str, entry: Dict[str, Any]) -> None:
    """Append one JSON line in a single write, so a crash cannot split a record."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    line = json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n"
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(line)


def _read_jsonl(path: str) -> List[Dict[str, Any]]:
    """Read JSON lines, skipping a torn trailing line left behind by a crash."""
    if not os.path.exists(path):
        return []
    rows: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows


def _wait_ms(need: float, rate: float) -> int:
    return int(math.ceil(need / rate)) if rate > 0 and need > 0 else 0


class TokenBucket:
    """Capacity ``capacity``, refilling ``rate`` tokens per millisecond.

    ``tokens(n) = min(capacity, tokens(n-1) + (now - last) * rate)``; a request of
    ``cost`` is admitted when ``tokens >= cost`` and then pays ``cost``.
    """

    algorithm = "token-bucket"

    def __init__(self, capacity: int, rate_per_ms: float) -> None:
        self.capacity = float(capacity)
        self.rate = float(rate_per_ms)
        self.tokens = float(capacity)
        self.last_ms: Optional[int] = None

    def allow(self, cost: int = 1, now_ms: int = 0) -> Dict[str, Any]:
        now_ms = int(now_ms)
        if self.last_ms is None:
            self.last_ms = now_ms
        elapsed = max(0, now_ms - self.last_ms)
        self.last_ms = max(self.last_ms, now_ms)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        allowed = self.tokens >= cost
        if allowed:
            self.tokens -= cost
        return {"allowed": allowed, "remaining": max(0, int(self.tokens)),
                "reset_at_ms": now_ms + _wait_ms(max(0.0, cost - self.tokens), self.rate),
                "algorithm": self.algorithm, "limit": int(self.capacity)}


class LeakyBucket:
    """Queue free leaky bucket: the level rises by ``cost`` and leaks at ``rate``.

    A request is rejected as soon as ``level + cost > capacity``; nothing is
    queued, so the caller sees the rejection immediately.
    """

    algorithm = "leaky-bucket"

    def __init__(self, capacity: int, rate_per_ms: float) -> None:
        self.capacity = float(capacity)
        self.rate = float(rate_per_ms)
        self.level = 0.0
        self.last_ms: Optional[int] = None

    def allow(self, cost: int = 1, now_ms: int = 0) -> Dict[str, Any]:
        now_ms = int(now_ms)
        if self.last_ms is None:
            self.last_ms = now_ms
        elapsed = max(0, now_ms - self.last_ms)
        self.last_ms = max(self.last_ms, now_ms)
        self.level = max(0.0, self.level - elapsed * self.rate)
        allowed = self.level + cost <= self.capacity
        if allowed:
            self.level += cost
        need = max(0.0, self.level + cost - self.capacity)
        return {"allowed": allowed, "remaining": max(0, int(self.capacity - self.level)),
                "reset_at_ms": now_ms + _wait_ms(need, self.rate),
                "algorithm": self.algorithm, "limit": int(self.capacity)}


class SlidingWindow:
    """Exact count of admitted timestamps inside the trailing ``window_ms``."""

    algorithm = "sliding-window"

    def __init__(self, limit: int, window_ms: int) -> None:
        self.limit = int(limit)
        self.window_ms = int(window_ms)
        self.stamps: Deque[int] = deque()

    def allow(self, cost: int = 1, now_ms: int = 0) -> Dict[str, Any]:
        now_ms = int(now_ms)
        cutoff = now_ms - self.window_ms
        while self.stamps and self.stamps[0] <= cutoff:
            self.stamps.popleft()
        allowed = len(self.stamps) + cost <= self.limit
        if allowed:
            self.stamps.extend([now_ms] * cost)
        remaining = max(0, self.limit - len(self.stamps))
        if remaining >= cost:
            reset_at_ms = now_ms
        else:  # the (cost - remaining)-th oldest stamp has to expire first
            index = max(0, min(len(self.stamps) - self.limit + cost - 1, len(self.stamps) - 1))
            reset_at_ms = self.stamps[index] + self.window_ms
        return {"allowed": allowed, "remaining": remaining, "reset_at_ms": reset_at_ms,
                "algorithm": self.algorithm, "limit": self.limit}


def make_bucket(policy: QuotaPolicy):
    if policy.algorithm == "token-bucket":
        return TokenBucket(policy.capacity(), policy.rate_per_ms())
    if policy.algorithm == "leaky-bucket":
        return LeakyBucket(policy.capacity(), policy.rate_per_ms())
    return SlidingWindow(policy.limit, policy.window_ms)


class Limiter:
    """Registry of policy id -> partition key -> bucket.

    Buckets are created lazily per partition and keep their state across syncs
    while the policy signature (tenant scope, partition mode and algorithm
    parameters) is unchanged; a changed signature rebuilds every partition of
    that policy from its initial state, and a removed policy drops them all.
    ``allow`` checks and consumes under one lock, so concurrent requests in the
    same partition can never admit more than the limit.
    """

    def __init__(self, policies: Optional[Iterable[Any]] = None) -> None:
        self._policies: Dict[str, QuotaPolicy] = {}
        # policy_id -> {partition: (signature, bucket)}
        self._buckets: Dict[str, Dict[str, tuple]] = {}
        self._lock = threading.RLock()
        if policies:
            self.sync(policies)

    def sync(self, policies: Iterable[Any]) -> None:
        wanted = {}
        for item in policies:
            policy = item if isinstance(item, QuotaPolicy) else QuotaPolicy.from_dict(item)
            wanted[policy.id] = policy
        with self._lock:
            kept: Dict[str, Dict[str, tuple]] = {}
            for policy_id, partitions in self._buckets.items():
                policy = wanted.get(policy_id)
                if policy is None:
                    continue  # policy removed: its partitions start fresh if readded
                signature = policy.signature()
                # Same identity and parameters: preserve each partition's state.
                kept[policy_id] = {part: entry for part, entry in partitions.items()
                                   if entry[0] == signature}
            self._buckets = kept
            self._policies = wanted

    def set_policy(self, policy: Any) -> QuotaPolicy:
        parsed = policy if isinstance(policy, QuotaPolicy) else QuotaPolicy.from_dict(policy)
        with self._lock:
            self._policies[parsed.id] = parsed
        return parsed

    def bucket(self, policy_id: str, partition: Any = POLICY_PARTITION):
        with self._lock:
            policy = self._policies.get(policy_id)
            if policy is None:
                raise GatewayError("unknown quota policy: %s" % policy_id, 404)
            partitions = self._buckets.setdefault(policy_id, {})
            signature = policy.signature()
            current = partitions.get(partition)
            if current is None or current[0] != signature:
                current = (signature, make_bucket(policy))
                partitions[partition] = current
            return current[1]

    def allow(self, policy_id: str, cost: int = 1, now_ms: int = 0,
              partition: Any = None) -> Dict[str, Any]:
        # ``None`` means the historical single policy-wide partition; tenant and
        # key modes pass an immutable tuple identifying the partition.
        part = POLICY_PARTITION if partition is None else partition
        with self._lock:
            result = self.bucket(policy_id, part).allow(cost, now_ms)
        result["policy_id"] = policy_id
        return result


class QuotaLedger:
    """Append only usage entries persisted as ``<root>/usage.jsonl``."""

    def __init__(self, root: str = "gwd_data") -> None:
        self.root = root
        self.path = os.path.join(root, "usage.jsonl")

    def record(self, tenant: str, policy_id: Optional[str], key_id: Optional[str],
               cost: int, allowed: bool, now_ms: int) -> Dict[str, Any]:
        entry = {"at": int(now_ms), "tenant": tenant, "policy_id": policy_id, "key_id": key_id,
                 "cost": int(cost), "allowed": bool(allowed)}
        _append_jsonl(self.path, entry)
        return entry

    def entries(self, tenant: Optional[str] = None,
                since_ms: Optional[int] = None) -> List[Dict[str, Any]]:
        rows = _read_jsonl(self.path)
        if tenant:
            rows = [r for r in rows if r.get("tenant") == tenant]
        if since_ms is not None:
            rows = [r for r in rows if int(r.get("at", 0)) >= int(since_ms)]
        return rows

    def usage(self, tenant: Optional[str] = None, since_ms: Optional[int] = None) -> Dict[str, Any]:
        rows = self.entries(tenant, since_ms)
        by_policy: Dict[str, Dict[str, int]] = {}
        allowed = rejected = cost = allowed_cost = 0
        for row in rows:
            bucket = by_policy.setdefault(str(row.get("policy_id") or "-"),
                                          {"requests": 0, "allowed": 0, "rejected": 0, "cost": 0})
            ok = bool(row.get("allowed"))
            entry_cost = int(row.get("cost", 0))
            bucket["requests"] += 1
            bucket["cost"] += entry_cost
            bucket["allowed" if ok else "rejected"] += 1
            cost += entry_cost
            allowed += 1 if ok else 0
            allowed_cost += entry_cost if ok else 0
            rejected += 0 if ok else 1
        return {"tenant": tenant, "since_ms": since_ms, "requests": len(rows), "allowed": allowed,
                "rejected": rejected, "cost": cost, "allowed_cost": allowed_cost,
                "by_policy": by_policy}


class AuditLog:
    """Append only request audit trail persisted as ``<root>/audit.jsonl``."""

    def __init__(self, root: str = "gwd_data") -> None:
        self.root = root
        self.path = os.path.join(root, "audit.jsonl")

    def append(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        _append_jsonl(self.path, entry)
        return entry

    def entries(self, tenant: Optional[str] = None,
                limit: Optional[int] = None) -> List[Dict[str, Any]]:
        rows = _read_jsonl(self.path)
        if tenant:
            rows = [r for r in rows if r.get("tenant") == tenant]
        if limit is not None and int(limit) > 0:
            rows = rows[-int(limit):]
        return rows
