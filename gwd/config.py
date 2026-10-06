"""Route, API key and quota policy models with validation and mtime hot reload."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

ALGORITHMS = ("token-bucket", "leaky-bucket", "sliding-window")
PARTITION_MODES = ("policy", "tenant", "key")
ANY_TENANT = "*"
ANY_SCOPE = "*"
EMPTY_CONFIG: Dict[str, Any] = {"routes": [], "keys": [], "quota_policies": []}


class GatewayError(Exception):
    """A rejected configuration or request; ``status`` is the HTTP status to use."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.message = str(message)
        self.status = int(status)


def sha256_hex(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _get(data: Dict[str, Any], key: str, kind: type, where: str,
         default: Any = None, required: bool = False) -> Any:
    if key not in data or data[key] is None:
        if required:
            raise GatewayError("%s: missing field %r" % (where, key))
        return default
    value = data[key]
    bad = (kind is int and isinstance(value, bool)) or not isinstance(value, kind)
    if bad:
        raise GatewayError("%s: field %r must be %s" % (where, key, kind.__name__))
    return value


def _str_map(data: Dict[str, Any], key: str, where: str) -> Dict[str, str]:
    raw = _get(data, key, dict, where, default={})
    if any(not isinstance(k, str) or not isinstance(v, (str, int, float)) for k, v in raw.items()):
        raise GatewayError("%s: %r entries must map string to scalar" % (where, key))
    return {str(k): str(v) for k, v in raw.items()}


def _str_list(data: Dict[str, Any], key: str, where: str) -> List[str]:
    raw = _get(data, key, list, where, default=[])
    if any(not isinstance(item, str) for item in raw):
        raise GatewayError("%s: %r entries must be strings" % (where, key))
    return list(raw)


def _fallback_list(data: Dict[str, Any], key: str, where: str, primary: str) -> List[str]:
    """Ordered fallback upstream names: omitted means [], null/non-array and any
    non-string, empty, duplicated or primary-repeating entry is rejected."""
    if key not in data:
        return []
    raw = data[key]
    if not isinstance(raw, list):
        raise GatewayError("%s: %r must be an array of upstream names" % (where, key))
    out: List[str] = []
    for item in raw:
        if not isinstance(item, str) or not item:
            raise GatewayError("%s: %r entries must be non-empty upstream names" % (where, key))
        if item == primary:
            raise GatewayError("%s: %r must not repeat the primary upstream %r"
                               % (where, key, primary))
        if item in out:
            raise GatewayError("%s: duplicate fallback upstream %r" % (where, item))
        out.append(item)
    return out


def _quota_policy_list(data: Dict[str, Any], key: str, where: str) -> Optional[List[str]]:
    """Ordered quota policy ids for joint admission: omitted means the field is
    absent; null, a non-array and any non-string, empty or duplicated entry is
    rejected."""
    if key not in data:
        return None
    raw = data[key]
    if not isinstance(raw, list):
        raise GatewayError("%s: %r must be an array of quota policy ids" % (where, key))
    out: List[str] = []
    for item in raw:
        if not isinstance(item, str) or not item:
            raise GatewayError("%s: %r entries must be non-empty quota policy ids" % (where, key))
        if item in out:
            raise GatewayError("%s: duplicate quota policy %r" % (where, item))
        out.append(item)
    if not out:
        raise GatewayError("%s: %r must be a non-empty array of quota policy ids" % (where, key))
    return out


def _quota_cost(data: Dict[str, Any], where: str) -> int:
    """Optional fixed per-request quota cost: omission defaults to 1, while a
    present null, a boolean, any other non-integer type or a value below 1 is
    rejected (booleans are checked first because ``bool`` is an ``int``)."""
    if "quota_cost" not in data or data["quota_cost"] is None:
        if "quota_cost" not in data:
            return 1
        raise GatewayError("%s: quota_cost must be a positive integer" % where)
    raw = data["quota_cost"]
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 1:
        raise GatewayError("%s: quota_cost must be a positive integer" % where)
    return int(raw)


BODY_OPERATIONS = ("wrap", "unwrap")


def _body_transform(data: Dict[str, Any], key: str, where: str) -> Optional[Dict[str, str]]:
    """Optional JSON body transform: omitted means the body passes through
    unchanged; when present (even null) it must be an object with exactly
    ``operation`` (``wrap`` or ``unwrap``) and ``field`` (a non-empty string)."""
    if key not in data:
        return None
    raw = data[key]
    if not isinstance(raw, dict):
        raise GatewayError("%s: %r must be an object with operation and field" % (where, key))
    if set(raw) - {"operation", "field"}:
        raise GatewayError("%s: %r allows only operation and field" % (where, key))
    operation = raw.get("operation")
    if operation not in BODY_OPERATIONS:
        raise GatewayError("%s: %r operation must be one of %s"
                           % (where, key, ", ".join(BODY_OPERATIONS)))
    field_name = raw.get("field")
    if not isinstance(field_name, str) or not field_name:
        raise GatewayError("%s: %r field must be a non-empty string" % (where, key))
    return {"operation": operation, "field": field_name}


def _version_value(data: Dict[str, Any], where: str) -> Optional[str]:
    """Optional API version: omitted means an unversioned (legacy) route; when
    present it must be a non-empty string -- null, an empty string or any other
    type is rejected."""
    if "version" not in data:
        return None
    raw = data["version"]
    if not isinstance(raw, str) or not raw:
        raise GatewayError("%s: version must be a non-empty string" % where)
    return raw


def _unique(items: List[Any], pick: Callable[[Any], str], label: str) -> None:
    seen = set()
    for item in items:
        if pick(item) in seen:
            raise GatewayError("duplicate %s id: %s" % (label, pick(item)))
        seen.add(pick(item))


@dataclass
class Route:
    """One routing rule: match a method plus path prefix onto an upstream."""

    id: str
    tenant: str
    method: str
    path_prefix: str
    upstream: str
    auth_required: bool = True
    weight: int = 1
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    quota_policy: Optional[str] = None
    quota_policies: Optional[List[str]] = None
    quota_cost: int = 1
    timeout_ms: int = 5000
    scopes: List[str] = field(default_factory=list)
    fallback_upstreams: List[str] = field(default_factory=list)
    version: Optional[str] = None
    request_body: Optional[Dict[str, str]] = None
    response_body: Optional[Dict[str, str]] = None

    @classmethod
    def from_dict(cls, data: Any, where: str = "route") -> "Route":
        if not isinstance(data, dict):
            raise GatewayError("%s: must be a JSON object" % where)
        route_id = _get(data, "id", str, where, required=True)
        where = "route %s" % route_id
        match = _get(data, "match", dict, where, required=True)
        method = _get(match, "method", str, "%s match" % where, default="*").upper()
        prefix = _get(match, "path_prefix", str, "%s match" % where, required=True)
        if not prefix.startswith("/"):
            raise GatewayError("%s: path_prefix must start with '/'" % where)
        weight = _get(data, "weight", int, where, default=1)
        timeout_ms = _get(data, "timeout_ms", int, where, default=5000)
        if weight < 1 or timeout_ms < 1:
            raise GatewayError("%s: weight and timeout_ms must be >= 1" % where)
        transform = _get(data, "transform", dict, where, default={})
        upstream = _get(data, "upstream", str, where, required=True)
        quota_policy = _get(data, "quota_policy", str, where)
        quota_policies = _quota_policy_list(data, "quota_policies", where)
        if quota_policy and quota_policies is not None:
            raise GatewayError(
                "%s: quota_policy and quota_policies cannot both be set" % where)
        quota_cost = _quota_cost(data, where)
        return cls(id=route_id, tenant=_get(data, "tenant", str, where, default=ANY_TENANT),
                   method=method, path_prefix=prefix,
                   upstream=upstream,
                   auth_required=_get(data, "auth_required", bool, where, default=True),
                   weight=weight,
                   request_headers=_str_map(transform, "request_headers", "%s transform" % where),
                   response_headers=_str_map(transform, "response_headers", "%s transform" % where),
                   quota_policy=quota_policy,
                   quota_policies=quota_policies,
                   quota_cost=quota_cost,
                   timeout_ms=timeout_ms, scopes=_str_list(data, "scopes", where),
                   fallback_upstreams=_fallback_list(data, "fallback_upstreams", where, upstream),
                   version=_version_value(data, where),
                   request_body=_body_transform(transform, "request_body", "%s transform" % where),
                   response_body=_body_transform(transform, "response_body",
                                                 "%s transform" % where))

    def to_dict(self) -> Dict[str, Any]:
        out = {"id": self.id, "tenant": self.tenant,
               "match": {"method": self.method, "path_prefix": self.path_prefix},
               "upstream": self.upstream, "auth_required": self.auth_required,
               "weight": self.weight, "quota_policy": self.quota_policy,
               "quota_cost": self.quota_cost,
               "timeout_ms": self.timeout_ms, "scopes": list(self.scopes),
               "fallback_upstreams": list(self.fallback_upstreams),
               "transform": {"request_headers": dict(self.request_headers),
                             "response_headers": dict(self.response_headers)}}
        # Body transforms echo only when declared, so routes written before the
        # fields existed keep their exact output.
        if self.request_body is not None:
            out["transform"]["request_body"] = dict(self.request_body)
        if self.response_body is not None:
            out["transform"]["response_body"] = dict(self.response_body)
        if self.quota_policies is not None:
            out["quota_policies"] = list(self.quota_policies)
        if self.version is not None:
            out["version"] = self.version
        return out

    def matches(self, method: str, path: str, tenant: Optional[str]) -> bool:
        """``tenant`` of None matches any tenant, so a request can reach the auth step."""
        if self.method not in ("*", method.upper()):
            return False
        if tenant is not None and self.tenant not in (ANY_TENANT, tenant):
            return False
        return path.startswith(self.path_prefix)


@dataclass
class ApiKey:
    """An API key; only the sha256 of the secret is ever stored."""

    key_id: str
    tenant: str
    secret_sha256: str
    scopes: List[str] = field(default_factory=list)
    enabled: bool = True
    expires_at_ms: Optional[int] = None

    @classmethod
    def from_dict(cls, data: Any, where: str = "key") -> "ApiKey":
        if not isinstance(data, dict):
            raise GatewayError("%s: must be a JSON object" % where)
        key_id = _get(data, "key_id", str, where, required=True)
        where = "key %s" % key_id
        digest = _get(data, "secret_sha256", str, where, required=True)
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise GatewayError("%s: secret_sha256 must be 64 lowercase hex characters" % where)
        # enabled defaults to true and accepts only a real boolean (null included
        # is rejected); expires_at_ms defaults to null (never expires) and accepts
        # only a positive integer millisecond timestamp, never a boolean.
        if "enabled" in data and not isinstance(data["enabled"], bool):
            raise GatewayError("%s: field 'enabled' must be bool" % where)
        expires_at_ms = _get(data, "expires_at_ms", int, where)
        if expires_at_ms is not None and expires_at_ms <= 0:
            raise GatewayError("%s: expires_at_ms must be a positive integer "
                               "millisecond timestamp" % where)
        return cls(key_id, _get(data, "tenant", str, where, default=ANY_TENANT), digest,
                   _str_list(data, "scopes", where), data.get("enabled", True), expires_at_ms)

    def allows(self, required: List[str]) -> bool:
        return not required or ANY_SCOPE in self.scopes or set(required).issubset(set(self.scopes))

    def invalid_reason(self, now_ms: int) -> Optional[str]:
        """Why the key cannot authenticate at ``now_ms``; a disabled key reports
        disabled even when it is also expired."""
        if not self.enabled:
            return "api key disabled"
        if self.expires_at_ms is not None and now_ms >= self.expires_at_ms:
            return "api key expired"
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {"key_id": self.key_id, "tenant": self.tenant, "scopes": list(self.scopes),
                "secret_sha256": self.secret_sha256, "enabled": self.enabled,
                "expires_at_ms": self.expires_at_ms}

    def public(self) -> Dict[str, Any]:
        return {"key_id": self.key_id, "tenant": self.tenant, "scopes": list(self.scopes),
                "enabled": self.enabled, "expires_at_ms": self.expires_at_ms}


@dataclass
class QuotaPolicy:
    """A named rate limit policy; one bucket instance is kept per partition."""

    id: str
    tenant: str
    algorithm: str
    limit: int
    window_ms: int
    burst: Optional[int] = None
    partition_by: str = "policy"

    @classmethod
    def from_dict(cls, data: Any, where: str = "quota policy") -> "QuotaPolicy":
        if not isinstance(data, dict):
            raise GatewayError("%s: must be a JSON object" % where)
        policy_id = _get(data, "id", str, where, required=True)
        where = "quota policy %s" % policy_id
        algorithm = _get(data, "algorithm", str, where, required=True)
        if algorithm not in ALGORITHMS:
            raise GatewayError("%s: algorithm must be one of %s" % (where, ", ".join(ALGORITHMS)))
        limit = _get(data, "limit", int, where, required=True)
        window_ms = _get(data, "window_ms", int, where, required=True)
        burst = _get(data, "burst", int, where)
        if limit < 1 or window_ms < 1 or (burst is not None and burst < 1):
            raise GatewayError("%s: limit, window_ms and burst must be >= 1" % where)
        # partition_by is rejected explicitly when present (even null), while an
        # omitted field keeps the historical policy-wide sharing mode.
        if "partition_by" not in data:
            partition_by = "policy"
        else:
            raw_partition = data["partition_by"]
            if not isinstance(raw_partition, str) or not raw_partition:
                raise GatewayError(
                    "%s: partition_by must be one of %s" % (where, ", ".join(PARTITION_MODES)))
            partition_by = raw_partition
            if partition_by not in PARTITION_MODES:
                raise GatewayError(
                    "%s: partition_by must be one of %s" % (where, ", ".join(PARTITION_MODES)))
        return cls(policy_id, _get(data, "tenant", str, where, default=ANY_TENANT),
                   algorithm, limit, window_ms, burst, partition_by)

    def capacity(self) -> int:
        return self.burst or self.limit

    def rate_per_ms(self) -> float:
        return self.limit / float(self.window_ms)

    def signature(self) -> tuple:
        # Buckets are preserved only while the tenant scope, partition mode and
        # every algorithm parameter stay identical; any change restarts the
        # policy's partitions from their initial state.
        return (self.tenant, self.partition_by, self.algorithm,
                self.limit, self.window_ms, self.burst)

    def to_dict(self) -> Dict[str, Any]:
        out = {"id": self.id, "tenant": self.tenant, "algorithm": self.algorithm,
               "limit": self.limit, "window_ms": self.window_ms,
               "partition_by": self.partition_by}
        if self.burst is not None:
            out["burst"] = self.burst
        return out


@dataclass
class GatewayConfig:
    routes: List[Route] = field(default_factory=list)
    keys: List[ApiKey] = field(default_factory=list)
    policies: List[QuotaPolicy] = field(default_factory=list)
    revision: int = 0

    def matching_routes(self, method: str, path: str, tenant: Optional[str]) -> List[Route]:
        return [r for r in self.routes if r.matches(method, path, tenant)]

    def key(self, key_id: str) -> Optional[ApiKey]:
        return next((k for k in self.keys if k.key_id == key_id), None)

    def policy(self, policy_id: str) -> Optional[QuotaPolicy]:
        return next((p for p in self.policies if p.id == policy_id), None)

    def sanitized(self) -> Dict[str, Any]:
        return {"revision": self.revision, "routes": [r.to_dict() for r in self.routes],
                "keys": [k.public() for k in self.keys],
                "quota_policies": [p.to_dict() for p in self.policies]}


def _list(raw: Dict[str, Any], key: str) -> List[Any]:
    value = raw.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list):
        raise GatewayError("config: %r must be a JSON array" % key)
    return value


def parse(raw: Any) -> GatewayConfig:
    """Validate a decoded config document and build a :class:`GatewayConfig`."""
    if not isinstance(raw, dict):
        raise GatewayError("config root must be a JSON object")
    routes = [Route.from_dict(item, "route[%d]" % i) for i, item in enumerate(_list(raw, "routes"))]
    keys = [ApiKey.from_dict(item, "key[%d]" % i) for i, item in enumerate(_list(raw, "keys"))]
    policies = [QuotaPolicy.from_dict(item, "quota_policy[%d]" % i)
                for i, item in enumerate(_list(raw, "quota_policies"))]
    _unique(routes, lambda r: r.id, "route")
    _unique(keys, lambda k: k.key_id, "api key")
    _unique(policies, lambda p: p.id, "quota policy")
    known = {p.id for p in policies}
    for route in routes:
        if route.quota_policy and route.quota_policy not in known:
            raise GatewayError("route %s: unknown quota_policy %r" % (route.id, route.quota_policy))
        if route.quota_policies is not None:
            for policy_id in route.quota_policies:
                if policy_id not in known:
                    raise GatewayError("route %s: unknown quota policy %r in quota_policies"
                                       % (route.id, policy_id))
    return GatewayConfig(routes, keys, policies)


def load(path: str, revision: int = 0) -> GatewayConfig:
    """Read and validate ``path``; raise :class:`GatewayError` when malformed."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except FileNotFoundError:
        raise GatewayError("config file not found: %s" % path)
    except OSError as exc:
        raise GatewayError("config file unreadable: %s: %s" % (path, exc))
    except ValueError as exc:
        raise GatewayError("config file is not valid JSON: %s: %s" % (path, exc))
    config = parse(raw)
    config.revision = revision
    return config


def read_raw(path: str) -> Dict[str, Any]:
    """Return the editable document at ``path`` (an empty template when absent)."""
    if not os.path.exists(path):
        return json.loads(json.dumps(EMPTY_CONFIG))
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except ValueError as exc:
        raise GatewayError("config file is not valid JSON: %s: %s" % (path, exc))
    if not isinstance(raw, dict):
        raise GatewayError("config root must be a JSON object")
    for key in EMPTY_CONFIG:
        raw.setdefault(key, [])
    return raw


def save_config(path: str, raw: Dict[str, Any]) -> None:
    """Atomically replace ``path`` with ``raw``."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(raw, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp, path)


class ConfigStore:
    """Holds the live config and reloads it when the file mtime changes."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path
        self.ready = True
        self.last_error: Optional[str] = None
        self._config = GatewayConfig()
        self._revision = 0
        self._mtime_ns: Optional[int] = None
        if path:
            self.load()

    @property
    def config(self) -> GatewayConfig:
        return self._config

    @property
    def revision(self) -> int:
        return self._revision

    def adopt(self, config: GatewayConfig, mtime_ns: Optional[int] = None) -> GatewayConfig:
        self._revision += 1
        config.revision = self._revision
        self._config = config
        self._mtime_ns = self._mtime() if mtime_ns is None else mtime_ns
        self.ready = True
        self.last_error = None
        return config

    def load(self) -> GatewayConfig:
        if not self.path:
            raise GatewayError("no config path configured")
        return self.adopt(load(self.path))

    def _mtime(self) -> Optional[int]:
        if not self.path:
            return None
        try:
            return os.stat(self.path).st_mtime_ns
        except OSError:
            return None

    def reload_if_changed(self) -> bool:
        """Reload only when the mtime moved; keep the last good config on error."""
        if not self.path:
            return False
        mtime = self._mtime()
        if mtime is None:
            self.ready, self.last_error = False, "config file not found: %s" % self.path
            return False
        if self._mtime_ns is not None and mtime == self._mtime_ns:
            return False
        try:
            config = load(self.path)
        except GatewayError as exc:
            self._mtime_ns, self.ready, self.last_error = mtime, False, exc.message
            return False
        self.adopt(config, mtime_ns=mtime)
        return True


_STORES: Dict[str, ConfigStore] = {}


def reload_if_changed(path: str) -> bool:
    """Process wide convenience wrapper around :meth:`ConfigStore.reload_if_changed`."""
    key = os.path.abspath(path)
    store = _STORES.get(key)
    if store is None:
        store = _STORES[key] = ConfigStore(path)
    return store.reload_if_changed()
