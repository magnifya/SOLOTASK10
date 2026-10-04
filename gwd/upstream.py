"""Upstream registry: in-process handlers plus a small stdlib HTTP client."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from .config import sha256_hex


class UpstreamError(Exception):
    """Raised when an upstream cannot be reached or produced no response."""


class Upstream:
    """A callable backend. ``call`` returns ``{"status", "headers", "body"}``."""

    def __init__(self, name: str) -> None:
        self.name = name

    def call(self, request: Dict[str, Any], timeout_ms: int) -> Dict[str, Any]:
        raise NotImplementedError


class InProcessUpstream(Upstream):
    """Wraps a function taking the request dict and returning a response dict."""

    def __init__(self, name: str, fn: Callable[[Dict[str, Any]], Any]) -> None:
        super().__init__(name)
        self.fn = fn

    def call(self, request: Dict[str, Any], timeout_ms: int) -> Dict[str, Any]:
        try:
            result = self.fn(dict(request))
        except UpstreamError:
            raise
        except Exception as exc:  # a handler bug is an upstream failure, not a crash
            raise UpstreamError("%s: %s: %s" % (self.name, type(exc).__name__, exc))
        return normalise(self.name, result)


class HttpUpstream(Upstream):
    """Calls a real HTTP backend with :mod:`urllib` (standard library only)."""

    def __init__(self, name: str, base_url: str) -> None:
        super().__init__(name)
        self.base_url = base_url.rstrip("/")

    def call(self, request: Dict[str, Any], timeout_ms: int) -> Dict[str, Any]:
        url = self.base_url + request["path"]
        body = request.get("body") or ""
        data = body.encode("utf-8") if body else None
        http_request = urllib.request.Request(url, data=data, method=request["method"].upper())
        for name, value in (request.get("headers") or {}).items():
            if name.lower() in ("host", "content-length", "connection"):
                continue
            http_request.add_header(name, str(value))
        timeout = max(0.001, timeout_ms / 1000.0)
        try:
            with urllib.request.urlopen(http_request, timeout=timeout) as response:
                return {"status": int(response.status), "headers": dict(response.headers),
                        "body": response.read().decode("utf-8", "replace")}
        except urllib.error.HTTPError as exc:
            raw = exc.read() if hasattr(exc, "read") else b""
            return {"status": int(exc.code), "headers": dict(exc.headers or {}),
                    "body": raw.decode("utf-8", "replace")}
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise UpstreamError("%s: %s" % (self.name, exc))


def normalise(name: str, result: Any) -> Dict[str, Any]:
    """Accept a response dict or a ``(status, body)`` tuple."""
    if isinstance(result, tuple) and len(result) == 2:
        result = {"status": result[0], "body": result[1]}
    if not isinstance(result, dict) or "status" not in result:
        raise UpstreamError("%s: handler must return a response dict or (status, body)" % name)
    body = result.get("body", "")
    if not isinstance(body, str):
        body = json.dumps(body, sort_keys=True)
    headers = {str(k): str(v) for k, v in (result.get("headers") or {}).items()}
    return {"status": int(result["status"]), "headers": headers, "body": body}


class UpstreamRegistry:
    def __init__(self) -> None:
        self._items: Dict[str, Upstream] = {}

    def register(self, name: str, target: Any) -> Upstream:
        upstream = target if isinstance(target, Upstream) else InProcessUpstream(name, target)
        self._items[name] = upstream
        return upstream

    def get(self, name: str) -> Upstream:
        upstream = self._items.get(name)
        if upstream is None:
            raise UpstreamError("unknown upstream: %s" % name)
        return upstream

    def call(self, name: str, request: Dict[str, Any], timeout_ms: int) -> Dict[str, Any]:
        return self.get(name).call(request, timeout_ms)

    def names(self) -> List[str]:
        return sorted(self._items)


def echo_upstream(request: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic test upstream: reports what the gateway actually sent."""
    return {"status": 200, "body": {"method": request.get("method"),
                                    "path": request.get("path"),
                                    "headers": request.get("headers") or {},
                                    "body_sha256": sha256_hex(request.get("body") or "")}}


def default_registry(with_echo: bool = True) -> UpstreamRegistry:
    registry = UpstreamRegistry()
    if with_echo:
        registry.register("echo", echo_upstream)
    return registry


def http_upstream(name: str, base_url: Optional[str] = None) -> HttpUpstream:
    return HttpUpstream(name, base_url or "http://127.0.0.1:9000")
