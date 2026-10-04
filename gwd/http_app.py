"""ThreadingHTTPServer front end: admin surface plus the proxy surface."""

from __future__ import annotations

import json
import sys
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple

from .config import GatewayError
from .gateway import Gateway

ADMIN_GET = ("/healthz", "/v1/config", "/v1/quota/usage", "/v1/audit")
ADMIN_POST = ("/v1/config/reload", "/v1/keys", "/v1/quota/policies", "/v1/breaker/reset")


class GatewayHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: Tuple[str, int], gateway: Gateway, quiet: bool = False) -> None:
        super().__init__(address, GatewayHandler)
        self.gateway = gateway
        self.quiet = quiet


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = "gwd/0.1"
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self._dispatch()

    def do_POST(self) -> None:
        self._dispatch()

    def do_PUT(self) -> None:
        self._dispatch()

    def do_PATCH(self) -> None:
        self._dispatch()

    def do_DELETE(self) -> None:
        self._dispatch()

    def log_message(self, fmt: str, *args: Any) -> None:
        if not getattr(self.server, "quiet", False):
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    # ------------------------------------------------------------------ plumbing
    def _dispatch(self) -> None:
        gateway: Gateway = self.server.gateway
        now_ms = int(time.time() * 1000)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length > 0 else ""
        target, _, query = self.path.partition("?")
        params = urllib.parse.parse_qs(query)
        headers = {k.lower(): v for k, v in self.headers.items()}
        request_id = headers.get("x-request-id") or uuid.uuid4().hex[:16]
        try:
            handled = self._admin(gateway, target, raw, params, request_id)
            if handled:
                return
        except GatewayError as exc:
            self._json(exc.status, {"error": exc.message, "request_id": request_id}, request_id)
            return
        except ValueError as exc:
            self._json(400, {"error": str(exc), "request_id": request_id}, request_id)
            return
        path = target
        if path == "/gw":
            path = "/"
        elif path.startswith("/gw/"):
            path = path[3:]
        tenant = _first(params, "tenant") or headers.get("x-tenant") or ""
        response = gateway.handle(tenant, self.command, path, headers, raw, now_ms)
        self._send(response["status"], response["body"], response["headers"])

    def _admin(self, gateway: Gateway, target: str, raw: str,
               params: Dict[str, Any], request_id: str) -> bool:
        if target in ADMIN_GET and self.command != "GET":
            return False
        if target in ADMIN_POST and self.command != "POST":
            return False
        if target == "/healthz":
            self._json(200, gateway.health(), request_id)
        elif target == "/v1/config":
            self._json(200, gateway.sanitized_config(), request_id)
        elif target == "/v1/config/reload":
            reloaded = gateway.reload_config()
            self._json(200, {"reloaded": reloaded, "revision": gateway.store.revision,
                             "ready": bool(gateway.store.ready),
                             "error": gateway.store.last_error}, request_id)
        elif target == "/v1/keys":
            payload = _json_body(raw)
            out = gateway.add_key(payload.get("tenant") or "", payload.get("scopes"),
                                  payload.get("key_id"))
            self._json(201, out, request_id)
        elif target == "/v1/quota/policies":
            self._json(201, gateway.add_policy(_json_body(raw)), request_id)
        elif target == "/v1/quota/usage":
            self._json(200, gateway.usage(_first(params, "tenant") or "",
                                          _int_or_none(_first(params, "since"))), request_id)
        elif target == "/v1/audit":
            tenant = _first(params, "tenant") or ""
            limit = _int_or_none(_first(params, "limit"))
            entries = gateway.audit(tenant, 50 if limit is None else limit)
            self._json(200, {"tenant": tenant, "count": len(entries), "entries": entries}, request_id)
        elif target == "/v1/breaker/reset":
            payload = _json_body(raw, default={})
            self._json(200, {"reset": gateway.breaker_reset(payload.get("upstream"))}, request_id)
        else:
            return False
        return True

    def _json(self, status: int, payload: Any, request_id: str) -> None:
        self._send(status, json.dumps(payload, sort_keys=True), {"X-Request-Id": request_id})

    def _send(self, status: int, text: str, headers: Optional[Dict[str, str]] = None) -> None:
        headers = headers or {}
        payload = (text or "").encode("utf-8")
        self.send_response(int(status))
        has_type = False
        for name, value in headers.items():
            lowered = str(name).lower()
            if lowered in ("content-length", "transfer-encoding", "connection"):
                continue
            if lowered == "content-type":
                has_type = True
            self.send_header(str(name), str(value))
        if not has_type:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)


def _json_body(raw: str, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if not raw.strip():
        if default is not None:
            return default
        raise GatewayError("request body must be a JSON object")
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        raise GatewayError("request body is not valid JSON: %s" % exc)
    if not isinstance(payload, dict):
        raise GatewayError("request body must be a JSON object")
    return payload


def _first(params: Dict[str, Any], key: str) -> Optional[str]:
    values = params.get(key)
    return values[0] if values else None


def _int_or_none(value: Optional[str]) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        raise GatewayError("query parameter must be an integer: %s" % value)


def create_server(gateway: Gateway, host: str = "127.0.0.1", port: int = 8080,
                  quiet: bool = False) -> GatewayHTTPServer:
    """Build (but do not start) the HTTP server bound to ``host:port``."""
    return GatewayHTTPServer((host, int(port)), gateway, quiet=quiet)
