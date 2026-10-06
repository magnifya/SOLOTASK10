"""ThreadingHTTPServer front end: admin surface plus the proxy surface."""

from __future__ import annotations

import json
import sys
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple

from .config import ANY_TENANT, GatewayError
from .gateway import Gateway
from .limits import parse_audit_filters

ADMIN_GET = ("/healthz", "/v1/config", "/v1/quota/usage", "/v1/audit")
ADMIN_POST = ("/v1/config/reload", "/v1/keys", "/v1/quota/policies", "/v1/breaker/reset")
# Global operations act on the whole gateway rather than one tenant's data:
# when admin auth is enabled only a key whose tenant is "*" may run them.
ADMIN_GLOBAL = ("/v1/config", "/v1/config/reload", "/v1/breaker/reset")
ADMIN_SCOPE_ERROR = "admin scope is missing"
ADMIN_TENANT_ERROR = "admin tenant mismatch"


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
            kind = self._admin_kind(target, self.command)
            if kind is not None:
                # /healthz and (when admin auth is disabled) every other admin
                # route keep their historical unauthenticated behaviour. The
                # gate runs before any request body is parsed or mutated, so a
                # missing credential or a missing scope is rejected even with a
                # malformed body and never changes any state.
                auth_key = None
                if kind != "health":
                    policy = gateway.config.admin_auth
                    if policy is not None and policy.enabled:
                        auth_key = self._admin_authenticate(
                            gateway, policy, kind, target, headers, now_ms, request_id)
                if self._admin(gateway, target, raw, params, request_id, auth_key):
                    return
        except GatewayError as exc:
            payload: Dict[str, Any] = {"error": exc.message, "request_id": request_id}
            if exc.parameter is not None:
                payload["parameter"] = exc.parameter
            self._json(exc.status, payload, request_id)
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

    def _admin_kind(self, target: str, command: str) -> Optional[str]:
        """Classify a recognised admin path: ``"health"`` (never protected),
        ``"read"``, ``"write"`` or ``None`` (not an admin route for this
        method). A wrong-method hit on a registered path returns ``None``, just
        as ``_admin`` historically returned False, so the request falls through
        to the proxy surface and its own route-level authentication.
        """
        if target == "/healthz":
            return "health" if command == "GET" else None
        if target in ADMIN_GET:
            return "read" if command == "GET" else None
        if target in ADMIN_POST:
            return "write" if command == "POST" else None
        if target.startswith("/v1/keys/") and target.endswith("/rotate"):
            return "write" if command == "POST" else None
        return None

    def _admin_authenticate(self, gateway: Gateway, policy: Any, kind: str,
                            target: str, headers: Dict[str, str], now_ms: int,
                            request_id: str) -> Any:
        """Resolve the credential and authorise one admin request.

        Raises :class:`GatewayError` with the fixed 401/403 statuses and
        messages; on success returns the resolved :class:`ApiKey`. Key
        resolution reuses the proxy pipeline verbatim, so a missing, unknown,
        mismatched, disabled or expired key answers with the same 401 text and
        the expiry check uses the request start time.
        """
        key, auth_error = gateway.resolve_admin_key(headers, now_ms)
        if auth_error:
            raise GatewayError(auth_error, 401)
        satisfied = (policy.read_satisfied_by(key) if kind == "read"
                     else policy.write_satisfied_by(key))
        if not satisfied:
            raise GatewayError(ADMIN_SCOPE_ERROR, 403)
        if target in ADMIN_GLOBAL and key.tenant != ANY_TENANT:
            raise GatewayError(ADMIN_TENANT_ERROR, 403)
        return key

    def _admin(self, gateway: Gateway, target: str, raw: str,
               params: Dict[str, Any], request_id: str,
               auth_key: Any = None) -> bool:
        auth_enabled = auth_key is not None
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
            # The tenant to create the key under is taken from the body, but
            # only when the authenticated key owns that tenant: a "*" key may
            # create anywhere, every other key only within its own tenant. The
            # comparison happens after auth (and after body parsing here) but
            # before any write, so a cross-tenant attempt changes nothing.
            key_tenant = payload.get("tenant") or ""
            if auth_enabled:
                if auth_key.tenant != ANY_TENANT and key_tenant != auth_key.tenant:
                    raise GatewayError(ADMIN_TENANT_ERROR, 403)
            extras = {name: payload[name] for name in ("enabled", "expires_at_ms")
                      if name in payload}
            out = gateway.add_key(key_tenant, payload.get("scopes"),
                                  payload.get("key_id"), **extras)
            self._json(201, out, request_id)
        elif target.startswith("/v1/keys/") and target.endswith("/rotate"):
            if self.command != "POST":
                return False
            key_id = urllib.parse.unquote(target[len("/v1/keys/"):-len("/rotate")])
            _rotation_body(raw)
            if auth_enabled:
                # Rotation mutates one specific key; only its owner (or a "*"
                # key) may rotate it. Checked before the write, so an attempt
                # against another tenant's key leaves revision and state alone.
                owned = gateway.config.key(key_id)
                if owned is not None and auth_key.tenant != ANY_TENANT \
                        and owned.tenant != auth_key.tenant:
                    raise GatewayError(ADMIN_TENANT_ERROR, 403)
            self._json(200, gateway.rotate_key(key_id), request_id)
        elif target == "/v1/quota/policies":
            payload = _json_body(raw)
            if auth_enabled:
                # Like key creation: a policy's tenant must equal the
                # authenticated key's tenant unless that key is tenant "*";
                # an omitted tenant defaults to "*", which a scoped key can
                # never match. The check precedes the write, so a cross-tenant
                # attempt changes nothing.
                policy_tenant = payload.get("tenant") or ANY_TENANT
                if auth_key.tenant != ANY_TENANT and policy_tenant != auth_key.tenant:
                    raise GatewayError(ADMIN_TENANT_ERROR, 403)
            self._json(201, gateway.add_policy(payload), request_id)
        elif target == "/v1/quota/usage":
            tenant = self._admin_tenant(_first(params, "tenant") or "", auth_key, auth_enabled)
            self._json(200, gateway.usage(tenant,
                                          _int_or_none(_first(params, "since"))), request_id)
        elif target == "/v1/audit":
            tenant = self._admin_tenant(_first(params, "tenant") or "", auth_key, auth_enabled)
            limit = _int_or_none(_first(params, "limit"))
            filters = parse_audit_filters(
                request_id=_first(params, "request_id"),
                trace_id=_first(params, "trace_id"),
                route_id=_first(params, "route_id"),
                status=_first(params, "status"),
                since=_first(params, "since"),
                until=_first(params, "until"))
            entries = gateway.audit(tenant, 50 if limit is None else limit, **filters)
            self._json(200, {"tenant": tenant, "count": len(entries), "entries": entries}, request_id)
        elif target == "/v1/breaker/reset":
            payload = _json_body(raw, default={})
            self._json(200, {"reset": gateway.breaker_reset(payload.get("upstream"))}, request_id)
        else:
            return False
        return True

    @staticmethod
    def _admin_tenant(explicit: str, auth_key: Any, auth_enabled: bool) -> str:
        """Tenant scoping for a read query: an unauthenticated deployment keeps
        the raw query parameter; with admin auth, an omitted tenant defaults to
        the authenticated key's tenant, a "*" key may query anyone, and any
        other explicit value must equal the key's tenant.
        """
        if not auth_enabled:
            return explicit
        if not explicit:
            return "" if auth_key.tenant == ANY_TENANT else auth_key.tenant
        if auth_key.tenant == ANY_TENANT or explicit == auth_key.tenant:
            return explicit
        raise GatewayError(ADMIN_TENANT_ERROR, 403)

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


def _rotation_body(raw: str) -> Dict[str, Any]:
    """A key rotation accepts only an empty body or a JSON object (its content
    is ignored); anything else is a 400 ``invalid key rotation request``."""
    if not raw.strip():
        return {}
    try:
        payload = json.loads(raw)
    except ValueError:
        raise GatewayError("invalid key rotation request", 400)
    if not isinstance(payload, dict):
        raise GatewayError("invalid key rotation request", 400)
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
