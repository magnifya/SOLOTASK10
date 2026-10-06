"""Request pipeline: route -> auth -> quota -> idempotency -> breaker -> audit."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from .breaker import TRANSPORT_ERROR, BreakerRegistry, RetryPolicy
from .config import (ANY_TENANT, ApiKey, BodyTransform, ConfigStore, GatewayError,
                     QuotaPolicy, Route, parse, read_raw, save_config, sha256_hex)
from .limits import AuditLog, Limiter, QuotaLedger
from .upstream import UpstreamError, default_registry

REPLAY_HEADER = "X-Idempotent-Replay"
IN_PROGRESS_ERROR = "idempotency request in progress"
IN_PROGRESS_RETRY_AFTER = "1"
CREDENTIAL_HEADERS = ("authorization", "x-api-key", "x-api-key-secret")
HOP_HEADERS = ("host", "content-length", "connection", "transfer-encoding")
TRACE_HEADERS = ("traceparent", "x-trace-id")
_HEX = frozenset("0123456789abcdef")
_UNSET = object()


def _is_hex(value: str) -> bool:
    return bool(value) and all(char in _HEX for char in value)


def _parse_traceparent(value: str) -> Optional[Tuple[str, str, str]]:
    """Parse a W3C ``traceparent`` header into ``(trace_id, parent_id, flags)``.

    Only version ``00`` is accepted, with a 32 hex non-zero trace id, a 16 hex
    non-zero parent id and exactly two hex flag digits -- all lowercase, as the
    specification mandates. Anything else returns ``None``.
    """
    parts = (value or "").split("-")
    if len(parts) != 4:
        return None
    version, trace_id, parent_id, flags = parts
    if version != "00":
        return None
    if len(trace_id) != 32 or not _is_hex(trace_id) or trace_id == "0" * 32:
        return None
    if len(parent_id) != 16 or not _is_hex(parent_id) or parent_id == "0" * 16:
        return None
    if len(flags) != 2 or not _is_hex(flags):
        return None
    return trace_id, parent_id, flags


def _apply_body_transform(spec: BodyTransform, text: str) -> Optional[str]:
    """Apply a wrap/unwrap to a JSON document; ``None`` signals invalid input.

    ``wrap`` accepts any JSON value and nests it under ``field`` in a new
    top-level object; ``unwrap`` requires a top-level object carrying ``field``
    and lifts that value out. An empty body, malformed JSON and an unwrap
    target that is not an object or lacks the field all return ``None``.
    """
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if spec.operation == "wrap":
        return json.dumps({spec.field: value}, sort_keys=True)
    if not isinstance(value, dict) or spec.field not in value:
        return None
    return json.dumps(value[spec.field], sort_keys=True)


class _IdempotencyScope(tuple):
    """The concurrent identity of an idempotent request: tenant plus the full
    key value.

    A tuple subclass keeps the scope hashable and immutable while immune to
    separator characters appearing inside either component -- a key containing
    ``|`` can never collide with a different ``(tenant, key)`` pair, unlike a
    flat ``"tenant|key"`` rendering. Construct it with a ``(tenant, key)``
    pair, not positional members, so the pair always stays one scope.
    """

    __slots__ = ()

    def __new__(cls, pair: Tuple[str, str]) -> "_IdempotencyScope":
        return tuple.__new__(cls, (str(pair[0]), str(pair[1])))


class _InFlight:
    """Marker held in the idempotency map while a request is running upstream.

    Concurrent requests never wait on it: same body -> immediate ``425``,
    different body -> immediate ``409``.
    """

    __slots__ = ("body_sha256",)

    def __init__(self, body_hash: str) -> None:
        self.body_sha256 = body_hash


class Gateway:
    """Owns the config store, limiters, ledger, breakers and the request pipeline."""

    def __init__(self, config_path: Optional[str] = None, data_dir: str = "gwd_data",
                 upstreams: Any = None, retry_policy: Optional[RetryPolicy] = None,
                 breaker_settings: Optional[Dict[str, Any]] = None,
                 idempotency_window_ms: int = 600000,
                 sleep_fn: Optional[Callable[[int], None]] = None) -> None:
        self.store = ConfigStore(config_path)
        self.upstreams = upstreams if upstreams is not None else default_registry()
        self.limiter = Limiter()
        self.ledger = QuotaLedger(data_dir)
        self.audit_log = AuditLog(data_dir)
        self.retry_policy = retry_policy or RetryPolicy()
        self.breakers = BreakerRegistry(**(breaker_settings or {}))
        self.idempotency_window_ms = int(idempotency_window_ms)
        self.sleep_fn = sleep_fn
        # Scope key -> either an _InFlight marker (request running) or the
        # finished {"body_sha256", "expires_ms", "response"} cache entry.
        self._idempotency: Dict[_IdempotencyScope, Any] = {}
        # Serialises admission, lookup and release of idempotency scopes. It is
        # only ever held over map operations, never over an audit append or an
        # upstream call: the running request keeps a marker in the map and runs
        # unlocked, and concurrent callers are rejected against that marker.
        self._idem_lock = threading.RLock()
        self.sync()

    # ------------------------------------------------------------------ state
    def sync(self) -> None:
        """Push the current policies into the limiter without dropping buckets."""
        self.limiter.sync(self.store.config.policies)

    @property
    def config(self):
        return self.store.config

    def reload_config(self) -> bool:
        changed = self.store.reload_if_changed()
        if changed:
            self.sync()
        return changed

    def health(self) -> Dict[str, Any]:
        return {"ok": bool(self.store.ready), "ready": bool(self.store.ready),
                "revision": self.store.revision, "routes": len(self.config.routes),
                "upstreams": len(self.upstreams.names()),
                "config_error": self.store.last_error}

    def usage(self, tenant: str = "", since_ms: Optional[int] = None) -> Dict[str, Any]:
        return self.ledger.usage(tenant or None, since_ms)

    def audit(self, tenant: str = "", limit: int = 50) -> List[Dict[str, Any]]:
        return self.audit_log.entries(tenant or None, limit)

    def breaker_reset(self, name: Optional[str] = None) -> List[str]:
        return self.breakers.reset(name)

    def sanitized_config(self) -> Dict[str, Any]:
        return self.config.sanitized()

    # -------------------------------------------------------------- mutations
    def _mutate(self, mutate: Callable[[Dict[str, Any]], None]) -> None:
        path = self.store.path
        if not path:
            raise GatewayError("no config path: start the gateway with --config to persist changes")
        raw = read_raw(path)
        mutate(raw)
        parsed = parse(raw)          # validate the whole document before writing
        save_config(path, raw)
        self.store.adopt(parsed)
        self.sync()

    def add_route(self, raw: Any) -> Dict[str, Any]:
        items = raw if isinstance(raw, list) else [raw]
        routes = [Route.from_dict(item, "route") for item in items]
        def mutate(document: Dict[str, Any]) -> None:
            existing = {r.get("id") for r in document["routes"]}
            for route in routes:
                if route.id in existing:
                    raise GatewayError("route already exists: %s" % route.id)
                document["routes"].append(route.to_dict())
        self._mutate(mutate)
        return routes[0].to_dict() if len(routes) == 1 else {"routes": [r.to_dict() for r in routes]}

    def add_key(self, tenant: str, scopes: Optional[List[str]] = None,
                key_id: Optional[str] = None, enabled: Any = _UNSET,
                expires_at_ms: Any = _UNSET) -> Dict[str, Any]:
        if not tenant:
            raise GatewayError("tenant is required")
        secret = secrets.token_urlsafe(24)
        raw: Dict[str, Any] = {"key_id": key_id or ("key-" + secrets.token_hex(6)),
                               "tenant": tenant, "secret_sha256": sha256_hex(secret),
                               "scopes": list(scopes or [])}
        if enabled is not _UNSET:
            raw["enabled"] = enabled
        if expires_at_ms is not _UNSET:
            raw["expires_at_ms"] = expires_at_ms
        key = ApiKey.from_dict(raw, "key")
        def mutate(document: Dict[str, Any]) -> None:
            if any(k.get("key_id") == key.key_id for k in document["keys"]):
                raise GatewayError("api key already exists: %s" % key.key_id)
            document["keys"].append(key.to_dict())
        self._mutate(mutate)
        out = key.to_dict()          # the plaintext secret is returned exactly once
        out["secret"] = secret
        return out

    def rotate_key(self, key_id: Any) -> Dict[str, Any]:
        """Replace only the secret of an existing key; the new plaintext is
        returned exactly once.

        ``key_id``, ``tenant``, ``scopes``, ``enabled`` and ``expires_at_ms``
        are preserved verbatim -- a disabled or expired key may be rotated but
        stays disabled or expired until it is re-enabled or re-dated, and only
        the new secret works from then on. The mutation rides the usual
        ``_mutate`` path, so the revision advances exactly once on success and
        a failure writes nothing and advances nothing; quota buckets, breaker
        state, the idempotency cache and the audit trail are never reset.
        """
        if not isinstance(key_id, str) or not key_id:
            raise GatewayError("invalid key rotation request", 400)
        secret = secrets.token_urlsafe(24)
        digest = sha256_hex(secret)
        def mutate(document: Dict[str, Any]) -> None:
            for entry in document["keys"]:
                if entry.get("key_id") == key_id:
                    entry["secret_sha256"] = digest
                    return
            raise GatewayError("api key not found", 404)
        self._mutate(mutate)
        key = self.config.key(key_id)
        out = key.to_dict()          # the plaintext secret is returned exactly once
        out["secret"] = secret
        return out

    def add_policy(self, raw: Any) -> Dict[str, Any]:
        items = raw if isinstance(raw, list) else [raw]
        policies = [QuotaPolicy.from_dict(item, "quota policy") for item in items]
        def mutate(document: Dict[str, Any]) -> None:
            existing = {p.get("id") for p in document["quota_policies"]}
            for policy in policies:
                if policy.id in existing:
                    raise GatewayError("quota policy already exists: %s" % policy.id)
                document["quota_policies"].append(policy.to_dict())
        self._mutate(mutate)
        return policies[0].to_dict() if len(policies) == 1 else {"policies": [p.to_dict() for p in policies]}

    # --------------------------------------------------------------- pipeline
    def handle(self, tenant: str, method: str, path: str, headers: Optional[Dict[str, str]] = None,
               body: str = "", now_ms: Optional[int] = None) -> Dict[str, Any]:
        """Run one request through the full pipeline and return a response dict."""
        started_ms = int(now_ms if now_ms is not None else time.time() * 1000)
        now = started_ms
        mono = time.monotonic()
        method = (method or "GET").upper()
        body = body or ""
        hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        request_id = hdrs.get("x-request-id") or uuid.uuid4().hex[:16]
        # W3C Trace Context: every proxied request gets a local trace id and a
        # gateway span id up front. A missing traceparent starts a root trace
        # with flags 00; a valid one keeps the caller's trace id and flags and
        # remembers the caller's parent id; an invalid one falls back to a
        # local root context and the request is rejected below with a 400
        # before auth, quota, idempotency or any upstream call.
        span_id = secrets.token_hex(8)
        traceparent_raw = hdrs.get("traceparent")
        trace_error: Optional[str] = None
        parent_span_id: Optional[str] = None
        if traceparent_raw is None:
            trace_id = secrets.token_hex(16)
            trace_flags = "00"
        else:
            parsed_trace = _parse_traceparent(traceparent_raw)
            if parsed_trace is None:
                trace_id = secrets.token_hex(16)
                trace_flags = "00"
                trace_error = "invalid traceparent"
            else:
                trace_id, parent_span_id, trace_flags = parsed_trace
        sampled = bool(int(trace_flags, 16) & 1)
        # The canonical context this gateway propagates: its own span id under
        # the (kept or freshly started) trace id, with the effective flags.
        traceparent = "00-%s-%s-%s" % (trace_id, span_id, trace_flags)
        route: Optional[Route] = None
        upstream_name: Optional[str] = None
        key: Optional[ApiKey] = None
        quota: Dict[str, Any] = {"policy_id": None, "allowed": True, "remaining": None}
        # Multi-policy routes additionally carry an ordered per-policy view; it
        # stays empty until the joint admission check actually runs.
        quotas: List[Dict[str, Any]] = []
        joint = False
        attempts = 0

        def finish(status: int, payload: Optional[Dict[str, Any]] = None,
                   body_text: Optional[str] = None, extra_headers: Optional[Dict[str, str]] = None,
                   replay: bool = False) -> Dict[str, Any]:
            text = body_text if body_text is not None else json.dumps(payload or {}, sort_keys=True)
            audit_entry: Dict[str, Any] = {
                "at": now, "request_id": request_id, "tenant": tenant,
                "key_id": key.key_id if key else None,
                "route_id": route.id if route else None,
                "upstream": upstream_name or (route.upstream if route else None),
                "status": int(status), "attempts": attempts,
                "latency_ms": max(now - started_ms, int((time.monotonic() - mono) * 1000)),
                "quota": dict(quota), "idempotent_replay": bool(replay),
                "trace_id": trace_id, "span_id": span_id,
                "parent_span_id": parent_span_id, "sampled": sampled}
            if joint:
                # A multi-policy route always names quotas; it is an empty list
                # when the request never reached the joint check, and quota then
                # keeps its unchecked value.
                audit_entry["quotas"] = [dict(item) for item in quotas]
            self.audit_log.append(audit_entry)
            out_headers: Dict[str, str] = {"Content-Type": "application/json"}
            if route:
                out_headers.update(route.response_headers)
            out_headers.update(extra_headers or {})
            if route and route.version is not None:
                # The selected route's version always wins, even over a
                # transform.response_headers entry with the same name.
                for name in [name for name in out_headers
                             if name.lower() == "x-api-version"]:
                    del out_headers[name]
                out_headers["X-Api-Version"] = route.version
            # The trace context of this processing always wins, even over a
            # transform.response_headers entry or a replayed cached header with
            # the same name: errors, breaker rejections, idempotency conflicts,
            # 425s and replays all carry the freshly generated pair.
            for name in [name for name in out_headers
                         if name.lower() in TRACE_HEADERS]:
                del out_headers[name]
            out_headers["traceparent"] = traceparent
            out_headers["X-Trace-Id"] = trace_id
            return {"status": int(status), "headers": out_headers, "body": text,
                    "request_id": request_id, "route_id": route.id if route else None}

        if trace_error is not None:
            # Rejected before routing, auth, quota, idempotency or any upstream
            # call; the audit record keeps route_id null and attempts 0 and the
            # response carries the local root context generated above.
            return finish(400, {"error": trace_error, "request_id": request_id})

        key, auth_error = self._resolve_key(hdrs, now)
        explicit_tenant = tenant or ""
        tenant = tenant or (key.tenant if key else "")
        candidates = self.config.matching_routes(method, path, tenant)
        if not candidates:
            # No route for this tenant: retry without the tenant filter so the
            # request is rejected by authentication (401/403) instead of 404.
            candidates = self.config.matching_routes(method, path, None)
        if not candidates:
            return finish(404, {"error": "no route for %s %s" % (method, path), "request_id": request_id})
        # Header conditions: a route declaring match.headers is a candidate
        # only when the request satisfies every declared pair. When at least
        # one such route is satisfied, only those routes continue to the
        # version filter and selection; otherwise the unconditional routes
        # are the candidates, exactly as before.
        header_matched = [r for r in candidates
                          if r.match_headers and r.headers_satisfied_by(hdrs)]
        if header_matched:
            candidates = header_matched
        else:
            candidates = [r for r in candidates if not r.match_headers]
        if not candidates:
            return finish(404, {"error": "no route for %s %s" % (method, path), "request_id": request_id})
        # API version filter: a missing or blank X-Api-Version header reaches
        # only unversioned routes; a non-blank value reaches only routes that
        # declared exactly that (case-sensitive) version -- unversioned routes
        # are never a fallback for a versioned request.
        requested_version = (hdrs.get("x-api-version") or "").strip()
        supported_versions = sorted({r.version for r in candidates if r.version is not None})
        if requested_version:
            candidates = [r for r in candidates if r.version == requested_version]
        else:
            candidates = [r for r in candidates if r.version is None]
        if not candidates:
            # Rejected before auth, quota, idempotency or any upstream call;
            # the audit record keeps route_id null and attempts 0.
            return finish(406, {"error": "unsupported api version",
                                "requested_version": requested_version or None,
                                "supported_versions": supported_versions,
                                "request_id": request_id})
        selector = "%s|%s" % (key.key_id if key else "-", request_id)
        route = self._pick_route(candidates, selector)
        joint = route.quota_policies is not None
        # The retry budget is frozen for this request at route selection: a
        # route with an explicit retry block uses its own attempts and backoff
        # caps, any other route rides the gateway-wide policy. A hot reload
        # swaps the whole config object, never this local reference, so an
        # in-flight request always finishes on the policy it started with.
        retry_policy = route.retry if route.retry is not None else self.retry_policy
        # The fixed cost is read once from the selected route snapshot and
        # rides the whole pipeline: a hot reload swapping the config mid-request
        # keeps this local route object, so in-flight requests are always billed
        # at the cost they started with.
        cost = int(route.quota_cost)

        # 2. authentication and authorisation
        if route.auth_required:
            if auth_error:
                return finish(401, {"error": auth_error, "request_id": request_id})
            if route.tenant != ANY_TENANT and key.tenant != route.tenant:
                return finish(403, {"error": "api key tenant %r is not allowed on route %s"
                                             % (key.tenant, route.id), "request_id": request_id})
            missing = [scope for scope in route.scopes if not key.allows([scope])]
            if missing:
                return finish(403, {"error": "api key is missing required scope(s): %s"
                                             % ",".join(missing), "request_id": request_id})

        # 3. quota
        policy_ids = route.quota_policies if joint else (
            [route.quota_policy] if route.quota_policy else [])
        if policy_ids:
            # Resolve every named policy's partition identity in declaration
            # order. The first identity failure decides the response; it neither
            # consumes quota, writes usage nor calls the upstream, exactly as for
            # a single-policy route.
            checks: List[Tuple[str, Any]] = []
            identity_error: Optional[Tuple[int, str]] = None
            for policy_id in policy_ids:
                named_policy = self.config.policy(policy_id)
                partition = None
                if named_policy is not None and named_policy.partition_by != "policy":
                    if key is None:
                        if named_policy.partition_by == "key":
                            # A key partition needs a valid key even on anonymous
                            # routes: missing secret, unknown secret or a claimed
                            # key id that does not match the secret are all 401.
                            identity_error = (401, auth_error or "missing api key")
                            break
                        if not tenant:
                            identity_error = (
                                400, "tenant is required by quota policy %s" % policy_id)
                            break
                    elif explicit_tenant and explicit_tenant != key.tenant:
                        identity_error = (
                            403, "request tenant %r does not match api key tenant %r"
                                 % (explicit_tenant, key.tenant))
                        break
                    if named_policy.partition_by == "tenant":
                        partition = ("tenant", tenant)
                    else:
                        partition = ("key", key.tenant, key.key_id)
                checks.append((policy_id, partition))
            if identity_error is not None:
                error_status, error_message = identity_error
                return finish(error_status,
                              {"error": error_message, "request_id": request_id})
            if joint:
                results = self.limiter.allow_group(checks, cost, now)
            else:
                only_id, only_partition = checks[0]
                results = [self.limiter.allow(only_id, cost, now, partition=only_partition)]
            # ``allowed`` always reflects the whole group: a usage record is
            # written per policy, but the request is admitted only when every
            # policy had room.
            group_allowed = all(result["allowed"] for result in results)
            quotas = [{"policy_id": result["policy_id"], "allowed": group_allowed,
                       "remaining": result["remaining"], "cost": cost}
                      for result in results]
            quota = dict(quotas[0])
            for result in results:
                # Exactly one ledger line per named policy per request, each
                # carrying this request's full fixed cost; retries, failover
                # and an idempotent replay never pass through here twice.
                self.ledger.record(tenant, result["policy_id"],
                                   key.key_id if key else None, cost, group_allowed, now)
            if not group_allowed:
                insufficient = [result for result in results if not result["allowed"]]
                first_short = next(result for result in results if not result["allowed"])
                # Wait until the slowest of the starving policies recovers.
                reset_at_ms = max(result["reset_at_ms"] for result in insufficient)
                retry_after = max(1, int((reset_at_ms - now + 999) // 1000))
                return finish(429, {"error": "quota exceeded", "request_id": request_id,
                                    "policy_id": first_short["policy_id"],
                                    "reset_at_ms": reset_at_ms},
                              extra_headers={"Retry-After": str(retry_after)})

        # 3.5 request body transform: after auth, partition identity and quota,
        # before idempotency and any upstream call. A rejection here never
        # reaches the upstream, never touches the idempotency map and keeps
        # attempts at 0; quota was already charged exactly once above.
        upstream_body = body
        if route.request_body is not None:
            transformed = _apply_body_transform(route.request_body, body)
            if transformed is None:
                return finish(400, {"error": "invalid request body",
                                    "request_id": request_id})
            upstream_body = transformed

        # 4. idempotency
        body_hash = sha256_hex(body)
        idem_scope: Optional[_IdempotencyScope] = None
        in_flight: Optional[_InFlight] = None
        idem_header = hdrs.get("x-idempotency-key")
        if idem_header:
            # The scope is the immutable (tenant, full key) pair, never the flat
            # ``tenant|key`` rendering, so separator characters in either value
            # cannot merge two scopes.
            idem_scope = _IdempotencyScope((tenant, idem_header))
            # ``action`` is decided purely from map state under the lock; the
            # response and its audit entry are written outside it, so the global
            # idempotency lock never covers file or upstream I/O.
            action: Optional[str] = None
            replay_entry: Optional[Dict[str, Any]] = None
            with self._idem_lock:
                stored = self._idempotency.get(idem_scope)
                if isinstance(stored, _InFlight):
                    # A request for this scope is still inside the upstream
                    # chain. The protection outlives the replay window: an
                    # in-flight marker never expires and never caches anything,
                    # so a concurrent request can neither execute nor replay a
                    # response that does not exist yet.
                    action = ("conflict" if stored.body_sha256 != body_hash
                              else "in-progress")
                elif stored is None:
                    in_flight = _InFlight(body_hash)
                    self._idempotency[idem_scope] = in_flight
                elif stored["expires_ms"] <= now:
                    # Expired response and no request running: this request
                    # takes over the scope atomically, before any upstream call.
                    in_flight = _InFlight(body_hash)
                    self._idempotency[idem_scope] = in_flight
                elif stored["body_sha256"] != body_hash:
                    action = "conflict"
                else:
                    action = "replay"
                    replay_entry = stored
            if action == "in-progress":
                return finish(425, {"error": IN_PROGRESS_ERROR,
                                    "request_id": request_id},
                              extra_headers={"Retry-After": IN_PROGRESS_RETRY_AFTER})
            if action == "conflict":
                return finish(409, {"error": "idempotency key reused with a different request body",
                                    "request_id": request_id})
            if action == "replay":
                replay = dict(replay_entry["response"])
                replay_headers = dict(replay.get("headers") or {})
                replay_headers[REPLAY_HEADER] = "true"
                return finish(replay["status"], body_text=replay["body"],
                              extra_headers=replay_headers, replay=True)

        # 5. circuit breaker and upstream call with retries, then failover.
        # Fallback upstreams are considered only for GET requests or requests
        # carrying a non-empty X-Idempotency-Key; anything else still calls the
        # primary upstream alone. Each upstream keeps its own retry budget and
        # breaker; a breaker rejection skips it without a call, and only a
        # transport error or a 5xx left after the retries moves to the next one.
        if method == "GET" or hdrs.get("x-idempotency-key"):
            chain = [route.upstream] + list(route.fallback_upstreams)
        else:
            chain = [route.upstream]
        upstream_name = route.upstream
        upstream_headers = self._upstream_headers(hdrs, route)
        # Every actual upstream call -- each retry and each fallback hop --
        # receives the canonical traceparent built from the current trace id
        # and this gateway's span id, never the caller's original parent id.
        upstream_headers["traceparent"] = traceparent
        if "tracestate" in hdrs:
            # tracestate is forwarded verbatim and never feeds routing or quota.
            upstream_headers["tracestate"] = hdrs["tracestate"]
        # The transformed body rides every retry and every failover hop; the
        # idempotency hash above still covers the original client body.
        request = {"method": method, "path": path, "body": upstream_body, "tenant": tenant,
                   "request_id": request_id, "headers": upstream_headers}
        response = None
        status = TRANSPORT_ERROR
        rejected_state: Optional[str] = None
        called = False
        try:
            for name in chain:
                breaker = self.breakers.get(name)
                if not breaker.allow(now):
                    if rejected_state is None:
                        rejected_state = breaker.state
                    continue
                attempt = 0
                while attempt < retry_policy.max_attempts:
                    attempt += 1
                    attempts += 1
                    try:
                        response = self.upstreams.call(name, request, route.timeout_ms)
                        status = int(response["status"])
                    except UpstreamError:
                        response = None
                        status = TRANSPORT_ERROR
                    if not retry_policy.should_retry(attempt, status):
                        break
                    if self.sleep_fn is not None:
                        self.sleep_fn(retry_policy.delay_ms(attempt))
                breaker.record(status != TRANSPORT_ERROR and status < 500, now)
                if attempt:
                    upstream_name = name
                    called = True
                if status != TRANSPORT_ERROR and status < 500:
                    break
                # Transport error or 5xx after the retry budget: try the next upstream.

            if not called:
                # Every upstream refused through its breaker: no response to
                # cache; the finally below frees the scope for a later request.
                return finish(503, {"error": "upstream unavailable", "state": rejected_state,
                                    "request_id": request_id})
            if status == TRANSPORT_ERROR:
                # A transport failure is the request's own result, never cached;
                # the finally below lifts the protection for a later retry.
                return finish(502, {"error": "upstream error", "request_id": request_id,
                                    "upstream": upstream_name})
            text = response["body"] if response else ""
            if route.response_body is not None and status < 500:
                # Applied exactly once, to the final response of the chain. A
                # body that is not valid JSON (or an unwrap target that is not
                # an object carrying the field) is a 502: attempts are kept,
                # nothing is cached and the finally below frees the scope.
                transformed = _apply_body_transform(route.response_body, text)
                if transformed is None:
                    return finish(502, {"error": "invalid upstream response body",
                                        "request_id": request_id})
                text = transformed
            if idem_scope is not None and status < 500:
                # The marker becomes the cached response inside one critical
                # section: a concurrent request can never observe the scope
                # empty between the cache publish and the end of the in-flight
                # state. The cache entry now owns the scope, so the finally
                # release below is a no-op. The cached body is the transformed
                # client response, so a replay never re-runs the transform.
                self._idem_publish(idem_scope, in_flight, body_hash, now, status, text)
                in_flight = None
            # A final 5xx keeps ``in_flight`` set, so the finally releases the
            # scope without caching and a later request can attempt it again.
            return finish(status, body_text=text,
                          extra_headers=response.get("headers") if response else None)
        finally:
            # Runs on every exit that did not publish: breakers-only 503,
            # transport 502, final 5xx, or even an unexpected exception, so an
            # in-flight marker can never pin a scope after the chain ended.
            self._idem_release(idem_scope, in_flight)

    # ---------------------------------------------------------------- helpers
    def _idem_publish(self, scope: Optional[_IdempotencyScope], marker: Optional[_InFlight],
                      body_hash: str, now: int, status: int, text: str) -> None:
        """Turn this request's in-flight marker into the cached response.

        Runs in one critical section so there is no window in which the scope
        looks free: a concurrent request either sees the marker (``425``/``409``)
        or the finished cache entry (replay/``409``), never an opportunity to
        run the upstream a second time.
        """
        if scope is None or marker is None:
            return
        with self._idem_lock:
            if len(self._idempotency) > 1024:
                live = {k: v for k, v in self._idempotency.items()
                        if isinstance(v, _InFlight) or v["expires_ms"] > now}
                self._idempotency.clear()
                self._idempotency.update(live)
            self._idempotency[scope] = {
                "body_sha256": body_hash, "expires_ms": now + self.idempotency_window_ms,
                "response": {"status": int(status), "body": text, "headers": {}}}

    def _idem_release(self, scope: Optional[_IdempotencyScope],
                      marker: Optional[_InFlight]) -> None:
        """Drop the in-flight marker after a 5xx, transport failure or a chain
        refused entirely by breakers, so the scope can be executed again.

        Only this request's own marker is removed: it is never overwritten by
        another request (concurrent callers get ``425``/``409`` instead of
        taking over), so guarding the identity costs nothing in practice.
        """
        if scope is None or marker is None:
            return
        with self._idem_lock:
            if self._idempotency.get(scope) is marker:
                self._idempotency.pop(scope, None)

    def _resolve_key(self, hdrs: Dict[str, str],
                     now_ms: int) -> Tuple[Optional[ApiKey], Optional[str]]:
        """Resolve the API key from the presented secret; the sha256 is compared.

        A disabled or expired secret resolves like an invalid one: no key is
        returned and the caller sees ``api key disabled`` / ``api key expired``
        as the auth error, so anonymous routes treat it as no key at all while
        authenticated routes and key partitions reject it with 401.
        """
        secret = hdrs.get("x-api-key-secret") or ""
        authorization = hdrs.get("authorization") or ""
        if authorization.lower().startswith("bearer "):
            secret = authorization[7:].strip()
        if not secret:
            return None, "missing api key"
        digest = sha256_hex(secret)
        match = None
        for candidate in self.config.keys:
            if hmac.compare_digest(candidate.secret_sha256, digest):
                match = candidate
                break
        if match is None:
            return None, "unknown api key"
        stated = hdrs.get("x-api-key")
        if stated and stated != match.key_id:
            return None, "api key id does not match the presented secret"
        invalid = match.invalid_reason(now_ms)
        if invalid is not None:
            return None, invalid
        return match, None

    @staticmethod
    def _pick_route(candidates: List[Route], selector: str) -> Route:
        """Longest path prefix wins, then the most declared header conditions;
        remaining ties are resolved by weighted stable hashing.

        ``bucket = int(sha256("<key_id>|<request_id>").hexdigest()[:16], 16) % total_weight``
        then candidates sorted by route id consume the range ``[0, total_weight)``.
        """
        best = max(len(route.path_prefix) for route in candidates)
        pool = [r for r in candidates if len(r.path_prefix) == best]
        most = max(len(route.match_headers or ()) for route in pool)
        pool = sorted((r for r in pool if len(r.match_headers or ()) == most),
                      key=lambda r: r.id)
        if len(pool) == 1:
            return pool[0]
        total = sum(route.weight for route in pool)
        bucket = int(hashlib.sha256(selector.encode("utf-8")).hexdigest()[:16], 16) % total
        upto = 0
        for route in pool:
            upto += route.weight
            if bucket < upto:
                return route
        return pool[-1]

    @staticmethod
    def _upstream_headers(hdrs: Dict[str, str], route: Route) -> Dict[str, str]:
        out = {name: value for name, value in hdrs.items()
               if name not in CREDENTIAL_HEADERS and name not in HOP_HEADERS}
        out.update(route.request_headers)
        return out
