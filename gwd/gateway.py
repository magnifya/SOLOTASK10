"""Request pipeline: route -> auth -> quota -> idempotency -> breaker -> audit."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from .breaker import TRANSPORT_ERROR, BreakerRegistry, RetryPolicy
from .config import (ANY_TENANT, ApiKey, ConfigStore, GatewayError, QuotaPolicy,
                     Route, parse, read_raw, save_config, sha256_hex)
from .limits import AuditLog, Limiter, QuotaLedger
from .upstream import UpstreamError, default_registry

REPLAY_HEADER = "X-Idempotent-Replay"
CREDENTIAL_HEADERS = ("authorization", "x-api-key", "x-api-key-secret")
HOP_HEADERS = ("host", "content-length", "connection", "transfer-encoding")


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
        self._idempotency: Dict[str, Dict[str, Any]] = {}
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
                key_id: Optional[str] = None) -> Dict[str, Any]:
        if not tenant:
            raise GatewayError("tenant is required")
        secret = secrets.token_urlsafe(24)
        key = ApiKey(key_id=key_id or ("key-" + secrets.token_hex(6)), tenant=tenant,
                     secret_sha256=sha256_hex(secret), scopes=list(scopes or []))
        def mutate(document: Dict[str, Any]) -> None:
            if any(k.get("key_id") == key.key_id for k in document["keys"]):
                raise GatewayError("api key already exists: %s" % key.key_id)
            document["keys"].append(key.to_dict())
        self._mutate(mutate)
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
        route: Optional[Route] = None
        upstream_name: Optional[str] = None
        key: Optional[ApiKey] = None
        quota: Dict[str, Any] = {"policy_id": None, "allowed": True, "remaining": None}
        attempts = 0

        def finish(status: int, payload: Optional[Dict[str, Any]] = None,
                   body_text: Optional[str] = None, extra_headers: Optional[Dict[str, str]] = None,
                   replay: bool = False) -> Dict[str, Any]:
            text = body_text if body_text is not None else json.dumps(payload or {}, sort_keys=True)
            self.audit_log.append({
                "at": now, "request_id": request_id, "tenant": tenant,
                "key_id": key.key_id if key else None,
                "route_id": route.id if route else None,
                "upstream": upstream_name or (route.upstream if route else None),
                "status": int(status), "attempts": attempts,
                "latency_ms": max(now - started_ms, int((time.monotonic() - mono) * 1000)),
                "quota": dict(quota), "idempotent_replay": bool(replay)})
            out_headers: Dict[str, str] = {"Content-Type": "application/json"}
            if route:
                out_headers.update(route.response_headers)
            out_headers.update(extra_headers or {})
            return {"status": int(status), "headers": out_headers, "body": text,
                    "request_id": request_id, "route_id": route.id if route else None}

        key, auth_error = self._resolve_key(hdrs)
        explicit_tenant = tenant
        tenant = tenant or (key.tenant if key else "")
        candidates = self.config.matching_routes(method, path, tenant)
        if not candidates:
            # No route for this tenant: retry without the tenant filter so the
            # request is rejected by authentication (401/403) instead of 404.
            candidates = self.config.matching_routes(method, path, None)
        if not candidates:
            return finish(404, {"error": "no route for %s %s" % (method, path), "request_id": request_id})
        selector = "%s|%s" % (key.key_id if key else "-", request_id)
        route = self._pick_route(candidates, selector)

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
        if route.quota_policy:
            partition, denial = self._quota_partition(route, key, auth_error,
                                                      explicit_tenant, tenant)
            if denial is not None:
                status, message = denial
                return finish(status, {"error": message, "request_id": request_id})
            result = self.limiter.allow(route.quota_policy, 1, now, partition)
            quota = {"policy_id": route.quota_policy, "allowed": result["allowed"],
                     "remaining": result["remaining"]}
            self.ledger.record(tenant, route.quota_policy, key.key_id if key else None, 1,
                               result["allowed"], now)
            if not result["allowed"]:
                retry_after = max(1, int((result["reset_at_ms"] - now + 999) // 1000))
                return finish(429, {"error": "quota exceeded", "request_id": request_id,
                                    "policy_id": route.quota_policy,
                                    "reset_at_ms": result["reset_at_ms"]},
                              extra_headers={"Retry-After": str(retry_after)})

        # 4. idempotency
        body_hash = sha256_hex(body)
        idem_key = None
        idem_header = hdrs.get("x-idempotency-key")
        if idem_header:
            idem_key = "%s|%s" % (tenant, idem_header)
            stored = self._idempotency.get(idem_key)
            if stored is not None:
                if stored["expires_ms"] <= now:
                    self._idempotency.pop(idem_key, None)
                elif stored["body_sha256"] != body_hash:
                    return finish(409, {"error": "idempotency key reused with a different request body",
                                        "request_id": request_id})
                else:
                    replay = dict(stored["response"])
                    replay_headers = dict(replay.get("headers") or {})
                    replay_headers[REPLAY_HEADER] = "true"
                    return finish(replay["status"], body_text=replay["body"],
                                  extra_headers=replay_headers, replay=True)

        # 5. circuit breaker and upstream call with retries
        upstream_name = route.upstream
        breaker = self.breakers.get(upstream_name)
        if not breaker.allow(now):
            return finish(503, {"error": "upstream unavailable", "state": breaker.state,
                                "request_id": request_id})
        request = {"method": method, "path": path, "body": body, "tenant": tenant,
                   "request_id": request_id, "headers": self._upstream_headers(hdrs, route)}
        response = None
        status = TRANSPORT_ERROR
        while attempts < self.retry_policy.max_attempts:
            attempts += 1
            try:
                response = self.upstreams.call(upstream_name, request, route.timeout_ms)
                status = int(response["status"])
            except UpstreamError:
                response = None
                status = TRANSPORT_ERROR
            if not self.retry_policy.should_retry(attempts, status):
                break
            if self.sleep_fn is not None:
                self.sleep_fn(self.retry_policy.delay_ms(attempts))
        breaker.record(status != TRANSPORT_ERROR and status < 500, now)

        if status == TRANSPORT_ERROR:
            return finish(502, {"error": "upstream error", "request_id": request_id,
                                "upstream": upstream_name})
        text = response["body"] if response else ""
        if idem_key and status < 500:
            self._remember(idem_key, body_hash, now, status, text)
        return finish(status, body_text=text, extra_headers=response.get("headers") if response else None)

    # ---------------------------------------------------------------- helpers
    def _quota_partition(self, route: Route, key: Optional[ApiKey],
                         auth_error: Optional[str], explicit_tenant: str,
                         tenant: str) -> Tuple[str, Optional[Tuple[int, str]]]:
        """Resolve the quota partition identity for one request.

        Returns ``(partition, None)`` to proceed, or ``(None, (status, message))``
        when the partition identity cannot be established; the caller then
        rejects without charging quota, recording usage or calling the upstream
        (the audit entry is still written by ``finish``).
        """
        policy = next((p for p in self.config.policies if p.id == route.quota_policy), None)
        mode = policy.partition_by if policy else "policy"
        if mode == "policy":
            return "", None
        if key is not None:
            if explicit_tenant and key.tenant != explicit_tenant:
                return None, (403, "api key tenant %r does not match request tenant %r"
                                   % (key.tenant, explicit_tenant))
            if mode == "key":
                return "%s|%s" % (key.tenant, key.key_id), None
            return key.tenant, None
        if mode == "key":
            # A key partition needs a valid key even on anonymous routes.
            return None, (401, auth_error or "missing api key")
        if not tenant:
            return None, (400, "tenant is required to partition quota policy %s"
                               % route.quota_policy)
        return tenant, None

    def _remember(self, idem_key: str, body_hash: str, now: int, status: int, text: str) -> None:
        if len(self._idempotency) > 1024:
            self._idempotency = {k: v for k, v in self._idempotency.items() if v["expires_ms"] > now}
        self._idempotency[idem_key] = {
            "body_sha256": body_hash, "expires_ms": now + self.idempotency_window_ms,
            "response": {"status": int(status), "body": text, "headers": {}}}

    def _resolve_key(self, hdrs: Dict[str, str]) -> Tuple[Optional[ApiKey], Optional[str]]:
        """Resolve the API key from the presented secret; the sha256 is compared."""
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
        return match, None

    @staticmethod
    def _pick_route(candidates: List[Route], selector: str) -> Route:
        """Longest path prefix wins; ties are resolved by weighted stable hashing.

        ``bucket = int(sha256("<key_id>|<request_id>").hexdigest()[:16], 16) % total_weight``
        then candidates sorted by route id consume the range ``[0, total_weight)``.
        """
        best = max(len(route.path_prefix) for route in candidates)
        pool = sorted((r for r in candidates if len(r.path_prefix) == best), key=lambda r: r.id)
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
