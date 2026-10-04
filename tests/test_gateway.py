"""Pipeline tests: auth, quota, idempotency, weighted routing, breaker, audit."""

import hashlib
import json
import os
import shutil
import tempfile
import unittest

from gwd.config import GatewayError, load
from gwd.gateway import Gateway
from gwd.upstream import UpstreamError

SECRET_READ = "read-secret"
SECRET_ADMIN = "admin-secret"
SECRET_GLOBEX = "globex-secret"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def document():
    return {
        "quota_policies": [
            {"id": "p-fast", "tenant": "acme", "algorithm": "token-bucket",
             "limit": 2, "window_ms": 60000, "burst": 2}],
        "keys": [
            {"key_id": "k-read", "tenant": "acme", "secret_sha256": sha(SECRET_READ),
             "scopes": ["read"]},
            {"key_id": "k-admin", "tenant": "acme", "secret_sha256": sha(SECRET_ADMIN),
             "scopes": ["admin"]},
            {"key_id": "k-globex", "tenant": "globex", "secret_sha256": sha(SECRET_GLOBEX),
             "scopes": ["read"]}],
        "routes": [
            {"id": "r-api", "tenant": "acme", "match": {"method": "GET", "path_prefix": "/api"},
             "upstream": "echo", "quota_policy": "p-fast", "scopes": ["read"],
             "transform": {"request_headers": {"X-Gateway-Tenant": "acme"},
                           "response_headers": {"X-Served-By": "gwd"}}},
            {"id": "r-open", "tenant": "acme", "match": {"method": "POST", "path_prefix": "/open"},
             "upstream": "echo", "auth_required": False},
            {"id": "r-count", "tenant": "*", "match": {"method": "POST", "path_prefix": "/count"},
             "upstream": "count", "auth_required": False}],
    }


def write_config(path, doc):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle)
    stat = os.stat(path)
    os.utime(path, ns=(stat.st_atime_ns + 1_000_000, stat.st_mtime_ns + 1_000_000))


def make_gateway(doc=None, **kwargs):
    root = tempfile.mkdtemp(prefix="gwd-test-")
    path = os.path.join(root, "config.json")
    write_config(path, document() if doc is None else doc)
    gateway = Gateway(config_path=path, data_dir=os.path.join(root, "data"), **kwargs)
    return gateway, root, path


class GatewayTestCase(unittest.TestCase):
    def setUp(self):
        self.gateway, self.root, self.path = make_gateway(
            breaker_settings={"failure_threshold": 1, "open_ms": 1000, "success_threshold": 1})
        self.addCleanup(shutil.rmtree, self.root, True)
        self.calls = []

        def counting(request):
            self.calls.append(request)
            return {"status": 200, "body": {"n": len(self.calls), "path": request["path"]}}

        self.gateway.upstreams.register("count", counting)

    def auth(self, secret=SECRET_READ):
        return {"authorization": "Bearer " + secret}

    def body_of(self, response):
        return json.loads(response["body"])


class AuthTest(GatewayTestCase):
    def test_missing_key_is_401_and_audited(self):
        response = self.gateway.handle("acme", "GET", "/api/items", {}, "", now_ms=0)
        self.assertEqual(response["status"], 401)
        self.assertEqual(self.body_of(response)["error"], "missing api key")
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual((entry["status"], entry["route_id"]), (401, "r-api"))
        self.assertIsNone(entry["key_id"])

    def test_unknown_secret_is_401(self):
        response = self.gateway.handle("acme", "GET", "/api/items",
                                       {"authorization": "Bearer nope"}, "", now_ms=0)
        self.assertEqual(response["status"], 401)
        self.assertEqual(self.body_of(response)["error"], "unknown api key")

    def test_mismatched_key_id_is_401(self):
        headers = dict(self.auth(), **{"x-api-key": "k-admin"})
        response = self.gateway.handle("acme", "GET", "/api/items", headers, "", now_ms=0)
        self.assertEqual(response["status"], 401)

    def test_missing_scope_is_403(self):
        response = self.gateway.handle("acme", "GET", "/api/items", self.auth(SECRET_ADMIN),
                                       "", now_ms=0)
        self.assertEqual(response["status"], 403)
        self.assertIn("read", self.body_of(response)["error"])

    def test_key_of_another_tenant_is_403(self):
        response = self.gateway.handle("acme", "GET", "/api/items", self.auth(SECRET_GLOBEX),
                                       "", now_ms=0)
        self.assertEqual(response["status"], 403)
        self.assertIn("tenant", self.body_of(response)["error"])

    def test_auth_required_false_skips_authentication(self):
        response = self.gateway.handle("acme", "POST", "/open/thing", {}, "{}", now_ms=0)
        self.assertEqual(response["status"], 200)

    def test_unknown_path_is_404(self):
        response = self.gateway.handle("acme", "GET", "/nope", self.auth(), "", now_ms=0)
        self.assertEqual(response["status"], 404)


class QuotaTest(GatewayTestCase):
    def test_third_call_is_429_and_recorded_in_the_ledger(self):
        for _ in range(2):
            self.assertEqual(
                self.gateway.handle("acme", "GET", "/api/items", self.auth(), "", now_ms=0)["status"],
                200)
        response = self.gateway.handle("acme", "GET", "/api/items", self.auth(), "", now_ms=0)
        self.assertEqual(response["status"], 429)
        payload = self.body_of(response)
        self.assertEqual(payload["policy_id"], "p-fast")
        self.assertEqual(payload["reset_at_ms"], 30000)
        self.assertEqual(response["headers"]["Retry-After"], "30")
        usage = self.gateway.usage("acme")
        self.assertEqual((usage["requests"], usage["allowed"], usage["rejected"]), (3, 2, 1))
        rejected = self.gateway.ledger.entries("acme")[-1]
        self.assertEqual((rejected["allowed"], rejected["cost"], rejected["key_id"]),
                         (False, 1, "k-read"))

    def test_quota_refills_with_the_injected_clock(self):
        for _ in range(2):
            self.gateway.handle("acme", "GET", "/api/items", self.auth(), "", now_ms=0)
        self.assertEqual(
            self.gateway.handle("acme", "GET", "/api/items", self.auth(), "", now_ms=29999)["status"],
            429)
        self.assertEqual(
            self.gateway.handle("acme", "GET", "/api/items", self.auth(), "", now_ms=30001)["status"],
            200)

    def test_route_without_a_policy_has_no_quota(self):
        for _ in range(5):
            self.assertEqual(
                self.gateway.handle("acme", "POST", "/open/x", {}, "{}", now_ms=0)["status"], 200)
        self.assertEqual(self.gateway.usage("acme")["requests"], 0)


SECRET_OTHER = "other-secret"


def partition_document():
    return {
        "quota_policies": [
            {"id": "p-tenant", "tenant": "*", "algorithm": "token-bucket",
             "limit": 2, "window_ms": 60000, "burst": 2, "partition_by": "tenant"},
            {"id": "p-key", "tenant": "*", "algorithm": "token-bucket",
             "limit": 2, "window_ms": 60000, "burst": 2, "partition_by": "key"}],
        "keys": [
            {"key_id": "k-read", "tenant": "acme", "secret_sha256": sha(SECRET_READ),
             "scopes": ["read"]},
            {"key_id": "k-other", "tenant": "acme", "secret_sha256": sha(SECRET_OTHER),
             "scopes": ["read"]},
            {"key_id": "k-globex", "tenant": "globex", "secret_sha256": sha(SECRET_GLOBEX),
             "scopes": ["read"]}],
        "routes": [
            {"id": "r-t", "tenant": "*", "match": {"method": "GET", "path_prefix": "/t"},
             "upstream": "echo", "quota_policy": "p-tenant", "scopes": ["read"]},
            {"id": "r-topen", "tenant": "*", "match": {"method": "GET", "path_prefix": "/to"},
             "upstream": "echo", "quota_policy": "p-tenant", "auth_required": False},
            {"id": "r-k", "tenant": "*", "match": {"method": "GET", "path_prefix": "/k"},
             "upstream": "echo", "quota_policy": "p-key", "auth_required": False},
            {"id": "r-kauth", "tenant": "*", "match": {"method": "GET", "path_prefix": "/ka"},
             "upstream": "echo", "quota_policy": "p-key", "scopes": ["read"]}],
    }


class PartitionQuotaTest(unittest.TestCase):
    def setUp(self):
        self.gateway, self.root, self.path = make_gateway(
            partition_document(),
            breaker_settings={"failure_threshold": 1, "open_ms": 1000, "success_threshold": 1})
        self.addCleanup(shutil.rmtree, self.root, True)
        self.calls = []

        def counting(request):
            self.calls.append(request)
            return {"status": 200, "body": {"n": len(self.calls)}}

        self.gateway.upstreams.register("echo", counting)

    def key(self, secret=SECRET_READ):
        return {"authorization": "Bearer " + secret}

    def body_of(self, response):
        return json.loads(response["body"])

    def test_tenant_mode_is_shared_across_keys_and_routes_but_isolated_per_tenant(self):
        statuses = [
            self.gateway.handle("acme", "GET", "/t", self.key(), "", now_ms=0)["status"],
            self.gateway.handle("acme", "GET", "/t", self.key(SECRET_OTHER), "", now_ms=0)["status"],
            self.gateway.handle("acme", "GET", "/t", self.key(), "", now_ms=0)["status"],
            self.gateway.handle("globex", "GET", "/t", self.key(SECRET_GLOBEX), "", now_ms=0)["status"],
        ]
        self.assertEqual(statuses, [200, 200, 429, 200])

    def test_tenant_mode_anonymous_uses_the_request_tenant_and_shares_the_partition(self):
        # anonymous requests are attributed to the explicit request tenant and
        # share that tenant's bucket with authenticated requests on other routes
        self.assertEqual(self.gateway.handle("acme", "GET", "/t", self.key(), "", now_ms=0)["status"],
                         200)
        self.assertEqual(self.gateway.handle("acme", "GET", "/to", {}, "", now_ms=0)["status"], 200)
        self.assertEqual(self.gateway.handle("acme", "GET", "/to", {}, "", now_ms=0)["status"], 429)
        self.assertEqual(self.gateway.handle("globex", "GET", "/to", {}, "", now_ms=0)["status"], 200)

    def test_tenant_mode_empty_tenant_is_400_without_ledger_or_upstream(self):
        response = self.gateway.handle("", "GET", "/to", {}, "", now_ms=0)
        self.assertEqual(response["status"], 400)
        payload = self.body_of(response)
        self.assertIn("tenant", payload["error"])
        self.assertIn("request_id", payload)
        self.assertEqual(self.gateway.usage("")["requests"], 0)
        self.assertEqual(len(self.calls), 0)
        entry = self.gateway.audit("", 10)[-1]
        self.assertEqual(entry["status"], 400)
        self.assertIsNone(entry["quota"]["policy_id"])

    def test_key_mode_is_isolated_per_key_and_shared_across_routes(self):
        statuses = [
            self.gateway.handle("acme", "GET", "/k", self.key(), "", now_ms=0)["status"],
            self.gateway.handle("acme", "GET", "/ka", self.key(), "", now_ms=0)["status"],
            self.gateway.handle("acme", "GET", "/k", self.key(), "", now_ms=0)["status"],
            self.gateway.handle("acme", "GET", "/k", self.key(SECRET_OTHER), "", now_ms=0)["status"],
        ]
        self.assertEqual(statuses, [200, 200, 429, 200])

    def test_key_mode_requires_a_valid_key_even_when_the_route_allows_anonymous(self):
        missing = self.gateway.handle("", "GET", "/k", {}, "", now_ms=0)
        unknown = self.gateway.handle("", "GET", "/k",
                                     {"authorization": "Bearer wrong"}, "", now_ms=0)
        mismatch_headers = dict(self.key(), **{"x-api-key": "k-other"})
        mismatch = self.gateway.handle("acme", "GET", "/k", mismatch_headers, "", now_ms=0)
        self.assertEqual([missing["status"], unknown["status"], mismatch["status"]],
                         [401, 401, 401])
        self.assertEqual(self.gateway.usage("")["requests"], 0)
        self.assertEqual(len(self.calls), 0)
        for response in (missing, unknown, mismatch):
            self.assertIn("request_id", self.body_of(response))
        entries = self.gateway.audit("", 10)
        self.assertEqual([e["status"] for e in entries[-3:]], [401, 401, 401])

    def test_valid_key_with_a_mismatched_request_tenant_is_403_in_both_modes(self):
        tenant_mode = self.gateway.handle("globex", "GET", "/t", self.key(), "", now_ms=0)
        key_mode = self.gateway.handle("globex", "GET", "/k", self.key(), "", now_ms=0)
        self.assertEqual(tenant_mode["status"], 403)
        self.assertEqual(key_mode["status"], 403)
        self.assertEqual(self.gateway.usage("globex")["requests"], 0)
        self.assertEqual(len(self.calls), 0)

    def test_rejected_quota_still_records_usage_and_a_retry_after_header(self):
        for _ in range(2):
            self.gateway.handle("acme", "GET", "/k", self.key(), "", now_ms=0)
        response = self.gateway.handle("acme", "GET", "/k", self.key(), "", now_ms=0)
        self.assertEqual(response["status"], 429)
        self.assertEqual(response["headers"]["Retry-After"], "30")
        usage = self.gateway.usage("acme")
        self.assertEqual((usage["requests"], usage["allowed"], usage["rejected"]), (3, 2, 1))

    def test_audit_quota_block_keeps_the_existing_shape(self):
        self.gateway.handle("acme", "GET", "/t", self.key(), "", now_ms=1234)
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual(entry["quota"],
                         {"policy_id": "p-tenant", "allowed": True, "remaining": 1})

    def test_hot_reload_preserves_then_resets_partition_buckets(self):
        for _ in range(2):
            self.gateway.handle("acme", "GET", "/t", self.key(), "", now_ms=0)
        self.assertEqual(self.gateway.handle("acme", "GET", "/t", self.key(), "", now_ms=0)["status"],
                         429)
        write_config(self.path, partition_document())
        self.assertTrue(self.gateway.reload_config())
        # identity and algorithm parameters unchanged: the partition stays exhausted
        self.assertEqual(self.gateway.handle("acme", "GET", "/t", self.key(), "", now_ms=0)["status"],
                         429)
        changed = partition_document()
        changed["quota_policies"][0]["burst"] = 5
        write_config(self.path, changed)
        self.gateway.reload_config()
        self.assertEqual(self.gateway.handle("acme", "GET", "/t", self.key(), "", now_ms=0)["status"],
                         200)

    def test_sanitized_config_reports_the_partition_mode(self):
        policies = {p["id"]: p for p in self.gateway.sanitized_config()["quota_policies"]}
        self.assertEqual(policies["p-tenant"]["partition_by"], "tenant")
        self.assertEqual(policies["p-key"]["partition_by"], "key")


class IdempotencyTest(GatewayTestCase):
    def test_same_key_and_body_replays_without_calling_upstream(self):
        headers = {"x-idempotency-key": "idem-1"}
        first = self.gateway.handle("acme", "POST", "/count/x", headers, '{"a": 1}', now_ms=0)
        second = self.gateway.handle("acme", "POST", "/count/x", headers, '{"a": 1}', now_ms=100)
        self.assertEqual((first["status"], second["status"]), (200, 200))
        self.assertEqual(len(self.calls), 1)
        self.assertNotIn("X-Idempotent-Replay", first["headers"])
        self.assertEqual(second["headers"]["X-Idempotent-Replay"], "true")
        self.assertEqual(first["body"], second["body"])
        self.assertFalse(self.gateway.audit("acme", 10)[-2]["idempotent_replay"])
        self.assertTrue(self.gateway.audit("acme", 10)[-1]["idempotent_replay"])

    def test_same_key_with_a_different_body_is_409(self):
        headers = {"x-idempotency-key": "idem-2"}
        self.gateway.handle("acme", "POST", "/count/x", headers, '{"a": 1}', now_ms=0)
        response = self.gateway.handle("acme", "POST", "/count/x", headers, '{"a": 2}', now_ms=100)
        self.assertEqual(response["status"], 409)
        self.assertEqual(len(self.calls), 1)

    def test_the_window_expires_with_the_injected_clock(self):
        headers = {"x-idempotency-key": "idem-3"}
        self.gateway.handle("acme", "POST", "/count/x", headers, "{}", now_ms=0)
        self.gateway.handle("acme", "POST", "/count/x", headers, "{}", now_ms=599_999)
        self.assertEqual(len(self.calls), 1)
        self.gateway.handle("acme", "POST", "/count/x", headers, "{}", now_ms=600_001)
        self.assertEqual(len(self.calls), 2)

    def test_idempotency_is_scoped_per_tenant(self):
        headers = {"x-idempotency-key": "shared"}
        self.gateway.handle("acme", "POST", "/count/x", headers, "{}", now_ms=0)
        self.gateway.handle("globex", "POST", "/count/x", headers, "{}", now_ms=0)
        self.assertEqual(len(self.calls), 2)


class RoutingTest(unittest.TestCase):
    def _gateway_with_markers(self, doc):
        gateway, root, _ = make_gateway(doc, breaker_settings={"failure_threshold": 1})
        self.addCleanup(shutil.rmtree, root, True)
        for name in ("up-a", "up-b", "up-root", "up-v2"):
            gateway.upstreams.register(name, lambda request, name=name: {
                "status": 200, "body": {"upstream": name}})
        return gateway

    def test_longest_path_prefix_wins(self):
        gateway = self._gateway_with_markers({"routes": [
            {"id": "r-root", "tenant": "acme", "match": {"method": "GET", "path_prefix": "/api"},
             "upstream": "up-root", "auth_required": False},
            {"id": "r-v2", "tenant": "acme", "match": {"method": "GET", "path_prefix": "/api/v2"},
             "upstream": "up-v2", "auth_required": False}], "keys": [], "quota_policies": []})
        short = gateway.handle("acme", "GET", "/api/v1/x", {"x-request-id": "a"}, "", now_ms=0)
        deep = gateway.handle("acme", "GET", "/api/v2/x", {"x-request-id": "a"}, "", now_ms=0)
        self.assertEqual(json.loads(short["body"])["upstream"], "up-root")
        self.assertEqual(json.loads(deep["body"])["upstream"], "up-v2")

    def test_weighted_routing_follows_the_documented_formula(self):
        gateway = self._gateway_with_markers({"routes": [
            {"id": "r-a", "tenant": "acme", "match": {"method": "GET", "path_prefix": "/w"},
             "upstream": "up-a", "auth_required": False, "weight": 1},
            {"id": "r-b", "tenant": "acme", "match": {"method": "GET", "path_prefix": "/w"},
             "upstream": "up-b", "auth_required": False, "weight": 3}],
            "keys": [], "quota_policies": []})
        picked = {}
        for index in range(40):
            request_id = "req-%03d" % index
            bucket = int(hashlib.sha256(("-|%s" % request_id).encode("utf-8")).hexdigest()[:16],
                         16) % 4
            expected = "up-a" if bucket < 1 else "up-b"
            response = gateway.handle("acme", "GET", "/w/x", {"x-request-id": request_id},
                                      "", now_ms=0)
            picked[request_id] = json.loads(response["body"])["upstream"]
            self.assertEqual(picked[request_id], expected)
        self.assertEqual(set(picked.values()), {"up-a", "up-b"})

    def test_method_is_part_of_the_match_and_auth_still_rejects(self):
        doc = document()
        doc["routes"] = [route for route in doc["routes"] if route["id"] == "r-api"]
        gateway = self._gateway_with_markers(doc)
        ok = {"authorization": "Bearer " + SECRET_READ}
        self.assertEqual(gateway.handle("acme", "GET", "/api/x", ok, "", now_ms=0)["status"], 200)
        self.assertEqual(gateway.handle("acme", "POST", "/api/x", ok, "", now_ms=0)["status"], 404)
        self.assertEqual(gateway.handle("acme", "GET", "/api/x", {}, "", now_ms=0)["status"], 401)
        foreign = {"authorization": "Bearer " + SECRET_GLOBEX}
        self.assertEqual(gateway.handle("acme", "GET", "/api/x", foreign, "", now_ms=0)["status"], 403)


class BreakerAndRetryTest(GatewayTestCase):
    def test_transport_errors_open_the_breaker_and_then_return_503(self):
        attempts = []

        def flaky(request):
            attempts.append(request)
            raise UpstreamError("boom")

        self.gateway.upstreams.register("flaky", flaky)
        self.gateway.add_route({"id": "r-flaky", "tenant": "acme",
                                "match": {"method": "GET", "path_prefix": "/flaky"},
                                "upstream": "flaky", "auth_required": False})
        first = self.gateway.handle("acme", "GET", "/flaky/x", {}, "", now_ms=0)
        self.assertEqual(first["status"], 502)
        self.assertEqual(len(attempts), 3)  # RetryPolicy.max_attempts
        second = self.gateway.handle("acme", "GET", "/flaky/x", {}, "", now_ms=10)
        self.assertEqual(second["status"], 503)
        self.assertEqual(self.body_of(second)["state"], "open")
        self.assertEqual(len(attempts), 3)  # an open breaker makes no upstream call
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual((entry["status"], entry["attempts"], entry["upstream"]), (503, 0, "flaky"))

    def test_retryable_status_is_retried_then_succeeds(self):
        seen = []

        def mostly_down(request):
            seen.append(request)
            if len(seen) < 3:
                return {"status": 503, "body": {"error": "starting"}}
            return {"status": 200, "body": {"ok": True}}

        self.gateway.upstreams.register("flappy", mostly_down)
        self.gateway.add_route({"id": "r-flappy", "tenant": "acme",
                                "match": {"method": "GET", "path_prefix": "/flappy"},
                                "upstream": "flappy", "auth_required": False})
        response = self.gateway.handle("acme", "GET", "/flappy/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 200)
        self.assertEqual(len(seen), 3)
        self.assertEqual(self.gateway.audit("acme", 1)[0]["attempts"], 3)

    def test_non_retryable_status_is_returned_unchanged(self):
        seen = []

        def gone(request):
            seen.append(request)
            return {"status": 404, "body": {"error": "gone"}}

        self.gateway.upstreams.register("gone", gone)
        self.gateway.add_route({"id": "r-gone", "tenant": "acme",
                                "match": {"method": "GET", "path_prefix": "/gone"},
                                "upstream": "gone", "auth_required": False})
        response = self.gateway.handle("acme", "GET", "/gone/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 404)
        self.assertEqual(len(seen), 1)

    def test_unknown_upstream_is_a_transport_error(self):
        self.gateway.add_route({"id": "r-ghost", "tenant": "acme",
                                "match": {"method": "GET", "path_prefix": "/ghost"},
                                "upstream": "ghost", "auth_required": False})
        response = self.gateway.handle("acme", "GET", "/ghost/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 502)
        self.assertEqual(self.body_of(response)["upstream"], "ghost")

    def test_breaker_reset_helper(self):
        self.gateway.breakers.get("echo").allow(0)
        self.gateway.breakers.get("echo").record(False, 0)
        self.assertEqual(self.gateway.breaker_reset("echo"), ["echo"])
        self.assertEqual(self.gateway.breakers.get("echo").state, "closed")


class TransformAndAuditTest(GatewayTestCase):
    def test_request_and_response_transform_headers(self):
        response = self.gateway.handle("acme", "GET", "/api/items", self.auth(), "", now_ms=0)
        self.assertEqual(response["headers"]["X-Served-By"], "gwd")
        sent = self.body_of(response)["headers"]
        self.assertEqual(sent["X-Gateway-Tenant"], "acme")
        self.assertNotIn("authorization", sent)
        self.assertNotIn("x-api-key", sent)

    def test_echo_upstream_reports_method_path_and_body_hash(self):
        response = self.gateway.handle("acme", "GET", "/api/items", self.auth(), "", now_ms=0)
        payload = self.body_of(response)
        self.assertEqual(payload["method"], "GET")
        self.assertEqual(payload["path"], "/api/items")
        self.assertEqual(payload["body_sha256"], sha(""))

    def test_audit_entry_carries_every_documented_field(self):
        self.gateway.handle("acme", "GET", "/api/items", self.auth(), "", now_ms=1234)
        entry = self.gateway.audit("acme", 5)[-1]
        self.assertEqual(sorted(entry), ["at", "attempts", "idempotent_replay", "key_id",
                                         "latency_ms", "quota", "request_id", "route_id",
                                         "status", "tenant", "upstream"])
        self.assertEqual(entry["at"], 1234)
        self.assertEqual(entry["tenant"], "acme")
        self.assertEqual(entry["key_id"], "k-read")
        self.assertEqual(entry["route_id"], "r-api")
        self.assertEqual(entry["upstream"], "echo")
        self.assertEqual(entry["status"], 200)
        self.assertEqual(entry["attempts"], 1)
        self.assertIsInstance(entry["latency_ms"], int)
        self.assertEqual(entry["quota"], {"policy_id": "p-fast", "allowed": True, "remaining": 1})
        self.assertEqual(self.gateway.audit("nobody"), [])
        self.assertEqual(len(self.gateway.audit("acme", 1)), 1)


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-config-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = os.path.join(self.root, "config.json")

    def test_malformed_configs_are_rejected(self):
        cases = {
            "not an object": [],
            "missing match": {"routes": [{"id": "r", "upstream": "echo"}]},
            "bad algorithm": {"quota_policies": [{"id": "p", "algorithm": "magic",
                                                  "limit": 1, "window_ms": 1}]},
            "bad limit": {"quota_policies": [{"id": "p", "algorithm": "token-bucket",
                                              "limit": 0, "window_ms": 1}]},
            "duplicate route": {"routes": [
                {"id": "r", "match": {"method": "GET", "path_prefix": "/a"}, "upstream": "echo"},
                {"id": "r", "match": {"method": "GET", "path_prefix": "/b"}, "upstream": "echo"}]},
            "unknown policy": {"routes": [{"id": "r", "match": {"method": "GET",
                                                                "path_prefix": "/a"},
                                           "upstream": "echo", "quota_policy": "ghost"}]},
            "bad weight": {"routes": [{"id": "r", "match": {"method": "GET", "path_prefix": "/a"},
                                       "upstream": "echo", "weight": 0}]},
            "bad secret": {"keys": [{"key_id": "k", "tenant": "t", "secret_sha256": "xyz"}]},
            "partition null": {"quota_policies": [{"id": "p", "algorithm": "token-bucket",
                                                   "limit": 1, "window_ms": 1,
                                                   "partition_by": None}]},
            "partition empty": {"quota_policies": [{"id": "p", "algorithm": "token-bucket",
                                                    "limit": 1, "window_ms": 1,
                                                    "partition_by": ""}]},
            "partition unknown": {"quota_policies": [{"id": "p", "algorithm": "token-bucket",
                                                      "limit": 1, "window_ms": 1,
                                                      "partition_by": "route"}]},
            "partition number": {"quota_policies": [{"id": "p", "algorithm": "token-bucket",
                                                     "limit": 1, "window_ms": 1,
                                                     "partition_by": 1}]},
            "partition list": {"quota_policies": [{"id": "p", "algorithm": "token-bucket",
                                                   "limit": 1, "window_ms": 1,
                                                   "partition_by": ["tenant"]}]},
        }
        for label, doc in cases.items():
            write_config(self.path, doc)
            with self.assertRaises(GatewayError, msg=label):
                load(self.path)

    def test_partition_by_defaults_to_policy_and_round_trips(self):
        for mode in (None, "policy", "tenant", "key"):
            policy = {"id": "p", "algorithm": "token-bucket", "limit": 1, "window_ms": 1}
            if mode is not None:
                policy["partition_by"] = mode
            doc = {"routes": [], "keys": [], "quota_policies": [policy]}
            write_config(self.path, doc)
            loaded = load(self.path)
            self.assertEqual(loaded.policies[0].partition_by, mode or "policy")
            self.assertEqual(loaded.policies[0].to_dict()["partition_by"], mode or "policy")

    def test_missing_file_is_rejected(self):
        with self.assertRaises(GatewayError):
            load(os.path.join(self.root, "absent.json"))

    def test_reload_only_when_the_mtime_moved(self):
        gateway, root, path = make_gateway()
        self.addCleanup(shutil.rmtree, root, True)
        self.assertFalse(gateway.reload_config())
        doc = document()
        doc["routes"].append({"id": "r-new", "tenant": "acme",
                              "match": {"method": "GET", "path_prefix": "/new"},
                              "upstream": "echo"})
        write_config(path, doc)
        self.assertTrue(gateway.reload_config())
        self.assertEqual(gateway.store.revision, 2)
        self.assertTrue(gateway.store.ready)
        self.assertIn("r-new", [route.id for route in gateway.config.routes])

    def test_invalid_reload_keeps_the_last_good_config_and_lowers_readiness(self):
        gateway, root, path = make_gateway()
        self.addCleanup(shutil.rmtree, root, True)
        write_config(path, {"routes": [{"id": "broken"}]})
        self.assertFalse(gateway.reload_config())
        self.assertFalse(gateway.store.ready)
        self.assertIn("broken", gateway.store.last_error)
        self.assertEqual(len(gateway.config.routes), 3)  # last known good kept
        self.assertEqual(gateway.health()["routes"], 3)

    def test_sanitized_config_never_contains_a_secret(self):
        gateway, root, _ = make_gateway()
        self.addCleanup(shutil.rmtree, root, True)
        blob = json.dumps(gateway.sanitized_config())
        self.assertNotIn("secret_sha256", blob)
        self.assertNotIn(SECRET_READ, blob)
        self.assertIn("k-read", blob)


class MutationTest(unittest.TestCase):
    def setUp(self):
        self.gateway, self.root, self.path = make_gateway()
        self.addCleanup(shutil.rmtree, self.root, True)

    def test_add_key_stores_only_the_hash_and_authenticates_later(self):
        created = self.gateway.add_key("acme", ["read"], key_id="k-new")
        self.assertIn("secret", created)
        self.assertEqual(created["tenant"], "acme")
        with open(self.path, "r", encoding="utf-8") as handle:
            raw = handle.read()
        self.assertNotIn(created["secret"], raw)
        self.assertIn(sha(created["secret"]), raw)
        self.gateway.add_route({"id": "r-new", "tenant": "acme",
                                "match": {"method": "GET", "path_prefix": "/new"},
                                "upstream": "echo"})
        headers = {"authorization": "Bearer " + created["secret"]}
        response = self.gateway.handle("acme", "GET", "/new/x", headers, "", now_ms=0)
        self.assertEqual(response["status"], 200)
        self.assertEqual(self.gateway.audit("acme", 1)[0]["key_id"], "k-new")

    def test_add_policy_and_duplicate_rejection(self):
        policy = {"id": "p-new", "tenant": "acme", "algorithm": "sliding-window",
                  "limit": 1, "window_ms": 1000}
        self.assertEqual(self.gateway.add_policy(policy)["algorithm"], "sliding-window")
        with self.assertRaises(GatewayError):
            self.gateway.add_policy(policy)
        with self.assertRaises(GatewayError):
            self.gateway.add_route(document()["routes"][0])

    def test_mutations_need_a_config_path(self):
        gateway = Gateway(config_path=None, data_dir=os.path.join(self.root, "empty"))
        with self.assertRaises(GatewayError):
            gateway.add_key("acme", ["read"])


if __name__ == "__main__":
    unittest.main()
