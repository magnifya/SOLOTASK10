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
SECRET_OFF = "off-secret"
SECRET_EXP = "exp-secret"
SECRET_BOTH = "both-secret"


def validity_document():
    return {
        "quota_policies": [
            {"id": "p-key", "tenant": "*", "algorithm": "token-bucket",
             "limit": 2, "window_ms": 60000, "burst": 2, "partition_by": "key"},
            {"id": "p-tenant", "tenant": "*", "algorithm": "token-bucket",
             "limit": 2, "window_ms": 60000, "burst": 2, "partition_by": "tenant"}],
        "keys": [
            {"key_id": "k-on", "tenant": "acme", "secret_sha256": sha(SECRET_READ),
             "scopes": ["read"]},
            {"key_id": "k-off", "tenant": "acme", "secret_sha256": sha(SECRET_OFF),
             "scopes": ["read"], "enabled": False},
            {"key_id": "k-exp", "tenant": "acme", "secret_sha256": sha(SECRET_EXP),
             "scopes": ["read"], "expires_at_ms": 1000},
            {"key_id": "k-both", "tenant": "acme", "secret_sha256": sha(SECRET_BOTH),
             "scopes": ["read"], "enabled": False, "expires_at_ms": 1000}],
        "routes": [
            {"id": "r-auth", "tenant": "acme", "match": {"method": "GET", "path_prefix": "/a"},
             "upstream": "echo", "scopes": ["read"], "quota_policy": "p-key"},
            {"id": "r-open", "tenant": "acme", "match": {"method": "GET", "path_prefix": "/o"},
             "upstream": "echo", "auth_required": False},
            {"id": "r-k", "tenant": "*", "match": {"method": "GET", "path_prefix": "/k"},
             "upstream": "echo", "auth_required": False, "quota_policy": "p-key"},
            {"id": "r-t", "tenant": "*", "match": {"method": "GET", "path_prefix": "/t"},
             "upstream": "echo", "auth_required": False, "quota_policy": "p-tenant"}],
    }


class KeyValidityTest(unittest.TestCase):
    def setUp(self):
        self.gateway, self.root, self.path = make_gateway(validity_document())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.calls = []

        def counting(request):
            self.calls.append(request)
            return {"status": 200, "body": {"n": len(self.calls)}}

        self.gateway.upstreams.register("echo", counting)

    def auth(self, secret):
        return {"authorization": "Bearer " + secret}

    def body_of(self, response):
        return json.loads(response["body"])

    def reload(self, mutate):
        doc = validity_document()
        mutate(doc)
        write_config(self.path, doc)
        self.assertTrue(self.gateway.reload_config())

    def test_disabled_key_is_401_without_quota_usage_or_upstream(self):
        response = self.gateway.handle("acme", "GET", "/a/x", self.auth(SECRET_OFF), "", now_ms=0)
        self.assertEqual(response["status"], 401)
        payload = self.body_of(response)
        self.assertEqual(payload["error"], "api key disabled")
        self.assertIn("request_id", payload)
        self.assertEqual(len(self.calls), 0)
        self.assertEqual(self.gateway.usage("acme")["requests"], 0)
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual((entry["status"], entry["attempts"], entry["idempotent_replay"]),
                         (401, 0, False))
        self.assertIsNone(entry["key_id"])

    def test_expiry_boundary_and_error_precedence(self):
        ok = self.gateway.handle("acme", "GET", "/a/x", self.auth(SECRET_EXP), "", now_ms=999)
        self.assertEqual(ok["status"], 200)
        expired = self.gateway.handle("acme", "GET", "/a/x", self.auth(SECRET_EXP), "", now_ms=1000)
        self.assertEqual(expired["status"], 401)
        self.assertEqual(self.body_of(expired)["error"], "api key expired")
        both = self.gateway.handle("acme", "GET", "/a/x", self.auth(SECRET_BOTH), "", now_ms=2000)
        self.assertEqual(self.body_of(both)["error"], "api key disabled")

    def test_invalid_key_on_plain_anonymous_route_is_treated_as_anonymous(self):
        response = self.gateway.handle("", "GET", "/o/x", self.auth(SECRET_OFF), "", now_ms=0)
        self.assertEqual(response["status"], 200)
        entry = self.gateway.audit("", 1)[0]
        self.assertIsNone(entry["key_id"])
        self.assertEqual(entry["tenant"], "")

    def test_invalid_key_on_key_partition_route_is_401(self):
        off = self.gateway.handle("", "GET", "/k/x", self.auth(SECRET_OFF), "", now_ms=0)
        exp = self.gateway.handle("", "GET", "/k/x", self.auth(SECRET_EXP), "", now_ms=1000)
        self.assertEqual([off["status"], exp["status"]], [401, 401])
        self.assertEqual(self.body_of(off)["error"], "api key disabled")
        self.assertEqual(self.body_of(exp)["error"], "api key expired")
        self.assertEqual(len(self.calls), 0)
        self.assertEqual(self.gateway.usage("")["requests"], 0)

    def test_invalid_key_does_not_supply_the_tenant_partition_identity(self):
        no_tenant = self.gateway.handle("", "GET", "/t/x", self.auth(SECRET_OFF), "", now_ms=0)
        self.assertEqual(no_tenant["status"], 400)
        self.assertIn("tenant", self.body_of(no_tenant)["error"])
        with_tenant = self.gateway.handle("acme", "GET", "/t/x", self.auth(SECRET_OFF), "", now_ms=0)
        self.assertEqual(with_tenant["status"], 200)  # anonymous under the request tenant

    def test_no_route_still_404_with_an_invalid_key(self):
        response = self.gateway.handle("acme", "GET", "/nope", self.auth(SECRET_OFF), "", now_ms=0)
        self.assertEqual(response["status"], 404)

    def test_hot_reload_disable_and_enable_keeps_the_quota_bucket(self):
        for _ in range(2):
            self.assertEqual(
                self.gateway.handle("acme", "GET", "/a/x", self.auth(SECRET_READ), "",
                                    now_ms=0)["status"], 200)
        self.assertEqual(
            self.gateway.handle("acme", "GET", "/a/x", self.auth(SECRET_READ), "",
                                now_ms=0)["status"], 429)
        self.reload(lambda doc: doc["keys"][0].update(enabled=False))
        disabled = self.gateway.handle("acme", "GET", "/a/x", self.auth(SECRET_READ), "", now_ms=0)
        self.assertEqual((disabled["status"], self.body_of(disabled)["error"]),
                         (401, "api key disabled"))
        self.reload(lambda doc: None)  # back to the enabled document
        # the bucket was not reset while the key was disabled
        self.assertEqual(
            self.gateway.handle("acme", "GET", "/a/x", self.auth(SECRET_READ), "",
                                now_ms=0)["status"], 429)

    def test_hot_reload_adjusts_the_expiry_for_later_requests(self):
        self.assertEqual(
            self.gateway.handle("acme", "GET", "/a/x", self.auth(SECRET_EXP), "",
                                now_ms=500)["status"], 200)
        self.reload(lambda doc: doc["keys"][2].update(expires_at_ms=400))
        response = self.gateway.handle("acme", "GET", "/a/x", self.auth(SECRET_EXP), "", now_ms=500)
        self.assertEqual((response["status"], self.body_of(response)["error"]),
                         (401, "api key expired"))

    def test_idempotent_replay_never_bypasses_key_validity(self):
        headers = dict(self.auth(SECRET_READ), **{"x-idempotency-key": "idem-off"})
        first = self.gateway.handle("acme", "GET", "/a/x", headers, "", now_ms=0)
        self.assertEqual(first["status"], 200)
        self.reload(lambda doc: doc["keys"][0].update(enabled=False))
        blocked = self.gateway.handle("acme", "GET", "/a/x", headers, "", now_ms=1)
        self.assertEqual(blocked["status"], 401)
        self.assertNotIn("X-Idempotent-Replay", blocked["headers"])
        self.assertEqual(len(self.calls), 1)
        self.reload(lambda doc: None)  # re-enable
        replay = self.gateway.handle("acme", "GET", "/a/x", headers, "", now_ms=2)
        self.assertEqual(replay["status"], 200)
        self.assertEqual(replay["headers"]["X-Idempotent-Replay"], "true")
        self.assertEqual(len(self.calls), 1)
        # quota is still checked before the replay: the two allowed requests above
        # exhausted the bucket, so the next replay attempt is a 429
        throttled = self.gateway.handle("acme", "GET", "/a/x", headers, "", now_ms=3)
        self.assertEqual(throttled["status"], 429)


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

    def key_doc(self, **fields):
        key = {"key_id": "k", "tenant": "t",
               "secret_sha256": hashlib.sha256(b"s").hexdigest()}
        key.update(fields)
        return {"keys": [key]}

    def test_malformed_key_validity_fields_are_rejected(self):
        cases = {
            "enabled string": {"enabled": "yes"},
            "enabled number": {"enabled": 1},
            "enabled null": {"enabled": None},
            "enabled list": {"enabled": [True]},
            "expires bool": {"expires_at_ms": True},
            "expires zero": {"expires_at_ms": 0},
            "expires negative": {"expires_at_ms": -5},
            "expires float": {"expires_at_ms": 1.5},
            "expires string": {"expires_at_ms": "1000"},
        }
        for label, fields in cases.items():
            write_config(self.path, self.key_doc(**fields))
            with self.assertRaises(GatewayError, msg=label) as caught:
                load(self.path)
            self.assertEqual(caught.exception.status, 400)

    def test_key_validity_defaults_and_round_trip(self):
        write_config(self.path, self.key_doc())
        key = load(self.path).keys[0]
        self.assertTrue(key.enabled)
        self.assertIsNone(key.expires_at_ms)
        self.assertEqual(key.to_dict()["enabled"], True)
        self.assertIsNone(key.to_dict()["expires_at_ms"])
        write_config(self.path, self.key_doc(enabled=False, expires_at_ms=None))
        key = load(self.path).keys[0]
        self.assertFalse(key.enabled)
        self.assertIsNone(key.expires_at_ms)
        write_config(self.path, self.key_doc(expires_at_ms=1000))
        key = load(self.path).keys[0]
        self.assertEqual(key.expires_at_ms, 1000)
        self.assertEqual(key.to_dict()["expires_at_ms"], 1000)

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


class FallbackTest(unittest.TestCase):
    """Ordered fallback upstreams: per-upstream retries and breakers, failover
    only on transport errors and 5xx, and only for GET or idempotent requests."""

    def setUp(self):
        doc = document()
        doc["routes"].append({
            "id": "r-fb", "tenant": "acme", "match": {"method": "*", "path_prefix": "/fb"},
            "upstream": "primary", "auth_required": False,
            "fallback_upstreams": ["backup-a", "backup-b"]})
        doc["routes"].append({
            "id": "r-fbq", "tenant": "acme", "match": {"method": "GET", "path_prefix": "/fbq"},
            "upstream": "primary", "auth_required": False, "quota_policy": "p-fast",
            "fallback_upstreams": ["backup-a"]})
        self.gateway, self.root, self.path = make_gateway(
            doc, breaker_settings={"failure_threshold": 1, "open_ms": 1000,
                                   "success_threshold": 1})
        self.addCleanup(shutil.rmtree, self.root, True)
        self.calls = {"primary": [], "backup-a": [], "backup-b": []}

    def register(self, name, fn):
        def counting(request, _fn=fn, _name=name):
            self.calls[_name].append(request)
            return _fn(request)
        self.gateway.upstreams.register(name, counting)

    def ok(self, request):
        return {"status": 200, "body": {"ok": True}}

    def boom(self, request):
        raise UpstreamError("boom")

    def down(self, request):
        return {"status": 500, "body": {"error": "down"}}

    def body_of(self, response):
        return json.loads(response["body"])

    def test_get_fails_over_on_transport_error(self):
        self.register("primary", self.boom)
        self.register("backup-a", self.ok)
        response = self.gateway.handle("acme", "GET", "/fb/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 200)
        self.assertEqual(len(self.calls["primary"]), 3)   # full retry budget first
        self.assertEqual(len(self.calls["backup-a"]), 1)
        self.assertEqual(len(self.calls["backup-b"]), 0)
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual((entry["attempts"], entry["upstream"], entry["status"]),
                         (4, "backup-a", 200))

    def test_get_fails_over_on_5xx_after_exhausting_retries(self):
        self.register("primary", self.down)
        self.register("backup-a", self.ok)
        response = self.gateway.handle("acme", "GET", "/fb/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 200)
        self.assertEqual(len(self.calls["primary"]), 3)
        self.assertEqual(self.gateway.audit("acme", 1)[0]["attempts"], 4)

    def test_non_5xx_status_is_returned_without_failover(self):
        self.register("primary", lambda request: {"status": 404, "body": {"error": "gone"}})
        self.register("backup-a", self.ok)
        response = self.gateway.handle("acme", "GET", "/fb/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 404)
        self.assertEqual(len(self.calls["backup-a"]), 0)

    def test_408_is_retried_then_returned_without_failover(self):
        self.register("primary", lambda request: {"status": 408, "body": {}})
        self.register("backup-a", self.ok)
        response = self.gateway.handle("acme", "GET", "/fb/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 408)
        self.assertEqual(len(self.calls["primary"]), 3)  # existing retry rule
        self.assertEqual(len(self.calls["backup-a"]), 0)

    def test_post_without_an_idempotency_key_never_fails_over(self):
        self.register("primary", self.boom)
        self.register("backup-a", self.ok)
        response = self.gateway.handle("acme", "POST", "/fb/x", {}, "{}", now_ms=0)
        self.assertEqual(response["status"], 502)
        self.assertEqual(len(self.calls["primary"]), 3)
        self.assertEqual(len(self.calls["backup-a"]), 0)
        self.assertEqual(len(self.calls["backup-b"]), 0)

    def test_post_with_an_idempotency_key_fails_over(self):
        self.register("primary", self.boom)
        self.register("backup-a", self.ok)
        headers = {"x-idempotency-key": "fb-idem"}
        response = self.gateway.handle("acme", "POST", "/fb/x", headers, "{}", now_ms=0)
        self.assertEqual(response["status"], 200)
        self.assertEqual(len(self.calls["backup-a"]), 1)

    def test_breaker_open_upstream_is_skipped_without_a_call(self):
        self.register("primary", self.ok)
        self.register("backup-a", self.ok)
        self.gateway.breakers.get("primary").record(False, 0)  # threshold 1: trips open
        response = self.gateway.handle("acme", "GET", "/fb/x", {}, "", now_ms=1)
        self.assertEqual(response["status"], 200)
        self.assertEqual(len(self.calls["primary"]), 0)
        self.assertEqual(len(self.calls["backup-a"]), 1)
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual((entry["upstream"], entry["attempts"]), ("backup-a", 1))

    def test_all_breakers_open_returns_503_with_the_primary_state(self):
        for name in ("primary", "backup-a", "backup-b"):
            self.gateway.breakers.get(name).record(False, 0)
        response = self.gateway.handle("acme", "GET", "/fb/x", {}, "", now_ms=1)
        self.assertEqual(response["status"], 503)
        self.assertEqual(self.body_of(response)["state"], "open")
        self.assertEqual(sum(len(v) for v in self.calls.values()), 0)
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual((entry["attempts"], entry["upstream"]), (0, "primary"))

    def test_fallback_chain_exhausted_returns_the_last_5xx_response(self):
        self.register("primary", self.down)
        self.register("backup-a", self.down)
        self.register("backup-b", lambda request: {"status": 503, "body": {"last": True},
                                                   "headers": {"X-Last": "b"}})
        response = self.gateway.handle("acme", "GET", "/fb/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 503)
        self.assertTrue(self.body_of(response)["last"])
        self.assertEqual(response["headers"]["X-Last"], "b")
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual((entry["attempts"], entry["upstream"]), (9, "backup-b"))

    def test_fallback_chain_exhausted_by_transport_errors_is_502(self):
        for name in ("primary", "backup-a", "backup-b"):
            self.register(name, self.boom)
        response = self.gateway.handle("acme", "GET", "/fb/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 502)
        self.assertEqual(self.body_of(response)["upstream"], "backup-b")
        self.assertEqual(self.gateway.audit("acme", 1)[0]["attempts"], 9)

    def test_unregistered_fallback_is_treated_as_a_transport_error(self):
        self.register("primary", self.boom)
        # backup-a is never registered; backup-b answers
        self.register("backup-b", self.ok)
        response = self.gateway.handle("acme", "GET", "/fb/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 200)
        self.assertEqual(len(self.calls["backup-b"]), 1)

    def test_failover_charges_quota_and_writes_usage_exactly_once(self):
        self.register("primary", self.boom)
        self.register("backup-a", self.ok)
        response = self.gateway.handle("acme", "GET", "/fbq/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 200)
        usage = self.gateway.usage("acme")
        self.assertEqual((usage["requests"], usage["allowed"]), (1, 1))
        self.assertEqual(len(self.calls["primary"]) + len(self.calls["backup-a"]), 4)

    def test_idempotency_stores_only_the_final_non_5xx_response(self):
        self.register("primary", self.down)
        self.register("backup-a", self.ok)
        headers = {"x-idempotency-key": "fb-cache"}
        first = self.gateway.handle("acme", "POST", "/fb/x", headers, "{}", now_ms=0)
        second = self.gateway.handle("acme", "POST", "/fb/x", headers, "{}", now_ms=1)
        self.assertEqual((first["status"], second["status"]), (200, 200))
        self.assertEqual(second["headers"]["X-Idempotent-Replay"], "true")
        total = sum(len(v) for v in self.calls.values())
        self.assertEqual(total, 4)  # the replay ran no upstream call at all

    def test_final_5xx_is_not_cached_for_idempotent_replay(self):
        for name in ("primary", "backup-a", "backup-b"):
            self.register(name, self.down)
        headers = {"x-idempotency-key": "fb-miss"}
        first = self.gateway.handle("acme", "POST", "/fb/x", headers, "{}", now_ms=0)
        self.gateway.breaker_reset()  # the 5xx calls tripped every breaker
        second = self.gateway.handle("acme", "POST", "/fb/x", headers, "{}", now_ms=1)
        self.assertEqual((first["status"], second["status"]), (500, 500))
        self.assertNotIn("X-Idempotent-Replay", second["headers"])
        self.assertEqual(sum(len(v) for v in self.calls.values()), 18)

    def test_route_without_fallbacks_keeps_the_original_behaviour(self):
        attempts = []

        def flaky(request):
            attempts.append(request)
            raise UpstreamError("boom")

        self.gateway.upstreams.register("flaky", flaky)
        self.gateway.add_route({"id": "r-flaky", "tenant": "acme",
                                "match": {"method": "GET", "path_prefix": "/flaky"},
                                "upstream": "flaky", "auth_required": False})
        first = self.gateway.handle("acme", "GET", "/flaky/x", {}, "", now_ms=0)
        self.assertEqual((first["status"], len(attempts)), (502, 3))
        second = self.gateway.handle("acme", "GET", "/flaky/x", {}, "", now_ms=10)
        self.assertEqual(second["status"], 503)
        self.assertEqual(self.body_of(second)["state"], "open")
        self.assertEqual(len(attempts), 3)

    def test_hot_reload_applies_the_new_order_and_keeps_breaker_state(self):
        self.register("primary", self.ok)
        self.register("backup-a", self.ok)
        self.register("backup-b", self.ok)
        self.gateway.breakers.get("primary").record(False, 0)  # open
        doc = document()
        doc["routes"].append({
            "id": "r-fb", "tenant": "acme", "match": {"method": "*", "path_prefix": "/fb"},
            "upstream": "primary", "auth_required": False,
            "fallback_upstreams": ["backup-b", "backup-a"]})  # swapped order
        doc["routes"].append({
            "id": "r-fbq", "tenant": "acme", "match": {"method": "GET", "path_prefix": "/fbq"},
            "upstream": "primary", "auth_required": False, "quota_policy": "p-fast",
            "fallback_upstreams": ["backup-a"]})
        write_config(self.path, doc)
        self.assertTrue(self.gateway.reload_config())
        response = self.gateway.handle("acme", "GET", "/fb/x", {}, "", now_ms=1)
        self.assertEqual(response["status"], 200)
        self.assertEqual(len(self.calls["backup-b"]), 1)   # new order: backup-b first
        self.assertEqual(len(self.calls["backup-a"]), 0)
        self.assertEqual(self.gateway.breakers.get("primary").state, "open")

    def test_invalid_reload_keeps_the_last_good_fallback_config(self):
        self.register("primary", self.boom)
        self.register("backup-a", self.ok)
        doc = document()
        doc["routes"].append({
            "id": "r-fb", "tenant": "acme", "match": {"method": "*", "path_prefix": "/fb"},
            "upstream": "primary", "auth_required": False,
            "fallback_upstreams": ["primary"]})  # repeats the primary: invalid
        write_config(self.path, doc)
        self.assertFalse(self.gateway.reload_config())
        self.assertFalse(self.gateway.store.ready)
        response = self.gateway.handle("acme", "GET", "/fb/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 200)  # old chain still in effect
        self.assertEqual(len(self.calls["backup-a"]), 1)


class FallbackConfigTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-fallback-config-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = os.path.join(self.root, "config.json")

    def route(self, **extra):
        base = {"id": "r", "match": {"method": "GET", "path_prefix": "/a"},
                "upstream": "echo"}
        base.update(extra)
        return base

    def test_malformed_fallback_lists_are_rejected(self):
        cases = {
            "null": None,
            "not an array": "echo",
            "non-string entry": ["a", 1],
            "empty entry": [""],
            "duplicate entry": ["a", "a"],
            "repeats the primary": ["a", "echo"],
        }
        for label, value in cases.items():
            doc = {"routes": [dict(self.route(), fallback_upstreams=value)]}
            write_config(self.path, doc)
            with self.assertRaises(GatewayError, msg=label):
                load(self.path)

    def test_omitted_fallbacks_default_to_empty_and_round_trip(self):
        write_config(self.path, {"routes": [self.route()]})
        route = load(self.path).routes[0]
        self.assertEqual(route.fallback_upstreams, [])
        self.assertEqual(route.to_dict()["fallback_upstreams"], [])
        write_config(self.path, {"routes": [self.route(fallback_upstreams=["b", "c"])]})
        route = load(self.path).routes[0]
        self.assertEqual(route.fallback_upstreams, ["b", "c"])
        self.assertEqual(route.to_dict()["fallback_upstreams"], ["b", "c"])

    def test_sanitized_config_reports_fallback_upstreams(self):
        gateway, root, _ = make_gateway()
        self.addCleanup(shutil.rmtree, root, True)
        gateway.add_route({"id": "r-fb", "tenant": "acme",
                           "match": {"method": "GET", "path_prefix": "/fb"},
                           "upstream": "echo", "fallback_upstreams": ["ghost"]})
        routes = {r["id"]: r for r in gateway.sanitized_config()["routes"]}
        self.assertEqual(routes["r-fb"]["fallback_upstreams"], ["ghost"])
        self.assertEqual(routes["r-api"]["fallback_upstreams"], [])

    def test_route_add_rejects_bad_fallbacks_without_changing_the_config(self):
        gateway, root, path = make_gateway()
        self.addCleanup(shutil.rmtree, root, True)
        before = json.dumps(gateway.sanitized_config(), sort_keys=True)
        for bad in (None, "echo", [""], ["a", "a"], ["echo"], [1]):
            with self.assertRaises(GatewayError, msg=repr(bad)):
                gateway.add_route({"id": "r-bad", "tenant": "acme",
                                   "match": {"method": "GET", "path_prefix": "/bad"},
                                   "upstream": "echo", "fallback_upstreams": bad})
        self.assertEqual(json.dumps(gateway.sanitized_config(), sort_keys=True), before)
        with open(path, "r", encoding="utf-8") as handle:
            self.assertNotIn("r-bad", handle.read())


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

    def test_add_key_echoes_validity_fields_and_defaults(self):
        created = self.gateway.add_key("acme", ["read"])
        self.assertTrue(created["enabled"])
        self.assertIsNone(created["expires_at_ms"])
        created = self.gateway.add_key("acme", ["read"], key_id="k-temp",
                                       enabled=False, expires_at_ms=1000)
        self.assertFalse(created["enabled"])
        self.assertEqual(created["expires_at_ms"], 1000)
        keys = {k["key_id"]: k for k in self.gateway.sanitized_config()["keys"]}
        self.assertFalse(keys["k-temp"]["enabled"])
        self.assertEqual(keys["k-temp"]["expires_at_ms"], 1000)
        self.assertNotIn("secret_sha256", keys["k-temp"])
        self.assertTrue(keys["k-read"]["enabled"])
        self.assertIsNone(keys["k-read"]["expires_at_ms"])

    def test_add_key_rejects_invalid_validity_fields_without_changing_state(self):
        before = json.dumps(self.gateway.sanitized_config(), sort_keys=True)
        revision = self.gateway.store.revision
        for kwargs in ({"enabled": "yes"}, {"enabled": 1}, {"enabled": None},
                       {"expires_at_ms": True}, {"expires_at_ms": 0},
                       {"expires_at_ms": -1}, {"expires_at_ms": "1000"}):
            with self.assertRaises(GatewayError, msg=repr(kwargs)) as caught:
                self.gateway.add_key("acme", ["read"], **kwargs)
            self.assertEqual(caught.exception.status, 400)
        self.assertEqual(json.dumps(self.gateway.sanitized_config(), sort_keys=True), before)
        self.assertEqual(self.gateway.store.revision, revision)

    def test_mutations_need_a_config_path(self):
        gateway = Gateway(config_path=None, data_dir=os.path.join(self.root, "empty"))
        with self.assertRaises(GatewayError):
            gateway.add_key("acme", ["read"])


if __name__ == "__main__":
    unittest.main()
