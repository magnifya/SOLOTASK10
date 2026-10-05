"""Tests for route-level fixed quota cost (quota_cost)."""

import hashlib
import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from gwd.config import GatewayError, load
from gwd.gateway import Gateway
from gwd.http_app import create_server
from gwd.upstream import UpstreamError

SECRET_A = "secret-a"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_config(path, doc):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle)
    stat = os.stat(path)
    os.utime(path, ns=(stat.st_atime_ns + 1_000_000, stat.st_mtime_ns + 1_000_000))


def cost_document():
    return {
        "quota_policies": [
            # token bucket: 5 per 60s, burst 5 -> one unit refills in 12000ms
            {"id": "p-tok", "tenant": "*", "algorithm": "token-bucket",
             "limit": 5, "window_ms": 60000, "burst": 5},
            {"id": "p-leak", "tenant": "*", "algorithm": "leaky-bucket",
             "limit": 5, "window_ms": 60000, "burst": 5},
            {"id": "p-slide", "tenant": "*", "algorithm": "sliding-window",
             "limit": 5, "window_ms": 60000},
            {"id": "p-tenant", "tenant": "*", "algorithm": "token-bucket",
             "limit": 4, "window_ms": 60000, "burst": 4, "partition_by": "tenant"},
            {"id": "p-slow", "tenant": "*", "algorithm": "token-bucket",
             "limit": 2, "window_ms": 120000, "burst": 2},
        ],
        "keys": [
            {"key_id": "k-a", "tenant": "acme", "secret_sha256": sha(SECRET_A),
             "scopes": ["read"]},
        ],
        "routes": [
            {"id": "r-tok", "tenant": "*", "match": {"method": "GET", "path_prefix": "/tok"},
             "upstream": "echo", "auth_required": False,
             "quota_policy": "p-tok", "quota_cost": 3},
            {"id": "r-leak", "tenant": "*", "match": {"method": "GET", "path_prefix": "/leak"},
             "upstream": "echo", "auth_required": False,
             "quota_policy": "p-leak", "quota_cost": 3},
            {"id": "r-slide", "tenant": "*", "match": {"method": "GET", "path_prefix": "/slide"},
             "upstream": "echo", "auth_required": False,
             "quota_policy": "p-slide", "quota_cost": 3},
            {"id": "r-joint", "tenant": "*", "match": {"method": "GET", "path_prefix": "/joint"},
             "upstream": "echo", "auth_required": False,
             "quota_policies": ["p-tok", "p-slow"], "quota_cost": 2},
            {"id": "r-one", "tenant": "*", "match": {"method": "GET", "path_prefix": "/one"},
             "upstream": "echo", "auth_required": False, "quota_policy": "p-tok"},
            {"id": "r-none", "tenant": "*", "match": {"method": "GET", "path_prefix": "/none"},
             "upstream": "echo", "auth_required": False},
        ],
    }


def make_gateway(doc=None, **kwargs):
    root = tempfile.mkdtemp(prefix="gwd-cost-")
    path = os.path.join(root, "config.json")
    write_config(path, cost_document() if doc is None else doc)
    gateway = Gateway(config_path=path, data_dir=os.path.join(root, "data"), **kwargs)
    return gateway, root, path


class CostConfigTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-cost-cfg-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = os.path.join(self.root, "config.json")

    def load_route(self, route):
        doc = cost_document()
        doc["routes"] = [route]
        write_config(self.path, doc)
        return load(self.path)

    def base_route(self, **extra):
        route = {"id": "r", "match": {"method": "GET", "path_prefix": "/a"},
                 "upstream": "echo", "auth_required": False, "quota_policy": "p-tok"}
        route.update(extra)
        return route

    def test_omitted_quota_cost_defaults_to_one(self):
        loaded = self.load_route(self.base_route())
        self.assertEqual(loaded.routes[0].quota_cost, 1)
        self.assertEqual(loaded.routes[0].to_dict()["quota_cost"], 1)

    def test_valid_quota_cost_round_trips(self):
        loaded = self.load_route(self.base_route(quota_cost=4))
        self.assertEqual(loaded.routes[0].quota_cost, 4)
        self.assertEqual(loaded.routes[0].to_dict()["quota_cost"], 4)

    def test_invalid_quota_cost_values_are_rejected_with_a_clear_error(self):
        cases = {
            "null": None,
            "boolean true": True,
            "boolean false": False,
            "string": "3",
            "float": 1.5,
            "float whole": 2.0,
            "zero": 0,
            "negative": -2,
            "array": [1],
            "object": {"n": 1},
        }
        for label, value in cases.items():
            with self.assertRaises(GatewayError, msg=label) as caught:
                self.load_route(self.base_route(quota_cost=value))
            self.assertIn("quota_cost must be a positive integer",
                          str(caught.exception), msg=label)

    def test_route_add_rejects_bad_cost_without_writing_or_advancing_revision(self):
        gateway, root, path = make_gateway()
        self.addCleanup(shutil.rmtree, root, True)
        revision = gateway.store.revision
        before = json.dumps(gateway.sanitized_config(), sort_keys=True)
        for bad in (None, True, "3", 1.5, 0, -1):
            with self.assertRaises(GatewayError, msg=repr(bad)) as caught:
                gateway.add_route({"id": "r-bad", "tenant": "*",
                                   "match": {"method": "GET", "path_prefix": "/bad"},
                                   "upstream": "echo", "auth_required": False,
                                   "quota_policy": "p-tok", "quota_cost": bad})
            self.assertIn("quota_cost must be a positive integer", str(caught.exception))
        self.assertEqual(gateway.store.revision, revision)
        self.assertEqual(json.dumps(gateway.sanitized_config(), sort_keys=True), before)
        with open(path, "r", encoding="utf-8") as handle:
            self.assertNotIn("r-bad", handle.read())

    def test_batch_route_add_with_one_bad_cost_is_all_or_nothing(self):
        gateway, root, path = make_gateway()
        self.addCleanup(shutil.rmtree, root, True)
        revision = gateway.store.revision
        good = {"id": "r-good", "tenant": "*",
                "match": {"method": "GET", "path_prefix": "/good"},
                "upstream": "echo", "auth_required": False,
                "quota_policy": "p-tok", "quota_cost": 2}
        bad = dict(good, id="r-bad2", quota_cost=0,
                   match={"method": "GET", "path_prefix": "/bad2"})
        with self.assertRaises(GatewayError):
            gateway.add_route([good, bad])
        self.assertEqual(gateway.store.revision, revision)
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
        self.assertNotIn("r-good", text)
        self.assertNotIn("r-bad2", text)
        # a valid add still works and persists the cost
        out = gateway.add_route(good)
        self.assertEqual(out["quota_cost"], 2)
        self.assertEqual(gateway.store.revision, revision + 1)
        self.assertEqual({r.id: r for r in gateway.config.routes}["r-good"].quota_cost, 2)

    def test_invalid_reload_keeps_the_old_config_buckets_and_lowers_readiness(self):
        gateway, root, path = make_gateway()
        self.addCleanup(shutil.rmtree, root, True)
        gateway.upstreams.register("echo", lambda request: {"status": 200, "body": {}})
        # spend 3 of 5 tokens on the old cost
        self.assertEqual(gateway.handle("acme", "GET", "/tok/x",
                                        {"x-tenant": "acme"}, "", now_ms=0)["status"], 200)
        doc = cost_document()
        doc["routes"][0]["quota_cost"] = 0
        write_config(path, doc)
        self.assertFalse(gateway.reload_config())
        self.assertFalse(gateway.store.ready)
        self.assertIn("quota_cost must be a positive integer", gateway.store.last_error)
        # the old route and its bucket survive: cost 3 against 2 remaining -> 429
        response = gateway.handle("acme", "GET", "/tok/x", {"x-tenant": "acme"}, "", now_ms=0)
        self.assertEqual(response["status"], 429)

    def test_valid_reload_changes_the_cost_without_resetting_buckets(self):
        gateway, root, path = make_gateway()
        self.addCleanup(shutil.rmtree, root, True)
        gateway.upstreams.register("echo", lambda request: {"status": 200, "body": {}})
        self.assertEqual(gateway.handle("acme", "GET", "/tok/x",
                                        {"x-tenant": "acme"}, "", now_ms=0)["status"], 200)
        doc = cost_document()
        doc["routes"][0]["quota_cost"] = 2
        write_config(path, doc)
        self.assertTrue(gateway.reload_config())
        # bucket kept its 2 remaining tokens: the new cost 2 exactly fits
        response = gateway.handle("acme", "GET", "/tok/x", {"x-tenant": "acme"}, "", now_ms=0)
        self.assertEqual(response["status"], 200)
        # and is now empty, so a third request is rejected
        response = gateway.handle("acme", "GET", "/tok/x", {"x-tenant": "acme"}, "", now_ms=0)
        self.assertEqual(response["status"], 429)


class CostAdmissionTest(unittest.TestCase):
    def setUp(self):
        self.gateway, self.root, self.path = make_gateway()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.calls = []

        def counting(request):
            self.calls.append(request)
            return {"status": 200, "body": {"n": len(self.calls)}}

        self.gateway.upstreams.register("echo", counting)

        def boom(request):
            raise UpstreamError("boom")

        self.gateway.upstreams.register("boom", boom)
        self.gateway.upstreams.register("backup", counting)

    def call(self, path, now_ms=0, tenant="acme", headers=None, body="", method="GET"):
        hdrs = {"x-tenant": tenant}
        hdrs.update(headers or {})
        return self.gateway.handle(tenant, method, path, hdrs, body, now_ms=now_ms)

    def body_of(self, response):
        return json.loads(response["body"])

    def test_token_bucket_charges_the_full_cost_and_reports_remaining(self):
        response = self.call("/tok/x")
        self.assertEqual(response["status"], 200)
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual(entry["quota"], {"policy_id": "p-tok", "allowed": True,
                                          "remaining": 2, "cost": 3})
        # 2 tokens left, cost 3: rejected; one more unit refills in 12000ms
        rejected = self.call("/tok/x")
        self.assertEqual(rejected["status"], 429)
        payload = self.body_of(rejected)
        self.assertEqual(payload["policy_id"], "p-tok")
        self.assertEqual(payload["reset_at_ms"], 12000)
        self.assertEqual(rejected["headers"]["Retry-After"], "12")
        self.assertEqual(len(self.calls), 1)
        # at t=12000 exactly one more unit has refilled and pays the cost
        self.assertEqual(self.call("/tok/x", now_ms=12000)["status"], 200)

    def test_leaky_bucket_and_sliding_window_apply_the_same_cost(self):
        self.assertEqual(self.call("/leak/x")["status"], 200)
        rejected = self.call("/leak/x")
        self.assertEqual(rejected["status"], 429)
        self.assertEqual(self.body_of(rejected)["reset_at_ms"], 12000)
        self.assertEqual(self.call("/slide/x")["status"], 200)
        rejected = self.call("/slide/x")
        self.assertEqual(rejected["status"], 429)
        # sliding window recovers when the oldest stamp leaves the window
        self.assertEqual(self.body_of(rejected)["reset_at_ms"], 60000)
        self.assertEqual(rejected["headers"]["Retry-After"], "60")

    def test_ledger_records_the_cost_for_allowed_and_rejected_requests(self):
        self.assertEqual(self.call("/tok/x")["status"], 200)
        self.assertEqual(self.call("/tok/x")["status"], 429)
        records = self.gateway.ledger.entries("acme")
        self.assertEqual(len(records), 2)
        self.assertEqual([(r["cost"], r["allowed"]) for r in records],
                         [(3, True), (3, False)])
        usage = self.gateway.usage("acme")
        self.assertEqual((usage["requests"], usage["allowed"], usage["rejected"],
                          usage["cost"], usage["allowed_cost"]), (2, 1, 1, 6, 3))
        self.assertEqual(usage["by_policy"]["p-tok"],
                         {"requests": 2, "allowed": 1, "rejected": 1, "cost": 6})

    def test_joint_admission_charges_each_policy_the_full_cost_or_nothing(self):
        # p-tok holds 5, p-slow holds 2; cost 2 -> p-slow fits exactly once
        self.assertEqual(self.call("/joint/x")["status"], 200)
        rejected = self.call("/joint/x")
        self.assertEqual(rejected["status"], 429)
        payload = self.body_of(rejected)
        # p-slow is the only short policy; it recovers one unit per 60000ms
        self.assertEqual(payload["policy_id"], "p-slow")
        self.assertEqual(payload["reset_at_ms"], 120000)
        self.assertEqual(rejected["headers"]["Retry-After"], "120")
        # the rejected group charged nothing: p-tok still holds 3 of 5
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual(entry["quotas"], [
            {"policy_id": "p-tok", "allowed": False, "remaining": 3, "cost": 2},
            {"policy_id": "p-slow", "allowed": False, "remaining": 0, "cost": 2}])
        self.assertEqual(entry["quota"], entry["quotas"][0])
        # one ledger record per named policy, each carrying the full cost
        records = self.gateway.ledger.entries("acme")
        self.assertEqual([(r["policy_id"], r["cost"], r["allowed"]) for r in records],
                         [("p-tok", 2, True), ("p-slow", 2, True),
                          ("p-tok", 2, False), ("p-slow", 2, False)])

    def test_joint_429_reports_the_first_short_policy_and_the_latest_reset(self):
        doc = cost_document()
        doc["routes"] = [
            {"id": "r-j", "tenant": "*", "match": {"method": "GET", "path_prefix": "/j"},
             "upstream": "echo", "auth_required": False,
             "quota_policies": ["p-slide", "p-tok"], "quota_cost": 4}]
        write_config(self.path, doc)
        self.gateway.reload_config()
        self.assertEqual(self.call("/j/x")["status"], 200)
        # both are short now (slide 1 left, tok 1 left); declaration order wins
        rejected = self.call("/j/x")
        payload = self.body_of(rejected)
        self.assertEqual(payload["policy_id"], "p-slide")
        # slide recovers at 60000, tok needs 3 more units at 12000ms each
        self.assertEqual(payload["reset_at_ms"], 60000)

    def test_default_cost_routes_keep_charging_one_unit(self):
        for _ in range(5):
            self.assertEqual(self.call("/one/x")["status"], 200)
        self.assertEqual(self.call("/one/x")["status"], 429)
        records = self.gateway.ledger.entries("acme")
        self.assertTrue(all(r["cost"] == 1 for r in records))

    def test_no_quota_route_never_records_usage_and_keeps_its_audit_shape(self):
        self.assertEqual(self.call("/none/x")["status"], 200)
        self.assertEqual(self.gateway.usage("acme")["requests"], 0)
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual(entry["quota"], {"policy_id": None, "allowed": True,
                                          "remaining": None})
        self.assertNotIn("quotas", entry)

    def test_auth_identity_and_version_rejections_record_no_quota(self):
        doc = cost_document()
        doc["routes"] = [
            {"id": "r-t", "tenant": "*", "match": {"method": "GET", "path_prefix": "/t"},
             "upstream": "echo", "auth_required": False,
             "quota_policy": "p-tenant", "quota_cost": 2},
            {"id": "r-auth", "tenant": "*", "match": {"method": "GET", "path_prefix": "/auth"},
             "upstream": "echo", "quota_policy": "p-tok", "quota_cost": 2},
            {"id": "r-ver", "tenant": "*", "match": {"method": "GET", "path_prefix": "/ver"},
             "upstream": "echo", "auth_required": False,
             "quota_policy": "p-tok", "quota_cost": 2, "version": "v2"}]
        write_config(self.path, doc)
        self.gateway.reload_config()
        # tenant-partition policy with no tenant -> 400 identity rejection
        self.assertEqual(self.call("/t/x", tenant="")["status"], 400)
        # auth route without a key -> 401
        self.assertEqual(self.call("/auth/x")["status"], 401)
        # versioned route without the header -> 406
        self.assertEqual(self.call("/ver/x")["status"], 406)
        self.assertEqual(self.gateway.usage("acme")["requests"], 0)
        self.assertEqual(self.gateway.usage("")["requests"], 0)
        for entry in self.gateway.audit("", 10):
            self.assertEqual(entry["quota"], {"policy_id": None, "allowed": True,
                                              "remaining": None})

    def test_idempotent_replay_rechecks_and_pays_the_cost_again(self):
        doc = cost_document()
        doc["routes"] = [
            {"id": "r-idem", "tenant": "*", "match": {"method": "POST", "path_prefix": "/idem"},
             "upstream": "echo", "auth_required": False,
             "quota_policy": "p-tok", "quota_cost": 3}]
        write_config(self.path, doc)
        self.gateway.reload_config()
        headers = {"x-idempotency-key": "cost-1"}
        first = self.call("/idem/x", headers=headers, body="{}", method="POST")
        self.assertEqual(first["status"], 200)
        # the replay is charged again: 2 tokens left, cost 3 -> 429, no replay
        second = self.call("/idem/x", headers=headers, body="{}", method="POST")
        self.assertEqual(second["status"], 429)
        self.assertNotIn("X-Idempotent-Replay", second["headers"])
        self.assertEqual(len(self.calls), 1)
        # after a refill the stored response replays, paying the cost once more
        third = self.call("/idem/x", now_ms=12000, headers=headers, body="{}", method="POST")
        self.assertEqual(third["status"], 200)
        self.assertEqual(third["headers"].get("X-Idempotent-Replay"), "true")
        self.assertEqual(len(self.calls), 1)
        # a different body reaches the idempotency conflict only after quota
        conflict = self.call("/idem/x", now_ms=60000, headers=headers,
                             body='{"x":1}', method="POST")
        self.assertEqual(conflict["status"], 409)
        records = self.gateway.ledger.entries("acme")
        self.assertEqual([r["cost"] for r in records], [3, 3, 3, 3])

    def test_retries_and_failover_never_charge_twice(self):
        doc = cost_document()
        doc["routes"] = [
            {"id": "r-fb", "tenant": "*", "match": {"method": "GET", "path_prefix": "/fb"},
             "upstream": "boom", "auth_required": False,
             "quota_policy": "p-tok", "quota_cost": 3,
             "fallback_upstreams": ["backup"]}]
        write_config(self.path, doc)
        self.gateway.reload_config()
        response = self.call("/fb/x")
        self.assertEqual(response["status"], 200)
        entry = self.gateway.audit("acme", 1)[0]
        self.assertGreater(entry["attempts"], 1)
        self.assertEqual(entry["upstream"], "backup")
        records = self.gateway.ledger.entries("acme")
        self.assertEqual(len(records), 1)
        self.assertEqual((records[0]["cost"], records[0]["allowed"]), (3, True))

    def test_sanitized_config_echoes_quota_cost_for_every_route(self):
        routes = {r["id"]: r for r in self.gateway.sanitized_config()["routes"]}
        self.assertEqual(routes["r-tok"]["quota_cost"], 3)
        self.assertEqual(routes["r-joint"]["quota_cost"], 2)
        # omitted in the source document -> echoed as 1
        self.assertEqual(routes["r-one"]["quota_cost"], 1)
        self.assertEqual(routes["r-none"]["quota_cost"], 1)


class CostHttpTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-cost-http-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.config_path = os.path.join(self.root, "config.json")
        write_config(self.config_path, cost_document())
        self.gateway = Gateway(config_path=self.config_path,
                               data_dir=os.path.join(self.root, "data"))
        self.gateway.upstreams.register("echo", lambda request: {"status": 200, "body": {}})
        self.server = create_server(self.gateway, "127.0.0.1", 0, quiet=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]

    def _stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def request(self, path, headers=None, method="GET"):
        req = urllib.request.Request(self.base + path, headers=headers or {}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, dict(response.headers), json.loads(
                    response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers or {}), json.loads(
                exc.read().decode("utf-8"))

    def test_proxy_applies_the_route_cost(self):
        status, _, _ = self.request("/tok/x", {"X-Tenant": "acme"})
        self.assertEqual(status, 200)
        status, headers, payload = self.request("/tok/x", {"X-Tenant": "acme"})
        self.assertEqual(status, 429)
        self.assertEqual(payload["policy_id"], "p-tok")
        self.assertIn(headers["Retry-After"], ("11", "12"))
        # the usage ledger recorded the full cost for both attempts
        req = urllib.request.Request(self.base + "/v1/quota/usage?tenant=acme")
        with urllib.request.urlopen(req, timeout=5) as response:
            usage = json.loads(response.read().decode("utf-8"))
        self.assertEqual((usage["requests"], usage["cost"], usage["allowed_cost"]),
                         (2, 6, 3))

    def test_config_endpoint_echoes_quota_cost(self):
        req = urllib.request.Request(self.base + "/v1/config")
        with urllib.request.urlopen(req, timeout=5) as response:
            config = json.loads(response.read().decode("utf-8"))
        routes = {r["id"]: r for r in config["routes"]}
        self.assertEqual(routes["r-tok"]["quota_cost"], 3)
        self.assertEqual(routes["r-joint"]["quota_cost"], 2)
        self.assertEqual(routes["r-one"]["quota_cost"], 1)
        self.assertEqual(routes["r-none"]["quota_cost"], 1)

    def test_reload_with_a_bad_cost_reports_not_ready(self):
        doc = cost_document()
        doc["routes"][0]["quota_cost"] = False
        write_config(self.config_path, doc)
        req = urllib.request.Request(self.base + "/v1/config/reload", method="POST")
        with urllib.request.urlopen(req, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        self.assertEqual(payload["reloaded"], False)
        self.assertEqual(payload["ready"], False)
        self.assertIn("quota_cost must be a positive integer", payload["error"])
        # the old config still serves at the old cost
        status, _, _ = self.request("/tok/x", {"X-Tenant": "acme"})
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
