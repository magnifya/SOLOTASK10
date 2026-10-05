"""Tests for joint quota admission: ordered quota_policies on a route."""

import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from gwd.config import GatewayError, load
from gwd.gateway import Gateway
from gwd.http_app import create_server
from gwd.upstream import UpstreamError

SECRET_A = "secret-a"
SECRET_B = "secret-b"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_config(path, doc):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle)
    stat = os.stat(path)
    os.utime(path, ns=(stat.st_atime_ns + 1_000_000, stat.st_mtime_ns + 1_000_000))


def joint_document():
    return {
        "quota_policies": [
            # tenant-wide budget: 2 per 60s; reset for one unit is 30000ms
            {"id": "p-total", "tenant": "*", "algorithm": "token-bucket",
             "limit": 2, "window_ms": 60000, "burst": 2, "partition_by": "tenant"},
            # per-key budget: 1 per 60s; reset 60000ms
            {"id": "p-key", "tenant": "*", "algorithm": "token-bucket",
             "limit": 1, "window_ms": 60000, "burst": 1, "partition_by": "key"},
            # policy-wide slow budget: 1 per 120s
            {"id": "p-slow", "tenant": "*", "algorithm": "token-bucket",
             "limit": 1, "window_ms": 120000, "burst": 1},
            {"id": "p-leak", "tenant": "*", "algorithm": "leaky-bucket",
             "limit": 2, "window_ms": 60000, "burst": 2},
            {"id": "p-slide", "tenant": "*", "algorithm": "sliding-window",
             "limit": 2, "window_ms": 60000},
        ],
        "keys": [
            {"key_id": "k-a", "tenant": "acme", "secret_sha256": sha(SECRET_A),
             "scopes": ["read"]},
            {"key_id": "k-b", "tenant": "acme", "secret_sha256": sha(SECRET_B),
             "scopes": ["read"]},
        ],
        "routes": [
            {"id": "r-both", "tenant": "*", "match": {"method": "GET", "path_prefix": "/both"},
             "upstream": "echo", "auth_required": False,
             "quota_policies": ["p-total", "p-key"]},
            {"id": "r-rev", "tenant": "*", "match": {"method": "GET", "path_prefix": "/rev"},
             "upstream": "echo", "auth_required": False,
             "quota_policies": ["p-key", "p-total"]},
            {"id": "r-single", "tenant": "*", "match": {"method": "GET", "path_prefix": "/single"},
             "upstream": "echo", "auth_required": False, "quota_policy": "p-total"},
            {"id": "r-none", "tenant": "*", "match": {"method": "GET", "path_prefix": "/none"},
             "upstream": "echo", "auth_required": False},
        ],
    }


def identity_document():
    return {
        "quota_policies": [
            {"id": "p-tt", "tenant": "*", "algorithm": "token-bucket",
             "limit": 5, "window_ms": 60000, "partition_by": "tenant"},
            {"id": "p-kk", "tenant": "*", "algorithm": "token-bucket",
             "limit": 5, "window_ms": 60000, "partition_by": "key"}],
        "keys": [
            {"key_id": "k-a", "tenant": "acme", "secret_sha256": sha(SECRET_A),
             "scopes": ["read"]}],
        "routes": [
            {"id": "r-tk", "tenant": "*", "match": {"method": "GET", "path_prefix": "/tk"},
             "upstream": "echo", "auth_required": False,
             "quota_policies": ["p-tt", "p-kk"]},
            {"id": "r-kt", "tenant": "*", "match": {"method": "GET", "path_prefix": "/kt"},
             "upstream": "echo", "auth_required": False,
             "quota_policies": ["p-kk", "p-tt"]}],
    }


def make_gateway(doc=None, **kwargs):
    root = tempfile.mkdtemp(prefix="gwd-joint-")
    path = os.path.join(root, "config.json")
    write_config(path, joint_document() if doc is None else doc)
    gateway = Gateway(config_path=path, data_dir=os.path.join(root, "data"), **kwargs)
    return gateway, root, path


class JointConfigTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-joint-cfg-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = os.path.join(self.root, "config.json")

    def base_doc(self):
        doc = joint_document()
        doc["routes"] = []
        return doc

    def load_route(self, route):
        doc = self.base_doc()
        doc["routes"] = [route]
        write_config(self.path, doc)
        return load(self.path)

    def test_malformed_quota_policies_are_rejected(self):
        def route(policies):
            return {"id": "r", "match": {"method": "GET", "path_prefix": "/a"},
                    "upstream": "echo", "auth_required": False, "quota_policies": policies}
        cases = {
            "null": None,
            "empty": [],
            "not an array": "p-total",
            "non-string entry": ["p-total", 1],
            "empty string": [""],
            "whitespace string": [" "],
            "duplicate": ["p-total", "p-total"],
            "unknown policy": ["p-total", "p-ghost"],
        }
        for label, value in cases.items():
            with self.assertRaises(GatewayError, msg=label):
                self.load_route(route(value))

    def test_both_policy_fields_set_is_rejected_even_when_quota_policy_is_null(self):
        # a non-empty quota_policy together with quota_policies is rejected
        with self.assertRaises(GatewayError):
            self.load_route({"id": "r", "match": {"method": "GET", "path_prefix": "/a"},
                             "upstream": "echo", "auth_required": False,
                             "quota_policy": "p-total", "quota_policies": ["p-key"]})
        # an explicit null quota_policy plus quota_policies is fine
        loaded = self.load_route({"id": "r", "match": {"method": "GET", "path_prefix": "/a"},
                                  "upstream": "echo", "auth_required": False,
                                  "quota_policy": None, "quota_policies": ["p-key"]})
        self.assertEqual(loaded.routes[0].quota_policies, ["p-key"])

    def test_omitted_field_round_trips_and_old_routes_keep_their_output(self):
        loaded = self.load_route({"id": "r", "match": {"method": "GET", "path_prefix": "/a"},
                                  "upstream": "echo", "auth_required": False,
                                  "quota_policy": "p-total"})
        self.assertIsNone(loaded.routes[0].quota_policies)
        as_dict = loaded.routes[0].to_dict()
        self.assertNotIn("quota_policies", as_dict)
        joint = self.load_route({"id": "r2", "match": {"method": "GET", "path_prefix": "/b"},
                                 "upstream": "echo", "auth_required": False,
                                 "quota_policies": ["p-total", "p-key"]})
        self.assertEqual(joint.routes[0].to_dict()["quota_policies"], ["p-total", "p-key"])

    def test_batch_route_add_is_all_or_nothing_and_keeps_revision(self):
        gateway, root, path = make_gateway()
        self.addCleanup(shutil.rmtree, root, True)
        revision = gateway.store.revision
        before = json.dumps(gateway.sanitized_config(), sort_keys=True)
        good = {"id": "r-good", "tenant": "*",
                "match": {"method": "GET", "path_prefix": "/good"},
                "upstream": "echo", "auth_required": False,
                "quota_policies": ["p-total", "p-key"]}
        bad = {"id": "r-bad", "tenant": "*",
               "match": {"method": "GET", "path_prefix": "/bad"},
               "upstream": "echo", "auth_required": False,
               "quota_policies": ["p-total", "p-ghost"]}
        with self.assertRaises(GatewayError):
            gateway.add_route([good, bad])
        self.assertEqual(gateway.store.revision, revision)
        self.assertEqual(json.dumps(gateway.sanitized_config(), sort_keys=True), before)
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
        self.assertNotIn("r-good", text)
        self.assertNotIn("r-bad", text)
        # a valid single add still works afterwards
        gateway.add_route(good)
        self.assertEqual(gateway.store.revision, revision + 1)


class JointAdmissionTest(unittest.TestCase):
    def setUp(self):
        self.gateway, self.root, self.path = make_gateway(
            breaker_settings={"failure_threshold": 1, "open_ms": 1000,
                               "success_threshold": 1})
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

    def key(self, secret=SECRET_A):
        return {"authorization": "Bearer " + secret}

    def body_of(self, response):
        return json.loads(response["body"])

    def call(self, path="/both/x", secret=SECRET_A, tenant="acme", **kw):
        headers = {}
        if secret:
            headers["authorization"] = "Bearer " + secret
        if tenant:
            headers["x-tenant"] = tenant
        return self.gateway.handle(tenant, "GET", path, headers, "", now_ms=kw.pop("now_ms", 0))

    def test_group_admits_when_every_policy_has_room_and_records_each_policy(self):
        response = self.call()
        self.assertEqual(response["status"], 200)
        self.assertEqual(len(self.calls), 1)
        usage = self.gateway.usage("acme")
        # one request -> two usage records, both allowed, cost one each
        self.assertEqual((usage["requests"], usage["allowed"], usage["rejected"],
                          usage["cost"], usage["allowed_cost"]), (2, 2, 0, 2, 2))
        by_policy = usage["by_policy"]
        self.assertEqual(set(by_policy), {"p-total", "p-key"})
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual(entry["quota"], {"policy_id": "p-total", "allowed": True,
                                          "remaining": 1, "cost": 1})
        self.assertEqual(entry["quotas"], [
            {"policy_id": "p-total", "allowed": True, "remaining": 1, "cost": 1},
            {"policy_id": "p-key", "allowed": True, "remaining": 0, "cost": 1}])

    def test_second_policy_short_decides_the_429_and_the_first_is_not_charged(self):
        self.assertEqual(self.call()["status"], 200)
        # same key again: tenant total has room, the key budget does not
        rejected = self.call()
        self.assertEqual(rejected["status"], 429)
        payload = self.body_of(rejected)
        self.assertEqual(payload["policy_id"], "p-key")  # first short in order
        self.assertEqual(payload["reset_at_ms"], 60000)
        self.assertEqual(rejected["headers"]["Retry-After"], "60")
        self.assertEqual(len(self.calls), 1)
        # every policy got one record for the rejected group, all marked rejected
        by_policy = self.gateway.usage("acme")["by_policy"]
        self.assertEqual({p: (v["allowed"], v["rejected"]) for p, v in by_policy.items()},
                         {"p-total": (1, 1), "p-key": (1, 1)})
        # the rejected group did not deduct p-total: at t=30000 it has refilled
        # to its full burst of 2 even though two more (rejected) attempts ran,
        # while the key budget is still short at that instant
        self.assertEqual(self.call(now_ms=30000)["status"], 429)
        self.assertEqual(self.call(now_ms=30000)["status"], 429)
        admitted = self.call(now_ms=60000)
        self.assertEqual(admitted["status"], 200)
        self.assertEqual(len(self.calls), 2)

    def test_first_policy_short_points_at_it_and_reset_is_the_latest_recovery(self):
        # request with key A spends total 2->1 and key A 1->0
        self.assertEqual(self.call(secret=SECRET_A)["status"], 200)
        # request with key B spends total 1->0 and key B 1->0
        self.assertEqual(self.call(secret=SECRET_B)["status"], 200)
        rejected = self.call(secret=SECRET_A)
        self.assertEqual(rejected["status"], 429)
        payload = self.body_of(rejected)
        # both are short; declaration order makes p-total the reported policy ...
        self.assertEqual(payload["policy_id"], "p-total")
        # ... but reset_at_ms waits for the slowest starving policy (p-key 60s)
        self.assertEqual(payload["reset_at_ms"], 60000)
        self.assertEqual(rejected["headers"]["Retry-After"], "60")
        # every record of the rejected group carries the group verdict
        records = self.gateway.ledger.entries("acme")[-2:]
        self.assertEqual({r["policy_id"] for r in records}, {"p-total", "p-key"})
        self.assertTrue(all(r["allowed"] is False and r["cost"] == 1 for r in records))

    def test_rejected_group_remaining_is_the_undeducted_balance(self):
        self.assertEqual(self.call()["status"], 200)
        rejected = self.call()
        entry = self.gateway.audit("acme", 1)[0]
        # p-total still held one unit (not deducted); p-key held zero
        self.assertEqual(entry["quotas"], [
            {"policy_id": "p-total", "allowed": False, "remaining": 1, "cost": 1},
            {"policy_id": "p-key", "allowed": False, "remaining": 0, "cost": 1}])
        self.assertEqual(entry["quota"], entry["quotas"][0])

    def test_all_three_algorithms_compose_in_one_group(self):
        doc = joint_document()
        doc["routes"] = [
            {"id": "r-algo", "tenant": "*", "match": {"method": "GET", "path_prefix": "/algo"},
             "upstream": "echo", "auth_required": False,
             "quota_policies": ["p-total", "p-leak", "p-slide"]}]
        write_config(self.path, doc)
        self.assertTrue(self.gateway.reload_config())
        statuses = [self.gateway.handle(
            "acme", "GET", "/algo/x", {"x-tenant": "acme"}, "", now_ms=0)["status"]
            for _ in range(3)]
        self.assertEqual(statuses, [200, 200, 429])
        usage = self.gateway.usage("acme")
        self.assertEqual((usage["allowed"], usage["rejected"]), (6, 3))
        self.assertEqual(set(usage["by_policy"]), {"p-total", "p-leak", "p-slide"})

    def test_concurrent_groups_cannot_partially_charge_or_exceed_either_limit(self):
        doc = joint_document()
        doc["quota_policies"] = [
            {"id": "p-ten", "tenant": "*", "algorithm": "token-bucket",
             "limit": 10, "window_ms": 60000, "partition_by": "tenant"},
            {"id": "p-wide", "tenant": "*", "algorithm": "sliding-window",
             "limit": 10, "window_ms": 60000}]
        doc["routes"] = [
            {"id": "r-c", "tenant": "*", "match": {"method": "GET", "path_prefix": "/c"},
             "upstream": "echo", "auth_required": False,
             "quota_policies": ["p-ten", "p-wide"]}]
        write_config(self.path, doc)
        self.gateway.reload_config()
        statuses = []
        lock = threading.Lock()

        def worker():
            response = self.gateway.handle("acme", "GET", "/c/x",
                                           {"x-tenant": "acme"}, "", now_ms=0)
            with lock:
                statuses.append(response["status"])

        threads = [threading.Thread(target=worker) for _ in range(40)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(statuses).count(200), 10)
        self.assertEqual(sorted(statuses).count(429), 30)
        self.assertEqual(len(self.calls), 10)
        usage = self.gateway.usage("acme")
        self.assertEqual((usage["requests"], usage["allowed"], usage["allowed_cost"]),
                         (80, 20, 20))

    def test_identity_failures_follow_declaration_order(self):
        gateway, root, path = make_gateway(identity_document())
        self.addCleanup(shutil.rmtree, root, True)
        calls = []
        gateway.upstreams.register("echo", lambda request: calls.append(request) or {
            "status": 200, "body": {}})
        # tenant partition comes first: anonymous request with no tenant is 400
        response = gateway.handle("", "GET", "/tk/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 400)
        self.assertIn("tenant", json.loads(response["body"])["error"])
        # key partition comes first on the other route: anonymous is 401
        response = gateway.handle("", "GET", "/kt/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 401)
        # valid key plus a mismatched explicit tenant is 403 at the first check
        response = gateway.handle("globex", "GET", "/tk/x", self.key(), "", now_ms=0)
        self.assertEqual(response["status"], 403)
        # valid key with no explicit tenant resolves both partitions and passes
        response = gateway.handle("", "GET", "/tk/x", self.key(), "", now_ms=0)
        self.assertEqual(response["status"], 200)
        self.assertEqual(len(calls), 1)
        # identity failures neither write usage nor enter the joint check: the
        # only ledger entries are the two policies of the single admitted group
        self.assertEqual(len(gateway.ledger.entries()), 2)
        entries = gateway.audit("", 10)
        blocked = [e for e in entries if e["status"] in (400, 401, 403)]
        self.assertEqual(len(blocked), 3)
        for entry in blocked:
            self.assertEqual(entry["quotas"], [])
            self.assertEqual(entry["quota"],
                             {"policy_id": None, "allowed": True, "remaining": None})

    def test_idempotent_replay_checks_the_whole_group_again(self):
        doc = joint_document()
        doc["routes"] = [
            {"id": "r-idem", "tenant": "*", "match": {"method": "POST", "path_prefix": "/idem"},
             "upstream": "echo", "auth_required": False,
             "quota_policies": ["p-total", "p-key"]}]
        write_config(self.path, doc)
        self.gateway.reload_config()
        headers = {"x-idempotency-key": "joint-1", "x-tenant": "acme",
                   "authorization": "Bearer " + SECRET_A}
        first = self.gateway.handle("acme", "POST", "/idem/x", headers, "{}", now_ms=0)
        self.assertEqual(first["status"], 200)
        # the replay is a second group charge: the per-key budget is exhausted,
        # so quota wins over the replay and no upstream is called
        second = self.gateway.handle("acme", "POST", "/idem/x", headers, "{}", now_ms=0)
        self.assertEqual(second["status"], 429)
        self.assertEqual(self.body_of(second)["policy_id"], "p-key")
        self.assertNotIn("X-Idempotent-Replay", second["headers"])
        self.assertEqual(len(self.calls), 1)
        # once both budgets refill, the stored response replays; a different
        # body still reaches the idempotency conflict only after quota passes
        third = self.gateway.handle("acme", "POST", "/idem/x", headers, "{}", now_ms=60000)
        self.assertEqual(third["headers"].get("X-Idempotent-Replay"), "true")
        conflict = self.gateway.handle("acme", "POST", "/idem/x", headers, "{\"x\":1}",
                                       now_ms=120000)
        self.assertEqual(conflict["status"], 409)

    def test_failover_charges_the_group_exactly_once(self):
        doc = joint_document()
        doc["routes"] = [
            {"id": "r-fb", "tenant": "*", "match": {"method": "GET", "path_prefix": "/fb"},
             "upstream": "boom", "auth_required": False,
             "quota_policies": ["p-total", "p-slow"],
             "fallback_upstreams": ["backup"]}]
        write_config(self.path, doc)
        self.gateway.reload_config()
        response = self.gateway.handle("acme", "GET", "/fb/x",
                                       {"x-tenant": "acme"}, "", now_ms=0)
        self.assertEqual(response["status"], 200)
        usage = self.gateway.usage("acme")
        self.assertEqual((usage["requests"], usage["allowed"]), (2, 2))
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual((entry["attempts"], entry["upstream"]), (4, "backup"))

    def test_single_policy_and_no_policy_routes_keep_their_audit_shape(self):
        self.gateway.handle("acme", "GET", "/single/x", {"x-tenant": "acme"}, "", now_ms=0)
        self.gateway.handle("acme", "GET", "/none/x", {"x-tenant": "acme"}, "", now_ms=0)
        entries = self.gateway.audit("acme", 2)
        single, plain = entries[0], entries[1]
        self.assertEqual(single["route_id"], "r-single")
        # a checked single policy keeps the legacy block plus the actual cost
        self.assertEqual(single["quota"], {"policy_id": "p-total", "allowed": True,
                                           "remaining": 1, "cost": 1})
        self.assertNotIn("quotas", single)
        self.assertEqual(plain["route_id"], "r-none")
        # a route without any quota policy keeps the exact legacy shape
        self.assertEqual(plain["quota"], {"policy_id": None, "allowed": True,
                                          "remaining": None})
        self.assertNotIn("cost", plain["quota"])
        self.assertNotIn("quotas", plain)

    def test_hot_reload_reorders_the_group_without_dropping_buckets(self):
        self.assertEqual(self.call("/both/x")["status"], 200)
        doc = joint_document()
        route = next(r for r in doc["routes"] if r["id"] == "r-both")
        route["quota_policies"] = ["p-key", "p-total"]
        write_config(self.path, doc)
        self.assertTrue(self.gateway.reload_config())
        # only the route combination changed: both partitions stay as they were,
        # so the key budget is still exhausted
        response = self.call("/both/x")
        self.assertEqual(response["status"], 429)
        self.assertEqual(self.body_of(response)["policy_id"], "p-key")

    def test_invalid_reload_keeps_the_last_group_and_lowers_readiness(self):
        doc = joint_document()
        route = next(r for r in doc["routes"] if r["id"] == "r-both")
        route["quota_policies"] = ["p-total", "p-ghost"]
        write_config(self.path, doc)
        self.assertFalse(self.gateway.reload_config())
        self.assertFalse(self.gateway.store.ready)
        self.assertIn("p-ghost", self.gateway.store.last_error)
        # old combination still serves
        response = self.call()
        self.assertEqual(response["status"], 200)

    def test_sanitized_config_echoes_only_new_style_routes(self):
        routes = {r["id"]: r for r in self.gateway.sanitized_config()["routes"]}
        self.assertEqual(routes["r-both"]["quota_policies"], ["p-total", "p-key"])
        self.assertNotIn("quota_policies", routes["r-single"])
        self.assertNotIn("quota_policies", routes["r-none"])


class JointHttpTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-joint-http-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.config_path = os.path.join(self.root, "config.json")
        write_config(self.config_path, joint_document())
        self.gateway = Gateway(config_path=self.config_path,
                               data_dir=os.path.join(self.root, "data"))
        self.server = create_server(self.gateway, "127.0.0.1", 0, quiet=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]

    def _stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def request(self, path, headers=None):
        req = urllib.request.Request(self.base + path, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, dict(response.headers), json.loads(
                    response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers or {}), json.loads(
                exc.read().decode("utf-8"))

    def test_proxy_applies_joint_admission_and_identity_rules(self):
        auth = {"authorization": "Bearer " + SECRET_A}
        status, _, _ = self.request("/both/x", auth)
        self.assertEqual(status, 200)
        before = int(time.time() * 1000)
        status, headers, payload = self.request("/both/x", auth)
        self.assertEqual(status, 429)
        self.assertEqual(payload["policy_id"], "p-key")
        # the HTTP front end uses the wall clock, so reset_at_ms is the absolute
        # recovery time ~60s out and Retry-After the usual conversion
        self.assertGreaterEqual(payload["reset_at_ms"], before + 59000)
        self.assertLessEqual(payload["reset_at_ms"], before + 61000)
        self.assertIn(headers["Retry-After"], ("59", "60"))
        # anonymous on a tenant+key group hits the tenant partition first
        status, _, payload = self.request("/both/x")
        self.assertEqual(status, 400)
        self.assertIn("tenant", payload["error"])
        # key-first ordering on the other route gives 401 anonymously
        status, _, _ = self.request("/rev/x")
        self.assertEqual(status, 401)

    def test_config_echoes_the_group(self):
        req = urllib.request.Request(self.base + "/v1/config")
        with urllib.request.urlopen(req, timeout=5) as response:
            config = json.loads(response.read().decode("utf-8"))
        routes = {r["id"]: r for r in config["routes"]}
        self.assertEqual(routes["r-both"]["quota_policies"], ["p-total", "p-key"])
        self.assertNotIn("quota_policies", routes["r-single"])


if __name__ == "__main__":
    unittest.main()
