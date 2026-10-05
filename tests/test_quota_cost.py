"""Route level fixed ``quota_cost``: a request may consume several units of
every quota policy it names, while retries, failover and replays keep the
single charge semantics of the historical one unit billing.
"""

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
            # token bucket: 4 units per 60s, one unit refills every 15000ms
            {"id": "p-tok", "tenant": "*", "algorithm": "token-bucket",
             "limit": 4, "window_ms": 60000, "burst": 4, "partition_by": "tenant"},
            {"id": "p-leak", "tenant": "*", "algorithm": "leaky-bucket",
             "limit": 4, "window_ms": 60000, "burst": 4, "partition_by": "tenant"},
            {"id": "p-slide", "tenant": "*", "algorithm": "sliding-window",
             "limit": 4, "window_ms": 60000, "partition_by": "tenant"},
            # a 2-unit burst that refills one unit per 30s / 60s
            {"id": "p-slow30", "tenant": "*", "algorithm": "token-bucket",
             "limit": 2, "window_ms": 60000, "burst": 2, "partition_by": "tenant"},
            {"id": "p-slow60", "tenant": "*", "algorithm": "token-bucket",
             "limit": 2, "window_ms": 120000, "burst": 2, "partition_by": "tenant"},
        ],
        "keys": [
            {"key_id": "k-a", "tenant": "acme", "secret_sha256": sha(SECRET_A),
             "scopes": ["read"]},
        ],
        "routes": [
            {"id": "r-tok3", "tenant": "*", "match": {"method": "GET", "path_prefix": "/tok"},
             "upstream": "echo", "auth_required": False,
             "quota_policy": "p-tok", "quota_cost": 3},
            {"id": "r-leak3", "tenant": "*", "match": {"method": "GET", "path_prefix": "/leak"},
             "upstream": "echo", "auth_required": False,
             "quota_policy": "p-leak", "quota_cost": 3},
            {"id": "r-slide3", "tenant": "*", "match": {"method": "GET", "path_prefix": "/slide"},
             "upstream": "echo", "auth_required": False,
             "quota_policy": "p-slide", "quota_cost": 3},
            {"id": "r-tiny", "tenant": "*", "match": {"method": "GET", "path_prefix": "/tiny"},
             "upstream": "echo", "auth_required": False,
             "quota_policy": "p-slide", "quota_cost": 9},
            {"id": "r-default", "tenant": "*", "match": {"method": "GET", "path_prefix": "/def"},
             "upstream": "echo", "auth_required": False, "quota_policy": "p-tok"},
            {"id": "r-joint3", "tenant": "*", "match": {"method": "GET", "path_prefix": "/joint"},
             "upstream": "echo", "auth_required": False,
             "quota_policies": ["p-slow30", "p-slow60"], "quota_cost": 3},
            {"id": "r-joint-ok", "tenant": "*",
             "match": {"method": "GET", "path_prefix": "/jointok"},
             "upstream": "echo", "auth_required": False,
             "quota_policies": ["p-tok", "p-slow60"], "quota_cost": 2},
            {"id": "r-open", "tenant": "*", "match": {"method": "GET", "path_prefix": "/open"},
             "upstream": "echo", "auth_required": False, "quota_cost": 7},
        ],
    }


def make_gateway(doc=None, **kwargs):
    root = tempfile.mkdtemp(prefix="gwd-cost-")
    path = os.path.join(root, "config.json")
    write_config(path, cost_document() if doc is None else doc)
    gateway = Gateway(config_path=path, data_dir=os.path.join(root, "data"), **kwargs)
    return gateway, root, path


class QuotaCostConfigTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-cost-cfg-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = os.path.join(self.root, "config.json")

    def base_route(self, **overrides):
        route = {"id": "r", "match": {"method": "GET", "path_prefix": "/a"},
                 "upstream": "echo", "auth_required": False}
        route.update(overrides)
        return route

    def load_route(self, route):
        doc = cost_document()
        doc["routes"] = [route]
        write_config(self.path, doc)
        return load(self.path)

    def test_omitted_cost_defaults_to_one(self):
        loaded = self.load_route(self.base_route(quota_policy="p-tok"))
        self.assertEqual(loaded.routes[0].quota_cost, 1)
        # old documents are echoed back with an explicit 1
        self.assertEqual(loaded.routes[0].to_dict()["quota_cost"], 1)

    def test_positive_integers_are_accepted(self):
        for value in (1, 2, 3, 100000):
            loaded = self.load_route(self.base_route(quota_policy="p-tok",
                                                     quota_cost=value))
            self.assertEqual(loaded.routes[0].quota_cost, value, value)

    def test_invalid_costs_are_rejected_with_one_exact_message(self):
        cases = {
            "null": None,
            "true": True,
            "false": False,
            "zero": 0,
            "negative": -1,
            "float": 1.5,
            "numeric float integer-valued": 2.0,
            "string": "2",
            "array": [2],
            "object": {},
        }
        for label, value in cases.items():
            with self.assertRaises(GatewayError, msg=label) as caught:
                self.load_route(self.base_route(quota_policy="p-tok", quota_cost=value))
            self.assertEqual(caught.exception.message,
                             "route r: quota_cost must be a positive integer", label)

    def test_cost_is_validated_even_without_any_quota_policy(self):
        with self.assertRaises(GatewayError):
            self.load_route(self.base_route(quota_cost=True))

    def test_get_config_echoes_the_cost_of_every_route(self):
        gateway, root, _ = make_gateway()
        self.addCleanup(shutil.rmtree, root, True)
        routes = {r["id"]: r for r in gateway.sanitized_config()["routes"]}
        self.assertEqual(routes["r-tok3"]["quota_cost"], 3)
        self.assertEqual(routes["r-joint3"]["quota_cost"], 3)
        self.assertEqual(routes["r-default"]["quota_cost"], 1)
        self.assertEqual(routes["r-open"]["quota_cost"], 7)

    def test_route_add_validates_cost_and_a_batch_is_all_or_nothing(self):
        gateway, root, path = make_gateway()
        self.addCleanup(shutil.rmtree, root, True)
        revision = gateway.store.revision
        before = json.dumps(gateway.sanitized_config(), sort_keys=True)
        good = {"id": "r-good", "tenant": "*",
                "match": {"method": "GET", "path_prefix": "/good"},
                "upstream": "echo", "auth_required": False,
                "quota_policy": "p-tok", "quota_cost": 2}
        bad = {"id": "r-bad", "tenant": "*",
               "match": {"method": "GET", "path_prefix": "/bad"},
               "upstream": "echo", "auth_required": False,
               "quota_policy": "p-tok", "quota_cost": False}
        with self.assertRaises(GatewayError) as caught:
            gateway.add_route([good, bad])
        self.assertIn("quota_cost must be a positive integer", caught.exception.message)
        self.assertEqual(gateway.store.revision, revision)
        self.assertEqual(json.dumps(gateway.sanitized_config(), sort_keys=True), before)
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
        self.assertNotIn("r-good", text)
        self.assertNotIn("r-bad", text)
        # a valid add still advances the revision exactly once
        out = gateway.add_route(good)
        self.assertEqual(out["quota_cost"], 2)
        self.assertEqual(gateway.store.revision, revision + 1)


class QuotaCostAlgorithmsTest(unittest.TestCase):
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

    def call(self, path, now_ms=0):
        return self.gateway.handle("acme", "GET", path, {"x-tenant": "acme"},
                                   "", now_ms=now_ms)

    def payload(self, response):
        return json.loads(response["body"])

    def test_token_bucket_charges_the_full_cost_and_reports_recovery_for_it(self):
        ok = self.call("/tok/x")
        self.assertEqual(ok["status"], 200)
        self.assertEqual(len(self.calls), 1)
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual(entry["quota"], {"policy_id": "p-tok", "allowed": True,
                                          "remaining": 1, "cost": 3})
        # only one unit left: a cost of three is rejected and nothing is deducted
        rejected = self.call("/tok/x")
        self.assertEqual(rejected["status"], 429)
        body = self.payload(rejected)
        self.assertEqual(body["policy_id"], "p-tok")
        # two of the three required units still need to accrue -> 30000ms
        self.assertEqual(body["reset_at_ms"], 30000)
        self.assertEqual(rejected["headers"]["Retry-After"], "30")
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual(entry["quota"]["remaining"], 1)
        self.assertEqual(len(self.calls), 1)
        # at 30000ms exactly three tokens are available again
        self.assertEqual(self.call("/tok/x", now_ms=30000)["status"], 200)
        self.assertEqual(len(self.calls), 2)

    def test_leaky_bucket_charges_the_full_cost(self):
        self.assertEqual(self.call("/leak/x")["status"], 200)
        rejected = self.call("/leak/x")
        self.assertEqual(rejected["status"], 429)
        self.assertEqual(self.payload(rejected)["reset_at_ms"], 30000)
        self.assertEqual(rejected["headers"]["Retry-After"], "30")
        self.assertEqual(self.call("/leak/x", now_ms=30000)["status"], 200)

    def test_sliding_window_appends_cost_stamps(self):
        self.assertEqual(self.call("/slide/x")["status"], 200)
        rejected = self.call("/slide/x")
        self.assertEqual(rejected["status"], 429)
        # three of the four slots are occupied; the (3-1)=2nd oldest stamp (t=0)
        # has to expire before three more units fit
        self.assertEqual(self.payload(rejected)["reset_at_ms"], 60000)
        self.assertEqual(rejected["headers"]["Retry-After"], "60")
        self.assertEqual(self.call("/slide/x", now_ms=59999)["status"], 429)
        self.assertEqual(self.call("/slide/x", now_ms=60000)["status"], 200)

    def test_cost_above_the_limit_is_always_rejected_without_crashing(self):
        rejected = self.call("/tiny/x")
        self.assertEqual(rejected["status"], 429)
        self.assertEqual(self.payload(rejected)["policy_id"], "p-slide")
        self.assertEqual(rejected["headers"]["Retry-After"], "60")
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual(entry["quota"], {"policy_id": "p-slide", "allowed": False,
                                          "remaining": 4, "cost": 9})
        # never becomes admissible while the cost stays above the limit
        for now_ms in (0, 60000, 120000):
            self.assertEqual(self.call("/tiny/x", now_ms=now_ms)["status"], 429)
        self.assertEqual(len(self.calls), 0)

    def test_default_cost_stays_one(self):
        for _ in range(4):
            self.assertEqual(self.call("/def/x")["status"], 200)
        self.assertEqual(self.call("/def/x")["status"], 429)

    def test_allowed_and_rejected_ledger_rows_carry_the_same_full_cost(self):
        self.call("/tok/x")             # 200, cost 3
        self.call("/tok/x")             # 429, cost 3
        rows = self.gateway.ledger.entries("acme")
        self.assertEqual([(r["allowed"], r["cost"]) for r in rows],
                         [(True, 3), (False, 3)])
        usage = self.gateway.usage("acme")
        self.assertEqual((usage["requests"], usage["allowed"], usage["rejected"],
                          usage["cost"], usage["allowed_cost"]), (2, 1, 1, 6, 3))

    def test_route_without_a_policy_is_not_billed(self):
        for _ in range(10):
            self.assertEqual(self.call("/open/x")["status"], 200)
        self.assertEqual(self.gateway.usage("acme")["requests"], 0)
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual(entry["quota"], {"policy_id": None, "allowed": True,
                                          "remaining": None})
        self.assertNotIn("cost", entry["quota"])
        self.assertNotIn("quotas", entry)

    def test_joint_group_pays_the_cost_on_every_policy_or_none(self):
        rejected = self.call("/joint/x")
        self.assertEqual(rejected["status"], 429)
        body = self.payload(rejected)
        # both policies are short; declaration order names p-slow30 ...
        self.assertEqual(body["policy_id"], "p-slow30")
        # ... but recovery waits for the slowest starving policy (120s window)
        self.assertEqual(body["reset_at_ms"], 60000)
        self.assertEqual(rejected["headers"]["Retry-After"], "60")
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual(entry["quotas"], [
            {"policy_id": "p-slow30", "allowed": False, "remaining": 2, "cost": 3},
            {"policy_id": "p-slow60", "allowed": False, "remaining": 2, "cost": 3}])
        self.assertEqual(entry["quota"], entry["quotas"][0])
        # nothing was deducted: both buckets still show their full burst later
        admitted = self.call("/jointok/x")  # cost 2: p-tok has 4, p-slow60 has 2
        self.assertEqual(admitted["status"], 200)
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual(entry["quotas"], [
            {"policy_id": "p-tok", "allowed": True, "remaining": 2, "cost": 2},
            {"policy_id": "p-slow60", "allowed": True, "remaining": 0, "cost": 2}])
        usage = self.gateway.usage("acme")
        by_policy = usage["by_policy"]
        self.assertEqual({p: (v["allowed"], v["rejected"], v["cost"])
                          for p, v in by_policy.items()},
                         {"p-slow30": (0, 1, 3), "p-slow60": (1, 1, 5),
                          "p-tok": (1, 0, 2)})

    def test_auth_rejection_on_a_cost_route_is_not_billed(self):
        doc = cost_document()
        doc["routes"] = [
            {"id": "r-secret", "tenant": "acme",
             "match": {"method": "GET", "path_prefix": "/secret"},
             "upstream": "echo", "scopes": ["read"],
             "quota_policy": "p-tok", "quota_cost": 3}]
        write_config(self.path, doc)
        self.assertTrue(self.gateway.reload_config())
        response = self.gateway.handle("acme", "GET", "/secret/x",
                                       {"x-tenant": "acme"}, "", now_ms=0)
        self.assertEqual(response["status"], 401)
        self.assertEqual(self.gateway.usage("acme")["requests"], 0)
        self.assertEqual(len(self.calls), 0)

    def test_idempotent_replay_checks_quota_again_and_pays_the_cost_again(self):
        doc = cost_document()
        doc["routes"] = [
            {"id": "r-idem", "tenant": "*", "match": {"method": "POST", "path_prefix": "/idem"},
             "upstream": "echo", "auth_required": False,
             "quota_policy": "p-slow30", "quota_cost": 2}]
        write_config(self.path, doc)
        self.assertTrue(self.gateway.reload_config())
        headers = {"x-idempotency-key": "cost-1", "x-tenant": "acme"}
        first = self.gateway.handle("acme", "POST", "/idem/x", headers, "{}", now_ms=0)
        self.assertEqual(first["status"], 200)
        # the replay re-enters quota: the 2-unit burst is exhausted, so quota
        # wins over the replay and no second upstream call happens
        second = self.gateway.handle("acme", "POST", "/idem/x", headers, "{}", now_ms=0)
        self.assertEqual(second["status"], 429)
        self.assertNotIn("X-Idempotent-Replay", second["headers"])
        rows = self.gateway.ledger.entries("acme")
        self.assertEqual([(r["allowed"], r["cost"]) for r in rows],
                         [(True, 2), (False, 2)])
        self.assertEqual(len(self.calls), 1)
        # once the bucket refilled, the stored response replays (still billed)
        third = self.gateway.handle("acme", "POST", "/idem/x", headers, "{}",
                                    now_ms=60000)
        self.assertEqual(third["status"], 200)
        self.assertEqual(third["headers"].get("X-Idempotent-Replay"), "true")
        self.assertEqual(len(self.calls), 1)
        last = self.gateway.ledger.entries("acme")[-1]
        self.assertEqual((last["allowed"], last["cost"]), (True, 2))

    def test_retries_and_failover_charge_the_cost_exactly_once(self):
        doc = cost_document()
        doc["routes"] = [
            {"id": "r-retry", "tenant": "*",
             "match": {"method": "GET", "path_prefix": "/retry"},
             "upstream": "boom", "auth_required": False,
             "quota_policy": "p-tok", "quota_cost": 3,
             "fallback_upstreams": ["backup"]}]
        write_config(self.path, doc)
        self.assertTrue(self.gateway.reload_config())
        response = self.gateway.handle("acme", "GET", "/retry/x",
                                       {"x-tenant": "acme"}, "", now_ms=0)
        self.assertEqual(response["status"], 200)
        # three attempts on boom plus the backup call, but a single quota charge
        usage = self.gateway.usage("acme")
        self.assertEqual((usage["requests"], usage["allowed"], usage["cost"]), (1, 1, 3))
        entry = self.gateway.audit("acme", 1)[0]
        self.assertGreaterEqual(entry["attempts"], 4)
        self.assertEqual(entry["upstream"], "backup")
        self.assertEqual(entry["quota"]["cost"], 3)

    def test_changing_cost_by_hot_reload_keeps_buckets_and_applies_to_new_requests(self):
        # spend three of four tokens under cost 3
        self.assertEqual(self.call("/tok/x")["status"], 200)
        doc = cost_document()
        route = next(r for r in doc["routes"] if r["id"] == "r-tok3")
        route["quota_cost"] = 1
        write_config(self.path, doc)
        self.assertTrue(self.gateway.reload_config())
        # buckets were not reset: one token remains and cost 1 now fits
        response = self.call("/tok/x")
        self.assertEqual(response["status"], 200)
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual(entry["quota"]["remaining"], 0)
        self.assertEqual(entry["quota"]["cost"], 1)
        self.gateway.breaker_reset()
        self.assertEqual(self.call("/tok/x")["status"], 429)

    def test_invalid_cost_reload_keeps_the_previous_config_and_bucket(self):
        self.assertEqual(self.call("/tok/x")["status"], 200)  # 3 tokens spent
        doc = cost_document()
        route = next(r for r in doc["routes"] if r["id"] == "r-tok3")
        route["quota_cost"] = 2  # would fit the remaining token; make it invalid instead
        route["quota_cost"] = True
        write_config(self.path, doc)
        self.assertFalse(self.gateway.reload_config())
        self.assertFalse(self.gateway.store.ready)
        self.assertIn("quota_cost must be a positive integer",
                      self.gateway.store.last_error)
        # the old cost 3 still governs and the remaining one unit is insufficient
        response = self.call("/tok/x")
        self.assertEqual(response["status"], 429)
        route = next(r for r in self.gateway.config.routes if r.id == "r-tok3")
        self.assertEqual(route.quota_cost, 3)

    def test_in_flight_request_keeps_the_cost_it_started_with(self):
        entered = threading.Event()
        release = threading.Event()

        def hold(request):
            entered.set()
            release.wait(5)
            return {"status": 200, "body": {"ok": True}}

        self.gateway.upstreams.register("hold", hold)
        doc = cost_document()
        # generous bucket so the concurrent in-progress 425 (billed after the
        # reload) cannot be throttled by quota itself
        doc["quota_policies"] = [
            {"id": "p-wide", "tenant": "*", "algorithm": "token-bucket",
             "limit": 1000, "window_ms": 60000, "burst": 1000, "partition_by": "tenant"}]
        doc["routes"] = [
            {"id": "r-hold", "tenant": "*",
             "match": {"method": "POST", "path_prefix": "/hold"},
             "upstream": "hold", "auth_required": False,
             "quota_policy": "p-wide", "quota_cost": 2}]
        write_config(self.path, doc)
        self.assertTrue(self.gateway.reload_config())
        result = {}

        def worker():
            result["response"] = self.gateway.handle(
                "acme", "POST", "/hold/x",
                {"x-tenant": "acme", "x-idempotency-key": "fly-1",
                 "x-request-id": "fly-1"}, "{}")

        thread = threading.Thread(target=worker)
        thread.start()
        self.assertTrue(entered.wait(5))
        # swap the cost while the request is inside the upstream call
        doc["routes"][0]["quota_cost"] = 5
        write_config(self.path, doc)
        self.assertTrue(self.gateway.reload_config())
        # a concurrent same-body request reaches idempotency *after* quota and so
        # bills at the new cost (425 in progress), proving new requests use 5
        concurrent = self.gateway.handle(
            "acme", "POST", "/hold/x",
            {"x-tenant": "acme", "x-idempotency-key": "fly-1",
             "x-request-id": "fly-2"}, "{}")
        self.assertEqual(concurrent["status"], 425)
        release.set()
        thread.join(5)
        self.assertEqual(result["response"]["status"], 200)
        costs = sorted((r["cost"], r["allowed"])
                       for r in self.gateway.ledger.entries("acme"))
        self.assertEqual(costs, [(2, True), (5, True)])
        entries = {e["request_id"]: e for e in self.gateway.audit("acme", 2)}
        self.assertEqual(entries["fly-1"]["quota"]["cost"], 2)
        self.assertEqual(entries["fly-2"]["quota"]["cost"], 5)


class QuotaCostHttpTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-cost-http-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.config_path = os.path.join(self.root, "config.json")
        write_config(self.config_path, cost_document())
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

    def request(self, method, path, body=None, headers=None):
        data = body.encode("utf-8") if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, dict(response.headers), json.loads(
                    response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers or {}), json.loads(
                exc.read().decode("utf-8"))

    def test_proxy_bills_the_route_cost(self):
        status, _, _ = self.request("GET", "/gw/tok/x?tenant=acme")
        self.assertEqual(status, 200)
        status, _, usage = self.request("GET", "/v1/quota/usage?tenant=acme")
        self.assertEqual(status, 200)
        self.assertEqual((usage["requests"], usage["cost"], usage["allowed_cost"]),
                         (1, 3, 3))

    def test_invalid_cost_reload_reports_the_existing_feedback_shape(self):
        doc = cost_document()
        doc["routes"][0]["quota_cost"] = False
        write_config(self.config_path, doc)
        # bump mtime past the just-written file so the running store sees it
        time.sleep(0.01)
        stat = os.stat(self.config_path)
        os.utime(self.config_path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 2_000_000))
        status, _, payload = self.request("POST", "/v1/config/reload", "{}",
                                          {"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        self.assertEqual(payload["reloaded"], False)
        self.assertEqual(payload["ready"], False)
        self.assertIn("quota_cost must be a positive integer", payload["error"])


if __name__ == "__main__":
    unittest.main()
