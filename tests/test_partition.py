"""Partitioned quota tests: partition_by policy/tenant/key end to end."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from gwd.config import GatewayError, load
from gwd.gateway import Gateway
from gwd.http_app import create_server
from gwd.limits import Limiter

SECRET_A1 = "a1-secret"
SECRET_A2 = "a2-secret"
SECRET_B1 = "b1-secret"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def auth(secret, key_id=None):
    headers = {"authorization": "Bearer " + secret}
    if key_id:
        headers["x-api-key"] = key_id
    return headers


def document():
    return {
        "quota_policies": [
            {"id": "p-tenant", "tenant": "*", "algorithm": "token-bucket",
             "limit": 2, "window_ms": 60000, "partition_by": "tenant"},
            {"id": "p-key", "tenant": "*", "algorithm": "token-bucket",
             "limit": 2, "window_ms": 60000, "partition_by": "key"},
        ],
        "keys": [
            {"key_id": "k-a1", "tenant": "acme", "secret_sha256": sha(SECRET_A1), "scopes": []},
            {"key_id": "k-a2", "tenant": "acme", "secret_sha256": sha(SECRET_A2), "scopes": []},
            {"key_id": "k-b1", "tenant": "globex", "secret_sha256": sha(SECRET_B1), "scopes": []},
        ],
        "routes": [
            {"id": "r-tenant", "tenant": "*", "match": {"method": "GET", "path_prefix": "/t"},
             "upstream": "echo", "auth_required": False, "quota_policy": "p-tenant"},
            {"id": "r-key", "tenant": "*", "match": {"method": "GET", "path_prefix": "/k"},
             "upstream": "echo", "auth_required": False, "quota_policy": "p-key"},
            {"id": "r-key2", "tenant": "*", "match": {"method": "GET", "path_prefix": "/k2"},
             "upstream": "echo", "auth_required": False, "quota_policy": "p-key"},
        ],
    }


def write_config(path, doc):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle)
    stat = os.stat(path)
    os.utime(path, ns=(stat.st_atime_ns + 1_000_000, stat.st_mtime_ns + 1_000_000))


def read_config(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


class PartitionTestCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-partition-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = os.path.join(self.root, "config.json")
        write_config(self.path, document())
        self.gateway = Gateway(config_path=self.path, data_dir=os.path.join(self.root, "data"))
        self.calls = []

        def counting(request):
            self.calls.append(request)
            return {"status": 200, "body": {"ok": True}}

        self.gateway.upstreams.register("echo", counting)

    def body_of(self, response):
        return json.loads(response["body"])

    def statuses(self, tenant, path, headers, count, now_ms=0):
        return [self.gateway.handle(tenant, "GET", path, headers, "", now_ms=now_ms)["status"]
                for _ in range(count)]


class LimiterPartitionTest(unittest.TestCase):
    def test_every_algorithm_partitions_independently(self):
        for algorithm in ("token-bucket", "leaky-bucket", "sliding-window"):
            limiter = Limiter([{"id": "p", "algorithm": algorithm, "limit": 1,
                                "window_ms": 1000, "partition_by": "tenant"}])
            self.assertTrue(limiter.allow("p", 1, 0, partition="acme")["allowed"], algorithm)
            self.assertFalse(limiter.allow("p", 1, 0, partition="acme")["allowed"], algorithm)
            # another partition starts from the initial state with its own budget
            self.assertTrue(limiter.allow("p", 1, 0, partition="globex")["allowed"], algorithm)
            # the default (policy mode) partition is independent too
            self.assertTrue(limiter.allow("p", 1, 0)["allowed"], algorithm)


class TenantPartitionTest(PartitionTestCase):
    def test_same_tenant_shares_one_bucket_across_keys(self):
        self.assertEqual(self.gateway.handle("", "GET", "/t/x", auth(SECRET_A1), "",
                                             now_ms=0)["status"], 200)
        self.assertEqual(self.gateway.handle("", "GET", "/t/x", auth(SECRET_A2), "",
                                             now_ms=0)["status"], 200)
        # both keys belong to acme: the shared tenant bucket is now exhausted
        response = self.gateway.handle("", "GET", "/t/x", auth(SECRET_A1), "", now_ms=0)
        self.assertEqual(response["status"], 429)
        self.assertEqual(self.body_of(response)["policy_id"], "p-tenant")

    def test_different_tenants_do_not_consume_each_other(self):
        self.assertEqual(self.statuses("", "/t/x", auth(SECRET_A1), 2), [200, 200])
        self.assertEqual(self.statuses("", "/t/x", auth(SECRET_A1), 1), [429])
        self.assertEqual(self.statuses("", "/t/x", auth(SECRET_B1), 2), [200, 200])

    def test_anonymous_requests_use_the_request_tenant(self):
        self.assertEqual(self.statuses("acme", "/t/x", {}, 2), [200, 200])
        self.assertEqual(self.statuses("acme", "/t/x", {}, 1), [429])
        self.assertEqual(self.statuses("globex", "/t/x", {}, 1), [200])

    def test_anonymous_request_without_a_tenant_is_400(self):
        response = self.gateway.handle("", "GET", "/t/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 400)
        payload = self.body_of(response)
        self.assertIn("error", payload)
        self.assertEqual(payload["request_id"], response["request_id"])
        self.assertEqual(self.calls, [])                       # no upstream call
        self.assertEqual(self.gateway.usage()["requests"], 0)  # no usage written
        entries = self.gateway.audit(limit=5)
        self.assertEqual(len(entries), 1)                      # still audited
        self.assertEqual(entries[0]["status"], 400)

    def test_valid_key_with_a_conflicting_request_tenant_is_403(self):
        response = self.gateway.handle("globex", "GET", "/t/x", auth(SECRET_A1), "", now_ms=0)
        self.assertEqual(response["status"], 403)
        self.assertIn("error", self.body_of(response))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.gateway.usage()["requests"], 0)
        # the denied attempt did not spend anything: acme still has its full quota
        self.assertEqual(self.statuses("", "/t/x", auth(SECRET_A1), 2), [200, 200])


class KeyPartitionTest(PartitionTestCase):
    def test_each_key_gets_its_own_bucket(self):
        self.assertEqual(self.statuses("", "/k/x", auth(SECRET_A1), 2), [200, 200])
        self.assertEqual(self.statuses("", "/k/x", auth(SECRET_A1), 1), [429])
        self.assertEqual(self.statuses("", "/k/x", auth(SECRET_A2), 2), [200, 200])

    def test_one_key_shares_its_bucket_across_routes(self):
        self.assertEqual(self.gateway.handle("", "GET", "/k/x", auth(SECRET_A1), "",
                                             now_ms=0)["status"], 200)
        self.assertEqual(self.gateway.handle("", "GET", "/k2/x", auth(SECRET_A1), "",
                                             now_ms=0)["status"], 200)
        self.assertEqual(self.gateway.handle("", "GET", "/k2/x", auth(SECRET_A1), "",
                                             now_ms=0)["status"], 429)

    def test_missing_key_is_401_even_on_an_anonymous_route(self):
        response = self.gateway.handle("acme", "GET", "/k/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 401)
        self.assertEqual(self.body_of(response)["error"], "missing api key")

    def test_unknown_secret_is_401_even_on_an_anonymous_route(self):
        response = self.gateway.handle("acme", "GET", "/k/x", auth("nope"), "", now_ms=0)
        self.assertEqual(response["status"], 401)
        self.assertEqual(self.body_of(response)["error"], "unknown api key")

    def test_mismatched_key_id_is_401_even_on_an_anonymous_route(self):
        response = self.gateway.handle("acme", "GET", "/k/x",
                                       auth(SECRET_A1, key_id="k-a2"), "", now_ms=0)
        self.assertEqual(response["status"], 401)

    def test_key_denials_cost_nothing_and_are_audited(self):
        self.gateway.handle("acme", "GET", "/k/x", {}, "", now_ms=0)
        self.gateway.handle("acme", "GET", "/k/x", auth("nope"), "", now_ms=0)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.gateway.usage()["requests"], 0)
        self.assertEqual([e["status"] for e in self.gateway.audit(limit=5)], [401, 401])
        # the real key still owns a full bucket
        self.assertEqual(self.statuses("", "/k/x", auth(SECRET_A1), 2), [200, 200])

    def test_valid_key_with_a_conflicting_request_tenant_is_403(self):
        response = self.gateway.handle("globex", "GET", "/k/x", auth(SECRET_A1), "", now_ms=0)
        self.assertEqual(response["status"], 403)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.gateway.usage()["requests"], 0)


class ValidationTest(PartitionTestCase):
    def test_invalid_partition_by_values_are_rejected_on_load(self):
        for bad in (None, "", "tenants", 5, ["tenant"], {"mode": "tenant"}):
            doc = document()
            doc["quota_policies"][0]["partition_by"] = bad
            write_config(self.path, doc)
            with self.assertRaises(GatewayError, msg=repr(bad)):
                load(self.path)

    def test_omitted_partition_by_defaults_to_policy(self):
        doc = document()
        for policy in doc["quota_policies"]:
            policy.pop("partition_by")
        write_config(self.path, doc)
        config = load(self.path)
        self.assertEqual([p.partition_by for p in config.policies], ["policy", "policy"])
        self.assertEqual(config.policies[0].to_dict()["partition_by"], "policy")

    def test_add_policy_accepts_and_reports_the_mode(self):
        created = self.gateway.add_policy({"id": "p-new", "algorithm": "leaky-bucket",
                                           "limit": 5, "window_ms": 1000,
                                           "partition_by": "tenant"})
        self.assertEqual(created["partition_by"], "tenant")
        sanitized = self.gateway.sanitized_config()
        modes = {p["id"]: p["partition_by"] for p in sanitized["quota_policies"]}
        self.assertEqual(modes["p-new"], "tenant")
        self.assertEqual(modes["p-tenant"], "tenant")
        self.assertEqual(modes["p-key"], "key")

    def test_add_policy_with_a_bad_mode_fails_without_changing_anything(self):
        before = read_config(self.path)
        with self.assertRaises(GatewayError) as caught:
            self.gateway.add_policy({"id": "p-bad", "algorithm": "token-bucket",
                                     "limit": 1, "window_ms": 1000, "partition_by": "nope"})
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(read_config(self.path), before)
        self.assertNotIn("p-bad", [p.id for p in self.gateway.config.policies])

    def test_cli_quota_set_rejects_a_bad_mode_in_the_standard_format(self):
        bad = os.path.join(self.root, "bad.json")
        with open(bad, "w", encoding="utf-8") as handle:
            json.dump({"id": "p-cli", "algorithm": "token-bucket", "limit": 1,
                       "window_ms": 1000, "partition_by": None}, handle)
        before = read_config(self.path)
        result = subprocess.run(
            [sys.executable, "-m", "gwd", "--data-dir", os.path.join(self.root, "data"),
             "quota-set", "--file", bad, "--config", self.path],
            capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("partition_by", json.loads(result.stderr)["error"])
        self.assertEqual(read_config(self.path), before)


class ReloadTest(PartitionTestCase):
    def reload_with(self, mutate):
        doc = document()
        mutate(doc)
        write_config(self.path, doc)
        return self.gateway.reload_config()

    def test_unchanged_policy_keeps_its_partition_state(self):
        self.assertEqual(self.statuses("", "/t/x", auth(SECRET_A1), 1), [200])
        self.assertTrue(self.reload_with(lambda doc: None))
        self.assertEqual(self.statuses("", "/t/x", auth(SECRET_A1), 1), [200])
        self.assertEqual(self.statuses("", "/t/x", auth(SECRET_A1), 1), [429])

    def test_changed_algorithm_parameters_reset_only_that_policy(self):
        self.assertEqual(self.statuses("", "/t/x", auth(SECRET_A1), 2), [200, 200])
        self.assertEqual(self.statuses("", "/k/x", auth(SECRET_A1), 2), [200, 200])

        def bump(doc):
            doc["quota_policies"][0]["limit"] = 5

        self.assertTrue(self.reload_with(bump))
        # p-tenant restarts from the initial state; p-key is untouched
        self.assertEqual(self.statuses("", "/t/x", auth(SECRET_A1), 5), [200] * 5)
        self.assertEqual(self.statuses("", "/k/x", auth(SECRET_A1), 1), [429])

    def test_changed_partition_mode_resets_the_policy(self):
        self.assertEqual(self.statuses("", "/t/x", auth(SECRET_A1), 2), [200, 200])

        def repartition(doc):
            doc["quota_policies"][0]["partition_by"] = "policy"

        self.assertTrue(self.reload_with(repartition))
        self.assertEqual(self.statuses("", "/t/x", auth(SECRET_A1), 2), [200, 200])

    def test_changed_tenant_resets_the_policy(self):
        self.assertEqual(self.statuses("", "/t/x", auth(SECRET_A1), 2), [200, 200])

        def move(doc):
            doc["quota_policies"][0]["tenant"] = "acme"

        self.assertTrue(self.reload_with(move))
        self.assertEqual(self.statuses("", "/t/x", auth(SECRET_A1), 2), [200, 200])

    def test_delete_and_readd_restarts_from_the_initial_state(self):
        self.assertEqual(self.statuses("", "/t/x", auth(SECRET_A1), 2), [200, 200])

        def drop(doc):
            doc["quota_policies"] = doc["quota_policies"][1:]
            doc["routes"] = [r for r in doc["routes"] if r["id"] != "r-tenant"]

        self.assertTrue(self.reload_with(drop))
        self.assertTrue(self.reload_with(lambda doc: None))  # back to the original doc
        self.assertEqual(self.statuses("", "/t/x", auth(SECRET_A1), 2), [200, 200])

    def test_invalid_reload_keeps_the_old_config_and_quota(self):
        self.assertEqual(self.statuses("", "/t/x", auth(SECRET_A1), 1), [200])
        write_config(self.path, {"routes": [{"id": "broken"}]})
        self.assertFalse(self.gateway.reload_config())
        self.assertFalse(self.gateway.store.ready)
        self.assertIsNotNone(self.gateway.store.last_error)
        # the last good config and its partition state are still in effect
        self.assertEqual(self.statuses("", "/t/x", auth(SECRET_A1), 1), [200])
        self.assertEqual(self.statuses("", "/t/x", auth(SECRET_A1), 1), [429])


class ConcurrencyTest(PartitionTestCase):
    def test_concurrent_requests_on_one_partition_never_overspend(self):
        doc = document()
        doc["quota_policies"][0]["limit"] = 25
        write_config(self.path, doc)
        self.assertTrue(self.gateway.reload_config())

        outcomes = []
        lock = threading.Lock()

        def hammer():
            for _ in range(10):
                status = self.gateway.handle("", "GET", "/t/x", auth(SECRET_A1), "",
                                             now_ms=0)["status"]
                with lock:
                    outcomes.append(status)

        threads = [threading.Thread(target=hammer) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(outcomes), 100)
        self.assertEqual(outcomes.count(200), 25)
        self.assertEqual(outcomes.count(429), 75)


class HttpPartitionTest(PartitionTestCase):
    """The HTTP proxy surface enforces the same partition rules as handle()."""

    def setUp(self):
        super().setUp()
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
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_proxy_enforces_key_partition_rules(self):
        # anonymous on an auth_required=false route is still a 401 in key mode
        status, payload = self.request("/k/x")
        self.assertEqual(status, 401)
        self.assertIn("request_id", payload)
        # a valid key gets its own bucket; the tenant header must not conflict
        status, _ = self.request("/k/x", {"authorization": "Bearer " + SECRET_A1})
        self.assertEqual(status, 200)
        status, _ = self.request("/k/x?tenant=globex",
                                 {"authorization": "Bearer " + SECRET_A1})
        self.assertEqual(status, 403)

    def test_config_and_policy_creation_report_the_mode(self):
        req = urllib.request.Request(self.base + "/v1/quota/policies",
                                     data=json.dumps({"id": "p-http", "algorithm": "token-bucket",
                                                      "limit": 3, "window_ms": 1000,
                                                      "partition_by": "key"}).encode("utf-8"),
                                     method="POST")
        with urllib.request.urlopen(req, timeout=5) as response:
            self.assertEqual(response.status, 201)
            self.assertEqual(json.loads(response.read().decode("utf-8"))["partition_by"], "key")
        status, payload = self.request("/v1/config")
        self.assertEqual(status, 200)
        modes = {p["id"]: p["partition_by"] for p in payload["quota_policies"]}
        self.assertEqual(modes, {"p-tenant": "tenant", "p-key": "key", "p-http": "key"})

    def test_policy_creation_with_a_bad_mode_is_400(self):
        req = urllib.request.Request(self.base + "/v1/quota/policies",
                                     data=json.dumps({"id": "p-bad", "algorithm": "token-bucket",
                                                      "limit": 3, "window_ms": 1000,
                                                      "partition_by": ""}).encode("utf-8"),
                                     method="POST")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(caught.exception.code, 400)
        payload = json.loads(caught.exception.read().decode("utf-8"))
        self.assertIn("partition_by", payload["error"])
        self.assertIn("request_id", payload)
        status, config = self.request("/v1/config")
        self.assertNotIn("p-bad", [p["id"] for p in config["quota_policies"]])


if __name__ == "__main__":
    unittest.main()
