"""End to end tests against a real ThreadingHTTPServer on an ephemeral port."""

import hashlib
import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from gwd.gateway import Gateway
from gwd.http_app import create_server

SECRET = "http-secret"
SECRET_2 = "http-secret-2"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def config_document():
    return {
        "quota_policies": [{"id": "p-http", "tenant": "acme", "algorithm": "sliding-window",
                            "limit": 2, "window_ms": 60000}],
        "keys": [{"key_id": "k-http", "tenant": "acme", "secret_sha256": sha(SECRET),
                  "scopes": ["read"]}],
        "routes": [
            {"id": "r-http", "tenant": "acme", "match": {"method": "GET", "path_prefix": "/api"},
             "upstream": "echo", "quota_policy": "p-http", "scopes": ["read"],
             "transform": {"response_headers": {"X-Served-By": "gwd"}}},
            {"id": "r-post", "tenant": "acme", "match": {"method": "POST", "path_prefix": "/api"},
             "upstream": "echo", "auth_required": False}],
    }


class HttpTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-http-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.config_path = os.path.join(self.root, "config.json")
        with open(self.config_path, "w", encoding="utf-8") as handle:
            json.dump(config_document(), handle)
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
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method,
                                         headers=headers or {})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, dict(response.headers), response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers or {}), exc.read().decode("utf-8")

    def json_request(self, method, path, body=None, headers=None):
        status, response_headers, text = self.request(method, path, body, headers)
        return status, response_headers, json.loads(text)

    def test_healthz(self):
        status, _, payload = self.json_request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["routes"], 2)
        self.assertGreaterEqual(payload["upstreams"], 1)

    def test_config_endpoints(self):
        status, _, payload = self.json_request("GET", "/v1/config")
        self.assertEqual(status, 200)
        self.assertNotIn("secret_sha256", json.dumps(payload))
        status, _, payload = self.json_request("POST", "/v1/config/reload")
        self.assertEqual(status, 200)
        self.assertFalse(payload["reloaded"])  # mtime unchanged
        self.assertEqual(payload["revision"], 1)
        with open(self.config_path, "w", encoding="utf-8") as handle:
            json.dump(config_document(), handle)
        stat = os.stat(self.config_path)
        os.utime(self.config_path, ns=(stat.st_atime_ns + 1_000_000,
                                       stat.st_mtime_ns + 1_000_000))
        status, _, payload = self.json_request("POST", "/v1/config/reload")
        self.assertTrue(payload["reloaded"])
        self.assertEqual(payload["revision"], 2)

    def test_key_creation_returns_the_secret_once(self):
        status, _, payload = self.json_request("POST", "/v1/keys",
                                               {"tenant": "acme", "scopes": ["read"]})
        self.assertEqual(status, 201)
        self.assertIn("secret", payload)
        self.assertEqual(payload["secret_sha256"], sha(payload["secret"]))
        self.assertTrue(payload["enabled"])
        self.assertIsNone(payload["expires_at_ms"])
        status, _, reply = self.json_request("GET", "/api/items",
                                             headers={"authorization": "Bearer " + payload["secret"]})
        self.assertEqual(status, 200)
        self.assertEqual(reply["path"], "/api/items")

    def test_key_creation_with_validity_fields_and_validation(self):
        status, _, payload = self.json_request(
            "POST", "/v1/keys",
            {"tenant": "acme", "scopes": ["read"], "enabled": False, "expires_at_ms": 1000})
        self.assertEqual(status, 201)
        self.assertFalse(payload["enabled"])
        self.assertEqual(payload["expires_at_ms"], 1000)
        status, _, config = self.json_request("GET", "/v1/config")
        created = {k["key_id"]: k for k in config["keys"]}[payload["key_id"]]
        self.assertFalse(created["enabled"])
        self.assertEqual(created["expires_at_ms"], 1000)
        self.assertNotIn("secret_sha256", json.dumps(created))
        # the disabled key is rejected by the proxy surface
        status, _, reply = self.json_request(
            "GET", "/api/items", headers={"authorization": "Bearer " + payload["secret"]})
        self.assertEqual(status, 401)
        self.assertEqual(reply["error"], "api key disabled")
        self.assertIn("request_id", reply)
        # invalid field values are 400 and change nothing
        revision = self.gateway.store.revision
        for bad in ({"enabled": "yes"}, {"enabled": None}, {"expires_at_ms": True},
                    {"expires_at_ms": 0}, {"expires_at_ms": -1}, {"expires_at_ms": "1000"}):
            body = {"tenant": "acme"}
            body.update(bad)
            status, _, reply = self.json_request("POST", "/v1/keys", body)
            self.assertEqual(status, 400, bad)
            self.assertIn("request_id", reply)
        self.assertEqual(self.gateway.store.revision, revision)
        status, _, config = self.json_request("GET", "/v1/config")
        self.assertEqual(len(config["keys"]), 2)  # k-http plus the disabled one

    def test_quota_policy_creation_through_http(self):
        policy = {"id": "p-new", "tenant": "acme", "algorithm": "leaky-bucket",
                  "limit": 5, "window_ms": 1000}
        status, _, payload = self.json_request("POST", "/v1/quota/policies", policy)
        self.assertEqual(status, 201)
        self.assertEqual(payload["algorithm"], "leaky-bucket")
        self.assertEqual(payload["partition_by"], "policy")  # omitted defaults to policy
        status, _, payload = self.json_request("GET", "/v1/quota/usage?tenant=acme")
        self.assertEqual(status, 200)
        self.assertEqual(payload["tenant"], "acme")

    def test_partition_policy_create_echo_config_and_400(self):
        policy = {"id": "p-tenant", "tenant": "*", "algorithm": "sliding-window",
                  "limit": 3, "window_ms": 1000, "partition_by": "tenant"}
        status, _, payload = self.json_request("POST", "/v1/quota/policies", policy)
        self.assertEqual(status, 201)
        self.assertEqual(payload["partition_by"], "tenant")
        status, _, config = self.json_request("GET", "/v1/config")
        created = {p["id"]: p for p in config["quota_policies"]}
        self.assertEqual(created["p-tenant"]["partition_by"], "tenant")
        for bad in (None, "", "route", 7):
            status, _, reply = self.json_request(
                "POST", "/v1/quota/policies",
                {"id": "p-bad-%s" % str(bad), "algorithm": "token-bucket",
                 "limit": 1, "window_ms": 1, "partition_by": bad})
            self.assertEqual(status, 400, bad)
            self.assertIn("request_id", reply)
        # the failed creates must not have changed the configuration
        status, _, config = self.json_request("GET", "/v1/config")
        ids = {p["id"] for p in config["quota_policies"]}
        self.assertNotIn("p-bad-None", ids)
        self.assertIn("p-tenant", ids)

    def test_proxy_success_error_and_quota(self):
        authorization = {"authorization": "Bearer " + SECRET}
        status, headers, payload = self.json_request("GET", "/api/items", headers=authorization)
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Served-By"], "gwd")
        self.assertEqual(payload["path"], "/api/items")
        status, _, payload = self.json_request("GET", "/api/items")
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "missing api key")
        self.assertIn("request_id", payload)
        status, _, payload = self.json_request("GET", "/api/items",
                                               headers={"authorization": "Bearer wrong"})
        self.assertEqual(status, 401)
        self.assertEqual(self.json_request("GET", "/api/items", headers=authorization)[0], 200)
        status, _, payload = self.json_request("GET", "/api/items", headers=authorization)
        self.assertEqual(status, 429)
        self.assertEqual(payload["policy_id"], "p-http")
        self.assertIn("reset_at_ms", payload)

    def test_gw_prefix_is_stripped_before_matching(self):
        status, _, payload = self.json_request("GET", "/gw/api/items",
                                               headers={"authorization": "Bearer " + SECRET})
        self.assertEqual(status, 200)
        self.assertEqual(payload["path"], "/api/items")

    def test_audit_endpoint_reports_entries(self):
        self.json_request("GET", "/api/items", headers={"authorization": "Bearer " + SECRET})
        self.json_request("GET", "/api/items")
        status, _, payload = self.json_request("GET", "/v1/audit?tenant=acme&limit=10")
        self.assertEqual(status, 200)
        self.assertEqual(payload["count"], 1)  # the 401 has no tenant to attribute
        self.assertEqual(payload["entries"][0]["status"], 200)
        self.assertEqual(payload["entries"][0]["route_id"], "r-http")
        status, _, payload = self.json_request("GET", "/v1/audit?limit=10")
        self.assertEqual([entry["status"] for entry in payload["entries"]], [200, 401])

    def test_idempotent_replay_over_http(self):
        headers = {"x-idempotency-key": "http-idem"}
        first = self.json_request("POST", "/api/things", {"a": 1}, headers)
        second = self.json_request("POST", "/api/things", {"a": 1}, headers)
        self.assertEqual((first[0], second[0]), (200, 200))
        self.assertEqual(second[1]["X-Idempotent-Replay"], "true")
        self.assertEqual(first[2]["body_sha256"], second[2]["body_sha256"])
        status, _, payload = self.json_request("POST", "/api/things", {"a": 2}, headers)
        self.assertEqual(status, 409)

    def test_breaker_reset_endpoint(self):
        self.gateway.breakers.get("echo").allow(0)
        self.gateway.breakers.get("echo").record(False, 0)
        status, _, payload = self.json_request("POST", "/v1/breaker/reset", {"upstream": "echo"})
        self.assertEqual(status, 200)
        self.assertEqual(payload["reset"], ["echo"])

    def test_unknown_admin_route_falls_through_to_the_proxy(self):
        status, _, payload = self.json_request("GET", "/v1/does-not-exist")
        self.assertEqual(status, 404)
        self.assertIn("no route", payload["error"])


def joint_config_document():
    return {
        "quota_policies": [
            {"id": "p-total", "tenant": "*", "algorithm": "sliding-window",
             "limit": 3, "window_ms": 60000, "partition_by": "tenant"},
            {"id": "p-key", "tenant": "*", "algorithm": "token-bucket",
             "limit": 2, "window_ms": 60000, "burst": 2, "partition_by": "key"}],
        "keys": [
            {"key_id": "k-http", "tenant": "acme", "secret_sha256": sha(SECRET),
             "scopes": ["read"]},
            {"key_id": "k-http2", "tenant": "acme", "secret_sha256": sha(SECRET_2),
             "scopes": ["read"]}],
        "routes": [
            {"id": "r-joint", "tenant": "acme", "match": {"method": "GET", "path_prefix": "/joint"},
             "upstream": "echo", "scopes": ["read"],
             "quota_policies": ["p-total", "p-key"]}],
    }


class JointQuotaHttpTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-http-joint-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.config_path = os.path.join(self.root, "config.json")
        with open(self.config_path, "w", encoding="utf-8") as handle:
            json.dump(joint_config_document(), handle)
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
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method,
                                         headers=headers or {})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, dict(response.headers), response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers or {}), exc.read().decode("utf-8")

    def json_request(self, method, path, body=None, headers=None):
        status, response_headers, text = self.request(method, path, body, headers)
        return status, response_headers, json.loads(text)

    def test_joint_admission_ledger_and_audit_over_http(self):
        auth = {"authorization": "Bearer " + SECRET}
        for _ in range(2):
            status, _, _ = self.json_request("GET", "/joint/x", headers=auth)
            self.assertEqual(status, 200)
        status, headers, payload = self.json_request("GET", "/joint/x", headers=auth)
        self.assertEqual(status, 429)
        self.assertEqual(payload["policy_id"], "p-key")  # tighter key budget first
        self.assertEqual(headers["Retry-After"], "30")
        # six usage records: two checks x two policies, all admitted so far for
        # the 429 pair; verify the aggregate
        status, _, usage = self.json_request("GET", "/v1/quota/usage?tenant=acme")
        self.assertEqual(status, 200)
        self.assertEqual(usage["requests"], 6)
        self.assertEqual(usage["allowed"], 4)
        self.assertEqual(usage["rejected"], 2)
        self.assertEqual(usage["allowed_cost"], 4)
        status, _, audit = self.json_request("GET", "/v1/audit?tenant=acme&limit=1")
        entry = audit["entries"][0]
        self.assertEqual([q["policy_id"] for q in entry["quotas"]], ["p-total", "p-key"])
        self.assertEqual(entry["quota"]["policy_id"], "p-total")
        self.assertFalse(entry["quota"]["allowed"])

    def test_tenant_total_is_shared_across_keys(self):
        first = {"authorization": "Bearer " + SECRET}
        second = {"authorization": "Bearer " + SECRET_2}
        for headers in (first, second, first):
            status, _, _ = self.json_request("GET", "/joint/x", headers=headers)
            self.assertEqual(status, 200)
        # tenant total (3) exhausted for the second key even though its key
        # partition (2) still has room
        status, _, payload = self.json_request("GET", "/joint/x", headers=second)
        self.assertEqual(status, 429)
        self.assertEqual(payload["policy_id"], "p-total")

    def test_key_partition_needs_a_valid_key_and_config_echoes_the_field(self):
        status, _, payload = self.json_request("GET", "/joint/x?tenant=acme")
        self.assertEqual(status, 401)
        self.assertIn("request_id", payload)
        status, _, config = self.json_request("GET", "/v1/config")
        route = {r["id"]: r for r in config["routes"]}["r-joint"]
        self.assertEqual(route["quota_policies"], ["p-total", "p-key"])


if __name__ == "__main__":
    unittest.main()
