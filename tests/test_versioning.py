"""API version governance: config validation, version filtering, 406, headers."""

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

SECRET = "version-secret"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def document():
    return {
        "quota_policies": [
            {"id": "p-ver", "tenant": "acme", "algorithm": "token-bucket",
             "limit": 3, "window_ms": 60000, "burst": 3}],
        "keys": [{"key_id": "k-ver", "tenant": "acme", "secret_sha256": sha(SECRET),
                  "scopes": ["read"]}],
        "routes": [
            {"id": "r-legacy", "tenant": "acme",
             "match": {"method": "GET", "path_prefix": "/api"},
             "upstream": "echo", "quota_policy": "p-ver", "scopes": ["read"]},
            {"id": "r-v1", "tenant": "acme", "version": "v1",
             "match": {"method": "GET", "path_prefix": "/api"},
             "upstream": "echo", "auth_required": False,
             "transform": {"response_headers": {"X-Api-Version": "transform-wrong",
                                                "X-Served-By": "gwd"}}},
            {"id": "r-v2", "tenant": "acme", "version": "v2",
             "match": {"method": "GET", "path_prefix": "/api"},
             "upstream": "echo", "auth_required": False}],
    }


def write_config(path, doc):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle)
    stat = os.stat(path)
    os.utime(path, ns=(stat.st_atime_ns + 1_000_000, stat.st_mtime_ns + 1_000_000))


def make_gateway(doc=None, **kwargs):
    root = tempfile.mkdtemp(prefix="gwd-version-")
    path = os.path.join(root, "config.json")
    write_config(path, document() if doc is None else doc)
    gateway = Gateway(config_path=path, data_dir=os.path.join(root, "data"), **kwargs)
    return gateway, root, path


class VersionConfigTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-version-cfg-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = os.path.join(self.root, "config.json")

    def load_doc(self, route_patch):
        doc = document()
        doc["routes"][1].update(route_patch)
        write_config(self.path, doc)
        return load(self.path)

    def test_valid_version_accepted(self):
        config = self.load_doc({"version": "v9"})
        self.assertEqual(config.routes[1].version, "v9")

    def test_omitted_version_means_unversioned(self):
        doc = document()
        del doc["routes"][1]["version"]
        write_config(self.path, doc)
        config = load(self.path)
        self.assertIsNone(config.routes[1].version)

    def test_null_version_rejected(self):
        with self.assertRaises(GatewayError):
            self.load_doc({"version": None})

    def test_empty_version_rejected(self):
        with self.assertRaises(GatewayError):
            self.load_doc({"version": ""})

    def test_non_string_version_rejected(self):
        for bad in (1, 1.5, True, ["v1"], {"v": 1}):
            with self.assertRaises(GatewayError, msg=repr(bad)):
                self.load_doc({"version": bad})

    def test_route_add_rejects_bad_version(self):
        write_config(self.path, document())
        gateway = Gateway(config_path=self.path, data_dir=os.path.join(self.root, "data"))
        route = {"id": "r-new", "match": {"method": "GET", "path_prefix": "/new"},
                 "upstream": "echo", "version": ""}
        with self.assertRaises(GatewayError):
            gateway.add_route(route)
        with open(self.path, "r", encoding="utf-8") as handle:
            self.assertNotIn("r-new", handle.read())

    def test_route_add_accepts_version_and_sanitized_echoes_it(self):
        write_config(self.path, document())
        gateway = Gateway(config_path=self.path, data_dir=os.path.join(self.root, "data"))
        out = gateway.add_route({"id": "r-new", "version": "v3",
                                 "match": {"method": "GET", "path_prefix": "/new"},
                                 "upstream": "echo"})
        self.assertEqual(out["version"], "v3")
        routes = {r["id"]: r for r in gateway.sanitized_config()["routes"]}
        self.assertEqual(routes["r-new"]["version"], "v3")
        self.assertEqual(routes["r-v1"]["version"], "v1")
        self.assertNotIn("version", routes["r-legacy"])


class VersionRoutingTest(unittest.TestCase):
    def setUp(self):
        self.gateway, self.root, self.path = make_gateway()
        self.addCleanup(shutil.rmtree, self.root, True)

    def auth(self):
        return {"authorization": "Bearer " + SECRET}

    def body_of(self, response):
        return json.loads(response["body"])

    def test_no_header_selects_unversioned_route(self):
        response = self.gateway.handle("acme", "GET", "/api/x", self.auth())
        self.assertEqual(response["status"], 200)
        self.assertEqual(response["route_id"], "r-legacy")
        self.assertNotIn("X-Api-Version", response["headers"])

    def test_blank_header_selects_unversioned_route(self):
        headers = self.auth()
        headers["X-Api-Version"] = "   "
        response = self.gateway.handle("acme", "GET", "/api/x", headers)
        self.assertEqual(response["status"], 200)
        self.assertEqual(response["route_id"], "r-legacy")

    def test_exact_version_selects_versioned_route(self):
        response = self.gateway.handle("acme", "GET", "/api/x",
                                       {"X-Api-Version": "v2"})
        self.assertEqual(response["status"], 200)
        self.assertEqual(response["route_id"], "r-v2")
        self.assertEqual(response["headers"]["X-Api-Version"], "v2")

    def test_header_whitespace_is_trimmed(self):
        response = self.gateway.handle("acme", "GET", "/api/x",
                                       {"X-Api-Version": "  v1 "})
        self.assertEqual(response["status"], 200)
        self.assertEqual(response["route_id"], "r-v1")

    def test_version_header_overrides_transform_response_header(self):
        response = self.gateway.handle("acme", "GET", "/api/x",
                                       {"X-Api-Version": "v1"})
        self.assertEqual(response["headers"]["X-Api-Version"], "v1")
        self.assertEqual(response["headers"]["X-Served-By"], "gwd")

    def test_version_match_is_case_sensitive(self):
        response = self.gateway.handle("acme", "GET", "/api/x",
                                       {"X-Api-Version": "V1"})
        self.assertEqual(response["status"], 406)

    def test_unversioned_route_is_not_a_fallback(self):
        doc = document()
        doc["routes"] = [r for r in doc["routes"] if r["id"] != "r-v2"]
        gateway, root, _ = make_gateway(doc)
        self.addCleanup(shutil.rmtree, root, True)
        response = gateway.handle("acme", "GET", "/api/x", {"X-Api-Version": "v2"})
        self.assertEqual(response["status"], 406)

    def test_406_payload_shape(self):
        response = self.gateway.handle("acme", "GET", "/api/x",
                                       {"X-Api-Version": "v9"})
        self.assertEqual(response["status"], 406)
        payload = self.body_of(response)
        self.assertEqual(payload["error"], "unsupported api version")
        self.assertEqual(payload["requested_version"], "v9")
        self.assertEqual(payload["supported_versions"], ["v1", "v2"])
        self.assertEqual(payload["request_id"], response["request_id"])

    def test_406_requested_version_null_when_not_provided(self):
        doc = document()
        doc["routes"] = [r for r in doc["routes"] if r["id"] != "r-legacy"]
        gateway, root, _ = make_gateway(doc)
        self.addCleanup(shutil.rmtree, root, True)
        response = gateway.handle("acme", "GET", "/api/x", self.auth())
        self.assertEqual(response["status"], 406)
        payload = self.body_of(response)
        self.assertIsNone(payload["requested_version"])
        self.assertEqual(payload["supported_versions"], ["v1", "v2"])

    def test_404_when_no_method_path_tenant_candidate(self):
        response = self.gateway.handle("acme", "DELETE", "/nope", self.auth())
        self.assertEqual(response["status"], 404)

    def test_406_skips_auth_quota_idempotency_and_upstream(self):
        calls = []

        def counting(request):
            calls.append(request)
            return {"status": 200, "body": "ok"}

        self.gateway.upstreams.register("echo", counting)
        headers = {"X-Api-Version": "v9", "X-Idempotency-Key": "idem-1"}
        response = self.gateway.handle("acme", "GET", "/api/x", headers)
        self.assertEqual(response["status"], 406)
        # No upstream call, no quota consumption, no idempotency occupancy.
        self.assertEqual(calls, [])
        usage = self.gateway.usage("acme")
        self.assertEqual(usage["requests"], 0)
        self.assertEqual(self.gateway._idempotency, {})
        # Exactly one audit record with attempts 0 and route_id null.
        entries = self.gateway.audit()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["attempts"], 0)
        self.assertIsNone(entries[0]["route_id"])
        self.assertEqual(entries[0]["status"], 406)

    def test_406_happens_before_authentication(self):
        # An invalid key still gets 406, not 401, when the version matches nothing.
        headers = {"authorization": "Bearer wrong", "X-Api-Version": "v9"}
        response = self.gateway.handle("acme", "GET", "/api/x", headers)
        self.assertEqual(response["status"], 406)


class VersionReloadTest(unittest.TestCase):
    def setUp(self):
        self.gateway, self.root, self.path = make_gateway()
        self.addCleanup(shutil.rmtree, self.root, True)

    def auth(self):
        return {"authorization": "Bearer " + SECRET}

    def test_invalid_version_reload_keeps_previous_config(self):
        before = self.gateway.store.revision
        doc = document()
        doc["routes"][1]["version"] = ""
        write_config(self.path, doc)
        self.assertFalse(self.gateway.reload_config())
        self.assertFalse(self.gateway.store.ready)
        self.assertIn("version", self.gateway.store.last_error)
        self.assertEqual(self.gateway.store.revision, before)
        # The previous config still serves both legacy and versioned routes.
        self.assertEqual(self.gateway.handle("acme", "GET", "/api/x", self.auth())["status"], 200)
        self.assertEqual(
            self.gateway.handle("acme", "GET", "/api/x", {"X-Api-Version": "v1"})["route_id"],
            "r-v1")

    def test_valid_reload_applies_to_new_requests_and_keeps_state(self):
        # Drain part of the legacy route's bucket so bucket preservation is visible.
        self.assertEqual(self.gateway.handle("acme", "GET", "/api/x", self.auth())["status"], 200)
        doc = document()
        doc["routes"][2]["version"] = "v2.1"
        write_config(self.path, doc)
        self.assertTrue(self.gateway.reload_config())
        self.assertTrue(self.gateway.store.ready)
        self.assertIsNone(self.gateway.store.last_error)
        # New version string applies; the old one no longer matches.
        response = self.gateway.handle("acme", "GET", "/api/x", {"X-Api-Version": "v2.1"})
        self.assertEqual(response["route_id"], "r-v2")
        self.assertEqual(response["headers"]["X-Api-Version"], "v2.1")
        self.assertEqual(self.gateway.handle("acme", "GET", "/api/x",
                                             {"X-Api-Version": "v2"})["status"], 406)
        # Quota buckets survived the reload: two of three tokens are now gone,
        # so only one more legacy request fits before a 429.
        self.assertEqual(self.gateway.handle("acme", "GET", "/api/x", self.auth())["status"], 200)
        self.assertEqual(self.gateway.handle("acme", "GET", "/api/x", self.auth())["status"], 200)
        self.assertEqual(self.gateway.handle("acme", "GET", "/api/x", self.auth())["status"], 429)


class VersionHttpTest(unittest.TestCase):
    def setUp(self):
        self.gateway, self.root, self.path = make_gateway()
        self.addCleanup(shutil.rmtree, self.root, True)
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
        req = urllib.request.Request(self.base + path, method="GET",
                                     headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, dict(response.headers), response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers or {}), exc.read().decode("utf-8")

    def test_proxy_versioned_route_returns_header(self):
        status, headers, _ = self.request("/gw/api/x?tenant=acme",
                                          {"X-Api-Version": "v2"})
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Api-Version"), "v2")

    def test_proxy_unversioned_route_has_no_version_header(self):
        status, headers, _ = self.request(
            "/gw/api/x?tenant=acme", {"Authorization": "Bearer " + SECRET})
        self.assertEqual(status, 200)
        self.assertNotIn("X-Api-Version", headers)

    def test_proxy_406_matches_gateway_handle(self):
        status, _, text = self.request("/gw/api/x?tenant=acme", {"X-Api-Version": "v9"})
        self.assertEqual(status, 406)
        payload = json.loads(text)
        self.assertEqual(payload["error"], "unsupported api version")
        self.assertEqual(payload["requested_version"], "v9")
        self.assertEqual(payload["supported_versions"], ["v1", "v2"])
        self.assertTrue(payload["request_id"])

    def test_proxy_config_echoes_version_only_when_declared(self):
        req = urllib.request.Request(self.base + "/v1/config", method="GET")
        with urllib.request.urlopen(req, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        routes = {r["id"]: r for r in payload["routes"]}
        self.assertEqual(routes["r-v1"]["version"], "v1")
        self.assertNotIn("version", routes["r-legacy"])


if __name__ == "__main__":
    unittest.main()
