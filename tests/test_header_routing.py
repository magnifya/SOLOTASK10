"""Header-based gray routing: match.headers validation, filtering, selection."""

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

SECRET = "header-secret"
SHAPE_ERROR = "route match.headers must map non-empty string names to string values"
DUPLICATE_ERROR = "route match.headers contains duplicate header names"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def document():
    return {
        "quota_policies": [
            {"id": "p-hdr", "tenant": "acme", "algorithm": "token-bucket",
             "limit": 3, "window_ms": 60000, "burst": 3}],
        "keys": [{"key_id": "k-hdr", "tenant": "acme", "secret_sha256": sha(SECRET),
                  "scopes": ["read"]}],
        "routes": [
            {"id": "r-base", "tenant": "acme",
             "match": {"method": "GET", "path_prefix": "/api"},
             "upstream": "echo", "quota_policy": "p-hdr", "scopes": ["read"]},
            {"id": "r-gray", "tenant": "acme", "auth_required": False,
             "match": {"method": "GET", "path_prefix": "/api",
                       "headers": {"X-Gray-Channel": "beta"}},
             "upstream": "echo"},
        ],
    }


def write_config(path, doc):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle)
    stat = os.stat(path)
    os.utime(path, ns=(stat.st_atime_ns + 1_000_000, stat.st_mtime_ns + 1_000_000))


def make_gateway(doc=None, **kwargs):
    root = tempfile.mkdtemp(prefix="gwd-headers-")
    path = os.path.join(root, "config.json")
    write_config(path, document() if doc is None else doc)
    gateway = Gateway(config_path=path, data_dir=os.path.join(root, "data"), **kwargs)
    return gateway, root, path


class HeaderConfigTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-headers-cfg-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = os.path.join(self.root, "config.json")

    _OMIT = object()

    def load_doc(self, headers):
        doc = document()
        if headers is self._OMIT:
            doc["routes"][1]["match"].pop("headers")
        else:
            doc["routes"][1]["match"]["headers"] = headers
        write_config(self.path, doc)
        return load(self.path)

    def test_valid_headers_accepted(self):
        config = self.load_doc({"X-Gray-Channel": "beta", "X-Env": "prod"})
        self.assertEqual(config.routes[1].match_headers,
                         {"X-Gray-Channel": "beta", "X-Env": "prod"})

    def test_omitted_headers_means_unconditional(self):
        config = self.load_doc(self._OMIT)
        self.assertIsNone(config.routes[1].match_headers)

    def test_empty_headers_object_accepted(self):
        config = self.load_doc({})
        self.assertEqual(config.routes[1].match_headers, {})

    def test_shape_error_message_and_status(self):
        for bad in (None, "x", 1, True, ["a"], {"": "v"}, {"X-A": ""},
                    {"X-A": 1}, {"X-A": True}, {"X-A": None}, {"X-A": {"n": 1}}):
            with self.assertRaises(GatewayError) as ctx:
                self.load_doc(bad)
            self.assertEqual(ctx.exception.message, SHAPE_ERROR, msg=repr(bad))
            self.assertEqual(ctx.exception.status, 400, msg=repr(bad))

    def test_non_string_header_name_rejected(self):
        # JSON object keys are always strings, so a non-string name can only
        # arrive through the Python API (route-add); validate it the same way.
        from gwd.config import parse
        doc = document()
        doc["routes"][1]["match"]["headers"] = {1: "v"}
        with self.assertRaises(GatewayError) as ctx:
            parse(doc)
        self.assertEqual(ctx.exception.message, SHAPE_ERROR)
        self.assertEqual(ctx.exception.status, 400)

    def test_duplicate_names_differing_only_by_case(self):
        with self.assertRaises(GatewayError) as ctx:
            self.load_doc({"X-Gray": "a", "x-gray": "b"})
        self.assertEqual(ctx.exception.message, DUPLICATE_ERROR)
        self.assertEqual(ctx.exception.status, 400)

    def test_route_add_rejects_bad_headers_and_writes_nothing(self):
        write_config(self.path, document())
        gateway = Gateway(config_path=self.path, data_dir=os.path.join(self.root, "data"))
        revision = gateway.store.revision
        batch = [
            {"id": "r-ok", "match": {"method": "GET", "path_prefix": "/ok"},
             "upstream": "echo"},
            {"id": "r-bad", "match": {"method": "GET", "path_prefix": "/bad",
                                      "headers": {"X-A": ""}},
             "upstream": "echo"},
        ]
        with self.assertRaises(GatewayError) as ctx:
            gateway.add_route(batch)
        self.assertEqual(ctx.exception.message, SHAPE_ERROR)
        with open(self.path, "r", encoding="utf-8") as handle:
            text = handle.read()
        self.assertNotIn("r-ok", text)
        self.assertNotIn("r-bad", text)
        self.assertEqual(gateway.store.revision, revision)

    def test_route_add_accepts_headers_and_sanitized_echoes_them(self):
        write_config(self.path, document())
        gateway = Gateway(config_path=self.path, data_dir=os.path.join(self.root, "data"))
        out = gateway.add_route({"id": "r-new",
                                 "match": {"method": "GET", "path_prefix": "/new",
                                           "headers": {"X-Channel": "Beta"}},
                                 "upstream": "echo"})
        self.assertEqual(out["match"]["headers"], {"X-Channel": "Beta"})
        routes = {r["id"]: r for r in gateway.sanitized_config()["routes"]}
        # Declared routes echo the field exactly as declared, casing included.
        self.assertEqual(routes["r-new"]["match"]["headers"], {"X-Channel": "Beta"})
        self.assertEqual(routes["r-gray"]["match"]["headers"], {"X-Gray-Channel": "beta"})
        # Routes that never declared the field keep their exact old output.
        self.assertNotIn("headers", routes["r-base"]["match"])


class HeaderRoutingTest(unittest.TestCase):
    def setUp(self):
        self.gateway, self.root, self.path = make_gateway()
        self.addCleanup(shutil.rmtree, self.root, True)

    def auth(self):
        return {"authorization": "Bearer " + SECRET}

    def test_satisfied_condition_selects_header_route(self):
        headers = self.auth()
        headers["X-Gray-Channel"] = "beta"
        response = self.gateway.handle("acme", "GET", "/api/x", headers)
        self.assertEqual(response["status"], 200)
        self.assertEqual(response["route_id"], "r-gray")

    def test_header_name_is_case_insensitive(self):
        headers = self.auth()
        headers["x-GRAY-channel"] = "beta"
        response = self.gateway.handle("acme", "GET", "/api/x", headers)
        self.assertEqual(response["route_id"], "r-gray")

    def test_value_compares_exactly(self):
        for value in ("Beta", " beta", "beta ", "bet", "beta2", "b*"):
            headers = self.auth()
            headers["X-Gray-Channel"] = value
            response = self.gateway.handle("acme", "GET", "/api/x", headers)
            self.assertEqual(response["route_id"], "r-base", msg=repr(value))

    def test_missing_header_falls_back_to_unconditional_route(self):
        response = self.gateway.handle("acme", "GET", "/api/x", self.auth())
        self.assertEqual(response["status"], 200)
        self.assertEqual(response["route_id"], "r-base")

    def test_unmatched_conditional_without_unconditional_is_404(self):
        doc = document()
        doc["routes"] = [r for r in doc["routes"] if r["id"] != "r-base"]
        gateway, root, _ = make_gateway(doc)
        self.addCleanup(shutil.rmtree, root, True)
        response = gateway.handle("acme", "GET", "/api/x", self.auth())
        self.assertEqual(response["status"], 404)
        payload = json.loads(response["body"])
        self.assertEqual(payload["error"], "no route for GET /api/x")

    def test_every_condition_must_hold(self):
        doc = document()
        doc["routes"][1]["match"]["headers"] = {"X-Gray-Channel": "beta", "X-Env": "prod"}
        gateway, root, _ = make_gateway(doc)
        self.addCleanup(shutil.rmtree, root, True)
        headers = self.auth()
        headers["X-Gray-Channel"] = "beta"
        headers["X-Env"] = "prod"
        self.assertEqual(gateway.handle("acme", "GET", "/api/x", headers)["route_id"],
                         "r-gray")
        headers["X-Env"] = "dev"
        self.assertEqual(gateway.handle("acme", "GET", "/api/x", headers)["route_id"],
                         "r-base")
        del headers["X-Env"]
        self.assertEqual(gateway.handle("acme", "GET", "/api/x", headers)["route_id"],
                         "r-base")

    def test_more_conditions_win_on_prefix_tie(self):
        doc = document()
        doc["routes"].append(
            {"id": "r-gray2", "tenant": "acme", "auth_required": False,
             "match": {"method": "GET", "path_prefix": "/api",
                       "headers": {"X-Gray-Channel": "beta", "X-Env": "prod"}},
             "upstream": "echo"})
        gateway, root, _ = make_gateway(doc)
        self.addCleanup(shutil.rmtree, root, True)
        headers = self.auth()
        headers["X-Gray-Channel"] = "beta"
        headers["X-Env"] = "prod"
        # Both conditional routes match; the one declaring more conditions wins.
        for _ in range(5):
            response = gateway.handle("acme", "GET", "/api/x", headers)
            self.assertEqual(response["route_id"], "r-gray2")

    def test_weighted_stable_hash_among_equal_condition_counts(self):
        doc = document()
        doc["routes"].append(
            {"id": "r-gray2", "tenant": "acme", "auth_required": False,
             "match": {"method": "GET", "path_prefix": "/api",
                       "headers": {"X-Gray-Channel": "beta"}},
             "upstream": "echo"})
        gateway, root, _ = make_gateway(doc)
        self.addCleanup(shutil.rmtree, root, True)
        headers = self.auth()
        headers["X-Gray-Channel"] = "beta"
        headers["X-Request-Id"] = "sticky-1"
        first = gateway.handle("acme", "GET", "/api/x", headers)["route_id"]
        self.assertIn(first, ("r-gray", "r-gray2"))
        for _ in range(5):
            self.assertEqual(gateway.handle("acme", "GET", "/api/x", headers)["route_id"],
                             first)

    def test_satisfied_header_route_beats_longer_unconditional_prefix(self):
        doc = document()
        doc["routes"].append(
            {"id": "r-deep", "tenant": "acme",
             "match": {"method": "GET", "path_prefix": "/api/deep"},
             "upstream": "echo", "auth_required": False})
        gateway, root, _ = make_gateway(doc)
        self.addCleanup(shutil.rmtree, root, True)
        headers = self.auth()
        headers["X-Gray-Channel"] = "beta"
        # Once a conditional route is satisfied, only conditional routes
        # continue, even when an unconditional route has a longer prefix.
        response = gateway.handle("acme", "GET", "/api/deep/x", headers)
        self.assertEqual(response["route_id"], "r-gray")
        # Without the marker the unconditional routes are the candidates and
        # the longest prefix wins as usual.
        response = gateway.handle("acme", "GET", "/api/deep/x", self.auth())
        self.assertEqual(response["route_id"], "r-deep")

    def test_version_filter_applies_within_header_candidates(self):
        doc = document()
        doc["routes"][1]["version"] = "v2"
        gateway, root, _ = make_gateway(doc)
        self.addCleanup(shutil.rmtree, root, True)
        headers = self.auth()
        headers["X-Gray-Channel"] = "beta"
        # The only satisfied header route is versioned; an unversioned request
        # empties the candidate set and gets the usual 406.
        response = gateway.handle("acme", "GET", "/api/x", headers)
        self.assertEqual(response["status"], 406)
        payload = json.loads(response["body"])
        self.assertEqual(payload["supported_versions"], ["v2"])
        headers["X-Api-Version"] = "v2"
        response = gateway.handle("acme", "GET", "/api/x", headers)
        self.assertEqual(response["status"], 200)
        self.assertEqual(response["route_id"], "r-gray")
        self.assertEqual(response["headers"]["X-Api-Version"], "v2")

    def test_unconditional_only_config_is_unchanged(self):
        doc = document()
        doc["routes"] = [r for r in doc["routes"] if r["id"] != "r-gray"]
        gateway, root, _ = make_gateway(doc)
        self.addCleanup(shutil.rmtree, root, True)
        response = gateway.handle("acme", "GET", "/api/x", self.auth())
        self.assertEqual(response["status"], 200)
        self.assertEqual(response["route_id"], "r-base")

    def test_protected_header_route_still_authenticates(self):
        doc = document()
        doc["routes"][1]["auth_required"] = True
        doc["routes"][1]["scopes"] = ["read"]
        gateway, root, _ = make_gateway(doc)
        self.addCleanup(shutil.rmtree, root, True)
        headers = {"X-Gray-Channel": "beta"}
        response = gateway.handle("acme", "GET", "/api/x", headers)
        self.assertEqual(response["status"], 401)
        headers["authorization"] = "Bearer " + SECRET
        response = gateway.handle("acme", "GET", "/api/x", headers)
        self.assertEqual(response["status"], 200)
        self.assertEqual(response["route_id"], "r-gray")


class HeaderReloadTest(unittest.TestCase):
    def setUp(self):
        self.gateway, self.root, self.path = make_gateway()
        self.addCleanup(shutil.rmtree, self.root, True)

    def auth(self):
        return {"authorization": "Bearer " + SECRET}

    def test_invalid_headers_reload_keeps_previous_config(self):
        before = self.gateway.store.revision
        doc = document()
        doc["routes"][1]["match"]["headers"] = {"X-Gray-Channel": None}
        write_config(self.path, doc)
        self.assertFalse(self.gateway.reload_config())
        self.assertFalse(self.gateway.store.ready)
        self.assertEqual(self.gateway.store.last_error, SHAPE_ERROR)
        self.assertEqual(self.gateway.store.revision, before)
        # The previous config still routes by the old rules.
        headers = self.auth()
        headers["X-Gray-Channel"] = "beta"
        self.assertEqual(self.gateway.handle("acme", "GET", "/api/x", headers)["route_id"],
                         "r-gray")

    def test_duplicate_headers_reload_keeps_previous_config(self):
        doc = document()
        doc["routes"][1]["match"]["headers"] = {"X-Gray": "a", "x-gray": "b"}
        write_config(self.path, doc)
        self.assertFalse(self.gateway.reload_config())
        self.assertFalse(self.gateway.store.ready)
        self.assertEqual(self.gateway.store.last_error, DUPLICATE_ERROR)

    def test_valid_reload_applies_to_new_requests_and_keeps_state(self):
        # Drain part of the base route's bucket so bucket preservation is visible.
        self.assertEqual(self.gateway.handle("acme", "GET", "/api/x", self.auth())["status"], 200)
        doc = document()
        doc["routes"][1]["match"]["headers"] = {"X-Gray-Channel": "gamma"}
        write_config(self.path, doc)
        self.assertTrue(self.gateway.reload_config())
        self.assertTrue(self.gateway.store.ready)
        self.assertIsNone(self.gateway.store.last_error)
        headers = self.auth()
        headers["X-Gray-Channel"] = "gamma"
        self.assertEqual(self.gateway.handle("acme", "GET", "/api/x", headers)["route_id"],
                         "r-gray")
        headers["X-Gray-Channel"] = "beta"
        self.assertEqual(self.gateway.handle("acme", "GET", "/api/x", headers)["route_id"],
                         "r-base")
        # Quota buckets survived the reload: two of the three tokens were spent
        # (one before the reload, one by the beta request above), so exactly
        # one more base request fits before a 429.
        self.assertEqual(self.gateway.handle("acme", "GET", "/api/x", self.auth())["status"], 200)
        self.assertEqual(self.gateway.handle("acme", "GET", "/api/x", self.auth())["status"], 429)


class HeaderHttpTest(unittest.TestCase):
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

    def test_proxy_routes_by_request_header(self):
        headers = {"Authorization": "Bearer " + SECRET, "X-Gray-Channel": "beta"}
        status, _, text = self.request("/gw/api/x?tenant=acme", headers)
        self.assertEqual(status, 200)
        status, _, _ = self.request("/gw/api/x?tenant=acme",
                                    {"Authorization": "Bearer " + SECRET})
        self.assertEqual(status, 200)
        # The gray route only answers when the marker header is present.
        audit = self.gateway.audit()
        self.assertEqual([entry["route_id"] for entry in audit][:2],
                         ["r-gray", "r-base"])

    def test_proxy_config_echoes_headers_only_when_declared(self):
        req = urllib.request.Request(self.base + "/v1/config", method="GET")
        with urllib.request.urlopen(req, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        routes = {r["id"]: r for r in payload["routes"]}
        self.assertEqual(routes["r-gray"]["match"]["headers"], {"X-Gray-Channel": "beta"})
        self.assertNotIn("headers", routes["r-base"]["match"])


if __name__ == "__main__":
    unittest.main()
