"""Header-based gray routing: match.headers validation, filtering and picking."""

import hashlib
import json
import os
import shutil
import tempfile
import unittest

from gwd.config import GatewayError, load, parse
from gwd.gateway import Gateway

SECRET = "header-secret"

BAD_HEADERS_MESSAGE = ("route match.headers must map non-empty string names "
                       "to string values")
DUPLICATE_HEADERS_MESSAGE = "route match.headers contains duplicate header names"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def document():
    return {
        "quota_policies": [],
        "keys": [{"key_id": "k-hdr", "tenant": "acme", "secret_sha256": sha(SECRET),
                  "scopes": ["*"]}],
        "routes": [
            {"id": "r-base", "tenant": "acme",
             "match": {"method": "GET", "path_prefix": "/api"},
             "upstream": "echo"},
            {"id": "r-gray", "tenant": "acme",
             "match": {"method": "GET", "path_prefix": "/api",
                       "headers": {"X-Gray": "beta"}},
             "upstream": "echo"},
            {"id": "r-gray-prod", "tenant": "acme",
             "match": {"method": "GET", "path_prefix": "/api",
                       "headers": {"X-Gray": "beta", "X-Env": "prod"}},
             "upstream": "echo"},
            {"id": "r-solo", "tenant": "acme",
             "match": {"method": "GET", "path_prefix": "/solo",
                       "headers": {"X-Gray": "beta"}},
             "upstream": "echo"},
        ],
    }


def write_config(path, doc):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle)
    stat = os.stat(path)
    os.utime(path, ns=(stat.st_atime_ns + 1_000_000, stat.st_mtime_ns + 1_000_000))


class HeaderRoutingTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-headers-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = os.path.join(self.root, "config.json")
        write_config(self.path, document())
        self.gateway = Gateway(config_path=self.path,
                               data_dir=os.path.join(self.root, "data"))

    def auth(self, **extra):
        headers = {"authorization": "Bearer " + SECRET, "x-api-key": "k-hdr"}
        headers.update(extra)
        return headers

    def route_of(self, path, **headers):
        return self.gateway.handle("acme", "GET", path, self.auth(**headers),
                                   "", now_ms=0)

    def test_no_header_keeps_unconditional_route(self):
        response = self.route_of("/api/x")
        self.assertEqual(response["route_id"], "r-base")

    def test_header_name_is_case_insensitive(self):
        response = self.route_of("/api/x", **{"x-GRAY": "beta"})
        self.assertEqual(response["route_id"], "r-gray")

    def test_value_compares_exactly(self):
        for value in ("Beta", " beta", "beta ", "bet"):
            response = self.route_of("/api/x", **{"X-Gray": value})
            self.assertEqual(response["route_id"], "r-base", value)

    def test_every_condition_must_match(self):
        response = self.route_of("/api/x", **{"X-Gray": "beta", "X-Env": "staging"})
        self.assertEqual(response["route_id"], "r-gray")

    def test_more_conditions_win_over_fewer(self):
        response = self.route_of("/api/x", **{"X-Gray": "beta", "X-Env": "prod"})
        self.assertEqual(response["route_id"], "r-gray-prod")

    def test_missing_header_falls_back_to_unconditional(self):
        response = self.route_of("/api/x", **{"X-Other": "beta"})
        self.assertEqual(response["route_id"], "r-base")

    def test_only_header_routes_and_no_match_is_404(self):
        response = self.route_of("/solo/x")
        self.assertEqual(response["status"], 404)
        self.assertIsNone(response["route_id"])

    def test_only_header_route_matches_when_satisfied(self):
        response = self.route_of("/solo/x", **{"X-Gray": "beta"})
        self.assertEqual(response["route_id"], "r-solo")

    def test_longest_prefix_applies_within_the_header_matched_set(self):
        doc = document()
        doc["routes"].append(
            {"id": "r-deep-gray", "tenant": "acme",
             "match": {"method": "GET", "path_prefix": "/api/deep",
                       "headers": {"X-Gray": "beta"}},
             "upstream": "echo"})
        write_config(self.path, doc)
        self.gateway.reload_config()
        response = self.route_of("/api/deep/x", **{"X-Gray": "beta"})
        self.assertEqual(response["route_id"], "r-deep-gray")

    def test_satisfied_header_routes_exclude_longer_unconditional_prefixes(self):
        doc = document()
        doc["routes"].append(
            {"id": "r-deep", "tenant": "acme",
             "match": {"method": "GET", "path_prefix": "/api/deep"},
             "upstream": "echo"})
        write_config(self.path, doc)
        self.gateway.reload_config()
        # A satisfied header route wins even over an unconditional route with
        # a longer prefix: once any declared route matches, only those routes
        # continue to the version filter and selection.
        response = self.route_of("/api/deep/x", **{"X-Gray": "beta"})
        self.assertEqual(response["route_id"], "r-gray")
        response = self.route_of("/api/deep/x")
        self.assertEqual(response["route_id"], "r-deep")

    def test_version_filter_runs_inside_header_matched_set(self):
        doc = document()
        doc["routes"][1]["version"] = "v2"
        write_config(self.path, doc)
        self.gateway.reload_config()
        headers = self.auth(**{"X-Gray": "beta"})
        response = self.gateway.handle("acme", "GET", "/api/x", headers, "", now_ms=0)
        # The gray route is versioned v2 and the request asks for no version:
        # the header-matched set empties inside the version filter -> 406.
        self.assertEqual(response["status"], 406)
        self.assertEqual(json.loads(response["body"])["error"],
                         "unsupported api version")
        headers["x-api-version"] = "v2"
        response = self.gateway.handle("acme", "GET", "/api/x", headers, "", now_ms=0)
        self.assertEqual(response["route_id"], "r-gray")

    def test_config_endpoint_echoes_headers_as_declared(self):
        routes = {r["id"]: r for r in self.gateway.sanitized_config()["routes"]}
        self.assertEqual(routes["r-gray"]["match"]["headers"], {"X-Gray": "beta"})
        self.assertEqual(routes["r-gray-prod"]["match"]["headers"],
                         {"X-Gray": "beta", "X-Env": "prod"})
        self.assertNotIn("headers", routes["r-base"]["match"])


class HeaderValidationTest(unittest.TestCase):
    def assert_bad(self, headers, message):
        doc = {"routes": [{"id": "r", "upstream": "echo",
                           "match": {"method": "GET", "path_prefix": "/a",
                                     "headers": headers}}]}
        with self.assertRaises(GatewayError) as caught:
            parse(doc)
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(caught.exception.message, message)

    def test_null_headers_rejected(self):
        self.assert_bad(None, BAD_HEADERS_MESSAGE)

    def test_non_object_headers_rejected(self):
        for raw in ("X-Gray", ["X-Gray"], 3, True):
            self.assert_bad(raw, BAD_HEADERS_MESSAGE)

    def test_empty_name_rejected(self):
        self.assert_bad({"": "beta"}, BAD_HEADERS_MESSAGE)

    def test_empty_value_rejected(self):
        self.assert_bad({"X-Gray": ""}, BAD_HEADERS_MESSAGE)

    def test_non_string_value_rejected(self):
        for raw in (1, 1.5, True, None, ["beta"]):
            self.assert_bad({"X-Gray": raw}, BAD_HEADERS_MESSAGE)

    def test_case_variant_duplicate_names_rejected(self):
        self.assert_bad({"X-Gray": "a", "x-gray": "b"}, DUPLICATE_HEADERS_MESSAGE)

    def test_empty_headers_object_is_an_unconditional_route(self):
        doc = {"routes": [{"id": "r", "upstream": "echo",
                           "match": {"method": "GET", "path_prefix": "/a",
                                     "headers": {}}}]}
        config = parse(doc)
        self.assertEqual(config.routes[0].match_headers, {})
        self.assertEqual(config.routes[0].to_dict()["match"]["headers"], {})

    def test_omitted_headers_stay_omitted(self):
        doc = {"routes": [{"id": "r", "upstream": "echo",
                           "match": {"method": "GET", "path_prefix": "/a"}}]}
        config = parse(doc)
        self.assertIsNone(config.routes[0].match_headers)
        self.assertNotIn("headers", config.routes[0].to_dict()["match"])


class HeaderReloadTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-headers-reload-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = os.path.join(self.root, "config.json")
        write_config(self.path, document())
        self.gateway = Gateway(config_path=self.path,
                               data_dir=os.path.join(self.root, "data"))

    def test_invalid_reload_keeps_old_config_and_reports_error(self):
        doc = document()
        doc["routes"][1]["match"]["headers"] = {"X-Gray": 7}
        write_config(self.path, doc)
        self.assertFalse(self.gateway.reload_config())
        self.assertFalse(self.gateway.store.ready)
        self.assertEqual(self.gateway.store.last_error, BAD_HEADERS_MESSAGE)
        self.assertIn("r-gray", {r.id for r in self.gateway.config.routes})

    def test_valid_reload_applies_to_new_requests(self):
        doc = document()
        doc["routes"][0]["match"]["headers"] = {"X-Canary": "yes"}
        write_config(self.path, doc)
        self.assertTrue(self.gateway.reload_config())
        headers = {"authorization": "Bearer " + SECRET, "x-api-key": "k-hdr"}
        response = self.gateway.handle("acme", "GET", "/api/x", headers, "", now_ms=0)
        self.assertEqual(response["status"], 404)
        headers["X-Canary"] = "yes"
        response = self.gateway.handle("acme", "GET", "/api/x", headers, "", now_ms=0)
        self.assertEqual(response["route_id"], "r-base")

    def test_route_add_batch_is_all_or_nothing(self):
        with self.assertRaises(GatewayError) as caught:
            self.gateway.add_route([
                {"id": "r-new", "upstream": "echo",
                 "match": {"method": "GET", "path_prefix": "/new"}},
                {"id": "r-bad", "upstream": "echo",
                 "match": {"method": "GET", "path_prefix": "/bad",
                           "headers": {"X-Gray": None}}},
            ])
        self.assertEqual(caught.exception.message, BAD_HEADERS_MESSAGE)
        self.assertNotIn("r-new", {r.id for r in self.gateway.config.routes})
        self.assertNotIn("r-bad", {r.id for r in self.gateway.config.routes})

    def test_route_add_round_trips_headers(self):
        self.gateway.add_route(
            {"id": "r-new", "upstream": "echo",
             "match": {"method": "GET", "path_prefix": "/new",
                       "headers": {"X-Gray": "beta"}}})
        on_disk = load(self.path)
        route = next(r for r in on_disk.routes if r.id == "r-new")
        self.assertEqual(route.match_headers, {"X-Gray": "beta"})


if __name__ == "__main__":
    unittest.main()
