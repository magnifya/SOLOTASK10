"""Per-route retry budgets: validation, echo, runtime and hot reload."""

import hashlib
import json
import os
import shutil
import tempfile
import unittest

from gwd.config import GatewayError, load
from gwd.gateway import Gateway
from gwd.upstream import UpstreamError


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def document():
    return {
        "quota_policies": [
            {"id": "p-fast", "tenant": "acme", "algorithm": "token-bucket",
             "limit": 5, "window_ms": 60000, "burst": 5}],
        "keys": [
            {"key_id": "k-read", "tenant": "acme", "secret_sha256": sha("read-secret"),
             "scopes": ["read"]}],
        "routes": [
            {"id": "r-plain", "tenant": "acme",
             "match": {"method": "GET", "path_prefix": "/plain"},
             "upstream": "echo", "auth_required": False},
            {"id": "r-tuned", "tenant": "acme",
             "match": {"method": "GET", "path_prefix": "/tuned"},
             "upstream": "echo", "auth_required": False,
             "retry": {"max_attempts": 2, "base_ms": 5, "max_ms": 50}}],
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


class RouteRetryValidationTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-test-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = os.path.join(self.root, "config.json")

    def route(self, retry, **extra):
        data = {"id": "r-x", "match": {"method": "GET", "path_prefix": "/x"},
                "upstream": "echo", "auth_required": False}
        data.update(extra)
        if retry is not ...:
            data["retry"] = retry
        return data

    def load_routes(self, routes):
        write_config(self.path, {"routes": routes, "keys": [], "quota_policies": []})
        return load(self.path)

    def assert_invalid(self, retry):
        with self.assertRaises(GatewayError) as ctx:
            self.load_routes([self.route(retry)])
        self.assertEqual(ctx.exception.message, "route retry policy is invalid")

    def test_valid_retry_is_accepted_and_echoed(self):
        config = self.load_routes([self.route({"max_attempts": 2, "base_ms": 0, "max_ms": 1})])
        route = config.routes[0]
        self.assertEqual(route.to_dict()["retry"],
                         {"max_attempts": 2, "base_ms": 0, "max_ms": 1})

    def test_boundary_values_are_accepted(self):
        config = self.load_routes([
            self.route({"max_attempts": 1, "base_ms": 0, "max_ms": 1})])
        self.assertIsNotNone(config.routes[0].retry)

    def test_omitted_retry_keeps_the_legacy_shape(self):
        config = self.load_routes([self.route(...)])
        self.assertIsNone(config.routes[0].retry)
        self.assertNotIn("retry", config.routes[0].to_dict())

    def test_null_and_non_objects_are_rejected(self):
        for bad in (None, True, 3, "x", [], [{"max_attempts": 1}]):
            self.assert_invalid(bad)

    def test_missing_and_extra_members_are_rejected(self):
        self.assert_invalid({"max_attempts": 2, "base_ms": 5})
        self.assert_invalid({"max_attempts": 2, "base_ms": 5, "max_ms": 50, "jitter": 1})
        self.assert_invalid({"max_attempts": 2, "base_ms": 5, "max_ms": None})

    def test_non_integer_members_are_rejected(self):
        self.assert_invalid({"max_attempts": True, "base_ms": 5, "max_ms": 50})
        self.assert_invalid({"max_attempts": 2, "base_ms": 1.5, "max_ms": 50})
        self.assert_invalid({"max_attempts": 2, "base_ms": 5, "max_ms": "50"})

    def test_out_of_range_members_are_rejected(self):
        self.assert_invalid({"max_attempts": 0, "base_ms": 5, "max_ms": 50})
        self.assert_invalid({"max_attempts": 2, "base_ms": -1, "max_ms": 50})
        self.assert_invalid({"max_attempts": 2, "base_ms": 5, "max_ms": 0})
        self.assert_invalid({"max_attempts": 2, "base_ms": 60, "max_ms": 50})


class RouteRetryRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.gateway, self.root, self.path = make_gateway(
            breaker_settings={"failure_threshold": 10, "open_ms": 1000,
                              "success_threshold": 1})
        self.addCleanup(shutil.rmtree, self.root, True)
        self.calls = []

        def flaky(request):
            self.calls.append(request)
            return {"status": 503, "body": {"error": "down"}}

        self.gateway.upstreams.register("flaky", flaky)

    def add_flaky_route(self, route_id, prefix, retry=..., fallbacks=None):
        route = {"id": route_id, "tenant": "acme",
                 "match": {"method": "GET", "path_prefix": prefix},
                 "upstream": "flaky", "auth_required": False}
        if retry is not ...:
            route["retry"] = retry
        if fallbacks:
            route["fallback_upstreams"] = fallbacks
        self.gateway.add_route(route)

    def test_route_budget_overrides_the_global_policy(self):
        self.add_flaky_route("r-f1", "/f1", {"max_attempts": 1, "base_ms": 0, "max_ms": 1})
        response = self.gateway.handle("acme", "GET", "/f1/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 503)
        self.assertEqual(len(self.calls), 1)          # no retries with max_attempts 1
        self.assertEqual(self.gateway.audit("acme", 1)[0]["attempts"], 1)

    def test_route_budget_allows_more_attempts_than_the_global_default(self):
        self.add_flaky_route("r-f4", "/f4",
                             {"max_attempts": 4, "base_ms": 0, "max_ms": 1})
        response = self.gateway.handle("acme", "GET", "/f4/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 503)
        self.assertEqual(len(self.calls), 4)          # global default would stop at 3
        self.assertEqual(self.gateway.audit("acme", 1)[0]["attempts"], 4)

    def test_route_without_retry_still_uses_the_global_policy(self):
        self.add_flaky_route("r-fg", "/fg")
        response = self.gateway.handle("acme", "GET", "/fg/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 503)
        self.assertEqual(len(self.calls), 3)          # RetryPolicy.max_attempts default

    def test_non_retryable_status_is_returned_immediately(self):
        self.gateway.upstreams.register("gone", lambda req: {"status": 404, "body": {}})
        self.gateway.add_route({"id": "r-gone", "tenant": "acme",
                                "match": {"method": "GET", "path_prefix": "/gone"},
                                "upstream": "gone", "auth_required": False,
                                "retry": {"max_attempts": 5, "base_ms": 0, "max_ms": 1}})
        response = self.gateway.handle("acme", "GET", "/gone/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 404)
        self.assertEqual(self.gateway.audit("acme", 1)[0]["attempts"], 1)

    def test_each_fallback_gets_the_route_budget(self):
        fallback_calls = []
        self.gateway.upstreams.register(
            "backup", lambda req: fallback_calls.append(req) or {"status": 200, "body": {}})
        self.add_flaky_route("r-fb", "/fb",
                             {"max_attempts": 2, "base_ms": 0, "max_ms": 1},
                             fallbacks=["backup"])
        response = self.gateway.handle("acme", "GET", "/fb/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 200)
        self.assertEqual(len(self.calls), 2)          # primary spent its own budget
        self.assertEqual(len(fallback_calls), 1)      # fallback succeeded on its first try
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual((entry["attempts"], entry["upstream"]), (3, "backup"))

    def test_backoff_caps_come_from_the_route(self):
        delays = []
        gateway, root, _ = make_gateway(
            breaker_settings={"failure_threshold": 10},
            sleep_fn=lambda ms: delays.append(ms))
        self.addCleanup(shutil.rmtree, root, True)
        gateway.upstreams.register("flaky",
                                   lambda req: {"status": 503, "body": {}})
        gateway.add_route({"id": "r-sl", "tenant": "acme",
                           "match": {"method": "GET", "path_prefix": "/sl"},
                           "upstream": "flaky", "auth_required": False,
                           "retry": {"max_attempts": 4, "base_ms": 10, "max_ms": 25}})
        gateway.handle("acme", "GET", "/sl/x", {}, "", now_ms=0)
        self.assertEqual(delays, [10, 20, 25])        # exponential, capped at max_ms

    def test_route_add_batch_fails_atomically_on_invalid_retry(self):
        before_file = open(self.path, encoding="utf-8").read()
        before_revision = self.gateway.store.revision
        before_routes = len(self.gateway.config.routes)
        with self.assertRaises(GatewayError) as ctx:
            self.gateway.add_route([
                {"id": "r-ok", "tenant": "acme",
                 "match": {"method": "GET", "path_prefix": "/ok"},
                 "upstream": "echo", "auth_required": False},
                {"id": "r-bad", "tenant": "acme",
                 "match": {"method": "GET", "path_prefix": "/bad"},
                 "upstream": "echo", "auth_required": False,
                 "retry": {"max_attempts": 0, "base_ms": 5, "max_ms": 50}}])
        self.assertEqual(ctx.exception.message, "route retry policy is invalid")
        self.assertEqual(open(self.path, encoding="utf-8").read(), before_file)
        self.assertEqual(self.gateway.store.revision, before_revision)
        self.assertEqual(len(self.gateway.config.routes), before_routes)

    def test_route_add_echoes_the_retry_and_config_shows_it(self):
        out = self.gateway.add_route(
            {"id": "r-new", "tenant": "acme",
             "match": {"method": "GET", "path_prefix": "/new"},
             "upstream": "echo", "auth_required": False,
             "retry": {"max_attempts": 2, "base_ms": 5, "max_ms": 50}})
        self.assertEqual(out["retry"], {"max_attempts": 2, "base_ms": 5, "max_ms": 50})
        shown = {r["id"]: r for r in self.gateway.sanitized_config()["routes"]}
        self.assertEqual(shown["r-new"]["retry"],
                         {"max_attempts": 2, "base_ms": 5, "max_ms": 50})
        self.assertEqual(shown["r-tuned"]["retry"],
                         {"max_attempts": 2, "base_ms": 5, "max_ms": 50})
        self.assertNotIn("retry", shown["r-plain"])


class RouteRetryReloadTest(unittest.TestCase):
    def setUp(self):
        self.gateway, self.root, self.path = make_gateway(
            breaker_settings={"failure_threshold": 10, "open_ms": 1000})
        self.addCleanup(shutil.rmtree, self.root, True)
        self.calls = []
        self.gateway.upstreams.register(
            "flaky", lambda req: self.calls.append(req) or {"status": 503, "body": {}})

    def rewrite(self, mutate):
        doc = document()
        mutate(doc)
        write_config(self.path, doc)

    def tuned_route(self, doc):
        return next(r for r in doc["routes"] if r["id"] == "r-tuned")

    def test_reload_with_invalid_retry_keeps_the_last_good_config(self):
        def corrupt(doc):
            self.tuned_route(doc)["retry"] = {"max_attempts": 2, "base_ms": 5}
        self.rewrite(corrupt)
        self.assertFalse(self.gateway.reload_config())
        self.assertFalse(self.gateway.store.ready)
        self.assertEqual(self.gateway.store.last_error, "route retry policy is invalid")
        route = next(r for r in self.gateway.config.routes if r.id == "r-tuned")
        self.assertEqual(route.retry.max_attempts, 2)  # the previous config survived

    def test_new_requests_use_the_reloaded_budget(self):
        self.gateway.add_route({"id": "r-rl", "tenant": "acme",
                                "match": {"method": "GET", "path_prefix": "/rl"},
                                "upstream": "flaky", "auth_required": False,
                                "retry": {"max_attempts": 1, "base_ms": 0, "max_ms": 1}})
        self.gateway.handle("acme", "GET", "/rl/x", {}, "", now_ms=0)
        self.assertEqual(len(self.calls), 1)

        def expand(doc):
            doc["routes"].append(
                {"id": "r-rl2", "tenant": "acme",
                 "match": {"method": "GET", "path_prefix": "/rl"},
                 "upstream": "flaky", "auth_required": False,
                 "retry": {"max_attempts": 5, "base_ms": 0, "max_ms": 1}})
            doc["routes"] = [r for r in doc["routes"] if r["id"] != "r-rl"]
        self.rewrite(expand)
        self.assertTrue(self.gateway.reload_config())
        self.gateway.handle("acme", "GET", "/rl/x", {}, "", now_ms=10)
        self.assertEqual(len(self.calls), 1 + 5)

    def test_in_flight_request_keeps_the_snapshot_it_started_with(self):
        gateway, root, path = make_gateway(
            breaker_settings={"failure_threshold": 10}, sleep_fn=None)
        self.addCleanup(shutil.rmtree, root, True)
        calls = []
        gateway.upstreams.register(
            "flaky", lambda req: calls.append(req) or {"status": 503, "body": {}})
        gateway.add_route({"id": "r-snap", "tenant": "acme",
                           "match": {"method": "GET", "path_prefix": "/snap"},
                           "upstream": "flaky", "auth_required": False,
                           "retry": {"max_attempts": 3, "base_ms": 0, "max_ms": 1}})

        def shrink_mid_request(ms):
            doc = document()
            doc["routes"].append(
                {"id": "r-snap2", "tenant": "acme",
                 "match": {"method": "GET", "path_prefix": "/snap"},
                 "upstream": "flaky", "auth_required": False,
                 "retry": {"max_attempts": 1, "base_ms": 0, "max_ms": 1}})
            write_config(path, doc)
            gateway.reload_config()
            gateway.sleep_fn = None

        gateway.sleep_fn = shrink_mid_request
        gateway.handle("acme", "GET", "/snap/x", {}, "", now_ms=0)
        self.assertEqual(len(calls), 3)                # the old budget finished the request
        gateway.handle("acme", "GET", "/snap/x", {}, "", now_ms=10)
        self.assertEqual(len(calls), 3 + 1)            # new requests use the new budget

    def test_retry_change_preserves_quota_breaker_and_idempotency_state(self):
        gateway, root, path = make_gateway(
            breaker_settings={"failure_threshold": 10, "open_ms": 1000})
        self.addCleanup(shutil.rmtree, root, True)
        gateway.add_route({"id": "r-q", "tenant": "acme",
                           "match": {"method": "GET", "path_prefix": "/q"},
                           "upstream": "echo", "auth_required": False,
                           "quota_policy": "p-fast"})
        gateway.handle("acme", "GET", "/q/x", {}, "", now_ms=0)
        gateway.handle("acme", "GET", "/q/y",
                       {"x-idempotency-key": "abc"}, "", now_ms=1)
        gateway.breakers.get("echo").record(False, 1)  # one remembered failure

        def tune(doc):
            doc["routes"].append(
                {"id": "r-q2", "tenant": "acme",
                 "match": {"method": "GET", "path_prefix": "/q"},
                 "upstream": "echo", "auth_required": False,
                 "quota_policy": "p-fast",
                 "retry": {"max_attempts": 2, "base_ms": 0, "max_ms": 1}})
            doc["routes"] = [r for r in doc["routes"] if r["id"] != "r-q"]
        doc = document()
        tune(doc)
        write_config(path, doc)
        self.assertTrue(gateway.reload_config())

        self.assertEqual(gateway.breakers.get("echo").failures, 1)  # not reset
        replay = gateway.handle("acme", "GET", "/q/y",
                                {"x-idempotency-key": "abc"}, "", now_ms=2)
        self.assertEqual(replay["headers"].get("X-Idempotent-Replay"), "true")
        entry = gateway.audit("acme", 1)[0]            # quota bucket kept its state
        self.assertEqual(entry["quota"]["remaining"], 5 - 3)


if __name__ == "__main__":
    unittest.main()
