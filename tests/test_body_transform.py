"""JSON body transforms: wrap/unwrap of request and response bodies."""

import hashlib
import json
import os
import shutil
import tempfile
import unittest

from gwd.config import GatewayError, load
from gwd.gateway import Gateway
from gwd.upstream import UpstreamError

SECRET = "transform-secret"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def document():
    return {
        "quota_policies": [
            {"id": "p-body", "tenant": "acme", "algorithm": "token-bucket",
             "limit": 4, "window_ms": 60000, "burst": 4}],
        "keys": [{"key_id": "k-body", "tenant": "acme", "secret_sha256": sha(SECRET),
                  "scopes": ["read"]}],
        "routes": [
            {"id": "r-wrap", "tenant": "acme",
             "match": {"method": "POST", "path_prefix": "/wrap"},
             "upstream": "capture", "auth_required": False,
             "quota_policy": "p-body",
             "transform": {"request_body": {"operation": "wrap", "field": "data"}}},
            {"id": "r-unwrap", "tenant": "acme",
             "match": {"method": "POST", "path_prefix": "/unwrap"},
             "upstream": "capture", "auth_required": False,
             "transform": {"request_body": {"operation": "unwrap", "field": "data"},
                           "response_body": {"operation": "unwrap", "field": "result"}}},
            {"id": "r-resp", "tenant": "acme",
             "match": {"method": "GET", "path_prefix": "/resp"},
             "upstream": "capture", "auth_required": False,
             "transform": {"response_body": {"operation": "wrap", "field": "result"}}},
            {"id": "r-plain", "tenant": "acme",
             "match": {"method": "POST", "path_prefix": "/plain"},
             "upstream": "capture", "auth_required": False}],
    }


def write_config(path, doc):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle)
    stat = os.stat(path)
    os.utime(path, ns=(stat.st_atime_ns + 1_000_000, stat.st_mtime_ns + 1_000_000))


def make_gateway(doc=None, **kwargs):
    root = tempfile.mkdtemp(prefix="gwd-body-")
    path = os.path.join(root, "config.json")
    write_config(path, document() if doc is None else doc)
    gateway = Gateway(config_path=path, data_dir=os.path.join(root, "data"), **kwargs)
    return gateway, root, path


class BodyTransformConfigTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-body-cfg-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = os.path.join(self.root, "config.json")

    def route(self, transform):
        return {"id": "r", "match": {"method": "POST", "path_prefix": "/x"},
                "upstream": "echo", "transform": transform}

    def test_malformed_body_transforms_are_rejected(self):
        cases = {
            "null": None,
            "string": "wrap",
            "list": ["wrap"],
            "number": 1,
            "empty object": {},
            "extra key": {"operation": "wrap", "field": "f", "extra": 1},
            "missing operation": {"field": "f"},
            "bad operation": {"operation": "fold", "field": "f"},
            "null operation": {"operation": None, "field": "f"},
            "missing field": {"operation": "wrap"},
            "empty field": {"operation": "wrap", "field": ""},
            "non-string field": {"operation": "unwrap", "field": 1},
            "null field": {"operation": "unwrap", "field": None},
        }
        for key in ("request_body", "response_body"):
            for label, value in cases.items():
                doc = {"routes": [self.route({key: value})]}
                write_config(self.path, doc)
                with self.assertRaises(GatewayError, msg="%s %s" % (key, label)):
                    load(self.path)

    def test_omitted_body_transforms_default_to_none_and_stay_hidden(self):
        write_config(self.path, {"routes": [self.route({})]})
        route = load(self.path).routes[0]
        self.assertIsNone(route.request_body)
        self.assertIsNone(route.response_body)
        self.assertNotIn("request_body", route.to_dict()["transform"])
        self.assertNotIn("response_body", route.to_dict()["transform"])

    def test_body_transforms_round_trip(self):
        transform = {"request_body": {"operation": "wrap", "field": "data"},
                     "response_body": {"operation": "unwrap", "field": "result"}}
        write_config(self.path, {"routes": [self.route(transform)]})
        route = load(self.path).routes[0]
        self.assertEqual(route.request_body, {"operation": "wrap", "field": "data"})
        self.assertEqual(route.response_body, {"operation": "unwrap", "field": "result"})
        self.assertEqual(route.to_dict()["transform"]["request_body"],
                         {"operation": "wrap", "field": "data"})
        self.assertEqual(route.to_dict()["transform"]["response_body"],
                         {"operation": "unwrap", "field": "result"})

    def test_route_add_rejects_bad_transform_without_changing_state(self):
        gateway, root, _ = make_gateway()
        self.addCleanup(shutil.rmtree, root, True)
        before = json.dumps(gateway.sanitized_config(), sort_keys=True)
        revision = gateway.store.revision
        with self.assertRaises(GatewayError):
            gateway.add_route({"id": "r-bad", "tenant": "acme",
                               "match": {"method": "POST", "path_prefix": "/bad"},
                               "upstream": "echo",
                               "transform": {"request_body": {"operation": "fold",
                                                              "field": "f"}}})
        self.assertEqual(json.dumps(gateway.sanitized_config(), sort_keys=True), before)
        self.assertEqual(gateway.store.revision, revision)

    def test_invalid_reload_keeps_the_last_good_config(self):
        gateway, root, path = make_gateway()
        self.addCleanup(shutil.rmtree, root, True)
        doc = document()
        doc["routes"][0]["transform"]["request_body"] = {"operation": "wrap"}  # no field
        write_config(path, doc)
        self.assertFalse(gateway.reload_config())
        self.assertFalse(gateway.store.ready)
        route = next(r for r in gateway.config.routes if r.id == "r-wrap")
        self.assertEqual(route.request_body, {"operation": "wrap", "field": "data"})

    def test_sanitized_config_echoes_body_transforms(self):
        gateway, root, _ = make_gateway()
        self.addCleanup(shutil.rmtree, root, True)
        routes = {r["id"]: r for r in gateway.sanitized_config()["routes"]}
        self.assertEqual(routes["r-wrap"]["transform"]["request_body"],
                         {"operation": "wrap", "field": "data"})
        self.assertEqual(routes["r-unwrap"]["transform"]["response_body"],
                         {"operation": "unwrap", "field": "result"})
        self.assertNotIn("request_body", routes["r-plain"]["transform"])
        self.assertNotIn("response_body", routes["r-plain"]["transform"])


class RequestBodyTransformTest(unittest.TestCase):
    def setUp(self):
        self.gateway, self.root, self.path = make_gateway()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.calls = []

        def capture(request):
            self.calls.append(request)
            return {"status": 200, "body": {"result": {"echo": request["body"]}}}

        self.gateway.upstreams.register("capture", capture)

    def body_of(self, response):
        return json.loads(response["body"])

    def test_wrap_places_any_json_value_under_the_field(self):
        response = self.gateway.handle("acme", "POST", "/wrap/x", {}, '{"a": 1}', now_ms=0)
        self.assertEqual(response["status"], 200)
        self.assertEqual(json.loads(self.calls[-1]["body"]), {"data": {"a": 1}})
        self.gateway.handle("acme", "POST", "/wrap/x", {}, '[1, 2]', now_ms=1)
        self.assertEqual(json.loads(self.calls[-1]["body"]), {"data": [1, 2]})
        self.gateway.handle("acme", "POST", "/wrap/x", {}, '5', now_ms=2)
        self.assertEqual(json.loads(self.calls[-1]["body"]), {"data": 5})
        self.gateway.handle("acme", "POST", "/wrap/x", {}, 'null', now_ms=3)
        self.assertEqual(json.loads(self.calls[-1]["body"]), {"data": None})

    def test_unwrap_replaces_the_body_with_the_field_value(self):
        response = self.gateway.handle("acme", "POST", "/unwrap/x", {},
                                       '{"data": {"a": 1}, "meta": true}', now_ms=0)
        self.assertEqual(response["status"], 200)
        self.assertEqual(json.loads(self.calls[-1]["body"]), {"a": 1})
        self.gateway.handle("acme", "POST", "/unwrap/x", {}, '{"data": null}', now_ms=1)
        self.assertEqual(self.calls[-1]["body"], "null")

    def test_invalid_request_bodies_are_400_without_an_upstream_call(self):
        for bad in ("", "{not json", "   "):
            response = self.gateway.handle("acme", "POST", "/wrap/x", {}, bad, now_ms=0)
            self.assertEqual(response["status"], 400, msg=repr(bad))
            payload = self.body_of(response)
            self.assertEqual(payload["error"], "invalid request body")
            self.assertIn("request_id", payload)
        for bad in ('[1, 2]', '"text"', "5", '{"other": 1}'):
            response = self.gateway.handle("acme", "POST", "/unwrap/x", {}, bad, now_ms=0)
            self.assertEqual(response["status"], 400, msg=repr(bad))
            self.assertEqual(self.body_of(response)["error"], "invalid request body")
        self.assertEqual(len(self.calls), 0)
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual((entry["status"], entry["attempts"]), (400, 0))

    def test_rejected_body_is_still_billed_exactly_once(self):
        response = self.gateway.handle("acme", "POST", "/wrap/x", {}, "{", now_ms=0)
        self.assertEqual(response["status"], 400)
        usage = self.gateway.usage("acme")
        self.assertEqual((usage["requests"], usage["allowed"]), (1, 1))

    def test_transformed_body_is_sent_on_every_retry_and_failover(self):
        doc = document()
        doc["routes"].append({"id": "r-fb", "tenant": "acme",
                              "match": {"method": "GET", "path_prefix": "/fb"},
                              "upstream": "primary", "auth_required": False,
                              "fallback_upstreams": ["backup"],
                              "transform": {"request_body": {"operation": "wrap",
                                                             "field": "data"}}})
        gateway, root, _ = make_gateway(doc)
        self.addCleanup(shutil.rmtree, root, True)
        seen = {"primary": [], "backup": []}

        def register(name, fn):
            def counting(request, _fn=fn, _name=name):
                seen[_name].append(request["body"])
                return _fn(request)
            gateway.upstreams.register(name, counting)

        attempts = []

        def flaky(request):
            attempts.append(request)
            if len(attempts) < 3:
                raise UpstreamError("boom")
            return {"status": 200, "body": "{}"}

        register("primary", flaky)
        register("backup", lambda request: {"status": 200, "body": "{}"})
        response = gateway.handle("acme", "GET", "/fb/x", {}, '{"v": 1}', now_ms=0)
        self.assertEqual(response["status"], 200)
        self.assertEqual(seen["primary"], ['{"data": {"v": 1}}'] * 3)
        self.assertEqual(seen["backup"], [])

    def test_idempotency_hash_covers_the_original_body(self):
        headers = {"x-idempotency-key": "idem-body"}
        first = self.gateway.handle("acme", "POST", "/wrap/x", headers, '{"a": 1}', now_ms=0)
        replay = self.gateway.handle("acme", "POST", "/wrap/x", headers, '{"a": 1}', now_ms=1)
        self.assertEqual((first["status"], replay["status"]), (200, 200))
        self.assertEqual(replay["headers"]["X-Idempotent-Replay"], "true")
        self.assertEqual(len(self.calls), 1)
        # a different original body conflicts even though it wraps differently
        conflict = self.gateway.handle("acme", "POST", "/wrap/x", headers, '{"a": 2}', now_ms=2)
        self.assertEqual(conflict["status"], 409)

    def test_rejected_body_never_occupies_an_idempotency_scope(self):
        headers = {"x-idempotency-key": "idem-bad"}
        rejected = self.gateway.handle("acme", "POST", "/wrap/x", headers, "{", now_ms=0)
        self.assertEqual(rejected["status"], 400)
        ok = self.gateway.handle("acme", "POST", "/wrap/x", headers, '{"a": 1}', now_ms=1)
        self.assertEqual(ok["status"], 200)
        self.assertNotIn("X-Idempotent-Replay", ok["headers"])
        self.assertEqual(len(self.calls), 1)


class ResponseBodyTransformTest(unittest.TestCase):
    def setUp(self):
        self.gateway, self.root, self.path = make_gateway()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.calls = []
        self.next_response = {"status": 200, "body": {"result": {"a": 1}}}

        def capture(request):
            self.calls.append(request)
            return self.next_response

        self.gateway.upstreams.register("capture", capture)

    def body_of(self, response):
        return json.loads(response["body"])

    def test_wrap_response_keeps_the_status_and_outputs_json(self):
        self.next_response = {"status": 201, "body": {"a": 1}}
        response = self.gateway.handle("acme", "GET", "/resp/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 201)
        self.assertEqual(self.body_of(response), {"result": {"a": 1}})

    def test_unwrap_response_outputs_the_field_value(self):
        response = self.gateway.handle("acme", "POST", "/unwrap/x", {},
                                       '{"data": 1}', now_ms=0)
        self.assertEqual(response["status"], 200)
        self.assertEqual(self.body_of(response), {"a": 1})
        self.next_response = {"status": 200, "body": {"result": [1, 2]}}
        response = self.gateway.handle("acme", "POST", "/unwrap/x", {},
                                       '{"data": 1}', now_ms=1)
        self.assertEqual(json.loads(response["body"]), [1, 2])

    def test_invalid_upstream_body_is_502_and_never_cached(self):
        self.next_response = {"status": 200, "body": "not json"}
        headers = {"x-idempotency-key": "idem-resp"}
        response = self.gateway.handle("acme", "GET", "/resp/x", headers, "", now_ms=0)
        self.assertEqual(response["status"], 502)
        payload = self.body_of(response)
        self.assertEqual(payload["error"], "invalid upstream response body")
        self.assertIn("request_id", payload)
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual((entry["status"], entry["attempts"]), (502, 1))
        # nothing was cached: the next request with the same key executes again
        self.next_response = {"status": 200, "body": {"ok": True}}
        second = self.gateway.handle("acme", "GET", "/resp/x", headers, "", now_ms=1)
        self.assertEqual(second["status"], 200)
        self.assertNotIn("X-Idempotent-Replay", second["headers"])
        self.assertEqual(len(self.calls), 2)

    def test_unwrap_response_requires_an_object_with_the_field(self):
        for bad in ("[1, 2]", '"text"', '{"other": 1}'):
            self.next_response = {"status": 200, "body": bad}
            response = self.gateway.handle("acme", "POST", "/unwrap/x", {},
                                           '{"data": 1}', now_ms=0)
            self.assertEqual(response["status"], 502, msg=bad)
            self.assertEqual(self.body_of(response)["error"],
                             "invalid upstream response body")

    def test_5xx_responses_are_not_transformed(self):
        self.next_response = {"status": 500, "body": "boom"}
        response = self.gateway.handle("acme", "GET", "/resp/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 500)
        self.assertEqual(response["body"], "boom")

    def test_route_without_a_response_transform_passes_the_body_through(self):
        self.next_response = {"status": 200, "body": "not json"}
        response = self.gateway.handle("acme", "POST", "/plain/x", {}, "raw", now_ms=0)
        self.assertEqual(response["status"], 200)
        self.assertEqual(response["body"], "not json")

    def test_transform_runs_once_on_the_final_response_after_retries(self):
        outcomes = [{"status": 503, "body": "starting"},
                    {"status": 503, "body": "starting"},
                    {"status": 200, "body": {"done": True}}]

        def flappy(request):
            self.calls.append(request)
            return outcomes[min(len(self.calls), 3) - 1]

        self.gateway.upstreams.register("capture", flappy)
        response = self.gateway.handle("acme", "GET", "/resp/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 200)
        self.assertEqual(self.body_of(response), {"result": {"done": True}})
        self.assertEqual(self.gateway.audit("acme", 1)[0]["attempts"], 3)

    def test_idempotency_cache_stores_the_transformed_response(self):
        self.next_response = {"status": 200, "body": {"a": 1}}
        headers = {"x-idempotency-key": "idem-cache"}
        first = self.gateway.handle("acme", "GET", "/resp/x", headers, "", now_ms=0)
        replay = self.gateway.handle("acme", "GET", "/resp/x", headers, "", now_ms=1)
        self.assertEqual((first["status"], replay["status"]), (200, 200))
        self.assertEqual(self.body_of(first), {"result": {"a": 1}})
        self.assertEqual(replay["body"], first["body"])
        self.assertEqual(replay["headers"]["X-Idempotent-Replay"], "true")
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main()
