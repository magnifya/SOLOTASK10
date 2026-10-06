"""Request/response JSON body transforms: wrap and unwrap on route.transform."""

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


def write_config(path, doc):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle)
    stat = os.stat(path)
    os.utime(path, ns=(stat.st_atime_ns + 1_000_000, stat.st_mtime_ns + 1_000_000))


def route(route_id, prefix, transform=None, **extra):
    out = {"id": route_id, "tenant": "acme",
           "match": {"method": "POST", "path_prefix": prefix},
           "upstream": "up", "auth_required": False}
    if transform is not None:
        out["transform"] = transform
    out.update(extra)
    return out


def document():
    return {
        "quota_policies": [
            {"id": "p-fast", "tenant": "acme", "algorithm": "token-bucket",
             "limit": 5, "window_ms": 60000, "burst": 5}],
        "keys": [],
        "routes": [
            route("r-wrap", "/wrap",
                  {"request_body": {"operation": "wrap", "field": "payload"}}),
            route("r-unwrap", "/unwrap",
                  {"request_body": {"operation": "unwrap", "field": "payload"}}),
            route("r-resp-wrap", "/resp-wrap",
                  {"response_body": {"operation": "wrap", "field": "result"}}),
            route("r-resp-unwrap", "/resp-unwrap",
                  {"response_body": {"operation": "unwrap", "field": "result"}}),
            route("r-quota", "/quota",
                  {"request_body": {"operation": "wrap", "field": "payload"}},
                  quota_policy="p-fast"),
            route("r-plain", "/plain"),
        ],
    }


class BodyTransformTestCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-body-transform-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = os.path.join(self.root, "config.json")
        write_config(self.path, document())
        self.gateway = Gateway(config_path=self.path,
                               data_dir=os.path.join(self.root, "data"))
        self.calls = []
        self.next_response = {"status": 200, "body": {"ok": True}}

        def upstream(request):
            self.calls.append(request)
            return self.next_response

        self.gateway.upstreams.register("up", upstream)

    def body_of(self, response):
        return json.loads(response["body"])

    def call(self, prefix, body="{}", headers=None, now_ms=0):
        return self.gateway.handle("acme", "POST", prefix + "/x", headers or {},
                                   body, now_ms=now_ms)


class RequestWrapTest(BodyTransformTestCase):
    def test_wrap_nests_any_json_value_under_the_field(self):
        response = self.call("/wrap", "[1, 2]")
        self.assertEqual(response["status"], 200)
        self.assertEqual(self.calls[0]["body"], '{"payload": [1, 2]}')

    def test_wrap_accepts_scalars_and_objects(self):
        for raw, expected in (("1", '{"payload": 1}'),
                              ('"s"', '{"payload": "s"}'),
                              ("null", '{"payload": null}'),
                              ('{"a": 1}', '{"payload": {"a": 1}}')):
            self.calls.clear()
            self.assertEqual(self.call("/wrap", raw)["status"], 200)
            self.assertEqual(self.calls[0]["body"], expected)

    def test_unwrap_lifts_the_field_value(self):
        response = self.call("/unwrap", '{"payload": {"a": 1}, "other": 2}')
        self.assertEqual(response["status"], 200)
        self.assertEqual(self.calls[0]["body"], '{"a": 1}')

    def test_unwrap_allows_any_json_value_in_the_field(self):
        self.assertEqual(self.call("/unwrap", '{"payload": null}')["status"], 200)
        self.assertEqual(self.calls[0]["body"], "null")

    def test_invalid_request_bodies_are_400_without_an_upstream_call(self):
        for bad in ("", "   ", "{", "not json"):
            with self.subTest(bad=bad):
                response = self.call("/wrap", bad)
                self.assertEqual(response["status"], 400)
                payload = self.body_of(response)
                self.assertEqual(payload["error"], "invalid request body")
                self.assertEqual(payload["request_id"], response["request_id"])
        self.assertEqual(self.calls, [])

    def test_unwrap_rejects_non_objects_and_missing_fields(self):
        for bad in ("[1]", "1", '"s"', "null", '{"other": 1}'):
            with self.subTest(bad=bad):
                response = self.call("/unwrap", bad)
                self.assertEqual(response["status"], 400)
                self.assertEqual(self.body_of(response)["error"],
                                 "invalid request body")
        self.assertEqual(self.calls, [])

    def test_rejection_is_audited_with_zero_attempts(self):
        response = self.call("/wrap", "{")
        self.assertEqual(response["status"], 400)
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual((entry["status"], entry["attempts"], entry["route_id"]),
                         (400, 0, "r-wrap"))

    def test_rejection_charges_quota_exactly_once(self):
        response = self.call("/quota", "{")
        self.assertEqual(response["status"], 400)
        usage = self.gateway.usage("acme")
        self.assertEqual((usage["requests"], usage["allowed"]), (1, 1))

    def test_rejection_writes_no_idempotency_state(self):
        headers = {"x-idempotency-key": "k-bad"}
        first = self.call("/wrap", "{", headers)
        second = self.call("/wrap", "{", headers, now_ms=1)
        # No in-flight marker or cache entry survived: both are plain 400s.
        self.assertEqual((first["status"], second["status"]), (400, 400))
        third = self.call("/wrap", "1", headers, now_ms=2)
        self.assertEqual(third["status"], 200)

    def test_idempotency_is_judged_on_the_original_body(self):
        headers = {"x-idempotency-key": "k-orig"}
        first = self.call("/unwrap", '{"payload": 1}', headers)
        # A different original body unwrapping to the same upstream body still
        # conflicts: the hash covers what the client sent, not the transform.
        conflict = self.call("/unwrap", '{"payload": 1, "extra": 2}', headers, now_ms=1)
        replay = self.call("/unwrap", '{"payload": 1}', headers, now_ms=2)
        self.assertEqual(first["status"], 200)
        self.assertEqual(conflict["status"], 409)
        self.assertEqual(replay["status"], 200)
        self.assertEqual(replay["headers"]["X-Idempotent-Replay"], "true")
        self.assertEqual(len(self.calls), 1)

    def test_transformed_body_rides_retries_and_failover(self):
        seen = []

        def flaky(request):
            seen.append(request["body"])
            if len(seen) < 2:
                raise UpstreamError("boom")
            return {"status": 200, "body": "{}"}

        self.gateway.upstreams.register("flaky", flaky)
        self.gateway.add_route(route("r-flaky", "/flaky",
                                     {"request_body": {"operation": "wrap",
                                                       "field": "payload"}},
                                     upstream="flaky", fallback_upstreams=[]))
        response = self.call("/flaky", "1")
        self.assertEqual(response["status"], 200)
        self.assertEqual(seen, ['{"payload": 1}', '{"payload": 1}'])

    def test_route_without_body_transform_passes_the_body_through(self):
        response = self.call("/plain", "not json at all")
        self.assertEqual(response["status"], 200)
        self.assertEqual(self.calls[0]["body"], "not json at all")


class ResponseTransformTest(BodyTransformTestCase):
    def test_wrap_nests_the_upstream_json_and_keeps_the_status(self):
        self.next_response = {"status": 201, "body": {"a": 1}}
        response = self.call("/resp-wrap")
        self.assertEqual(response["status"], 201)
        self.assertEqual(self.body_of(response), {"result": {"a": 1}})

    def test_unwrap_lifts_the_field_value(self):
        self.next_response = {"status": 200, "body": {"result": [1, 2], "meta": 0}}
        response = self.call("/resp-unwrap")
        self.assertEqual(response["status"], 200)
        self.assertEqual(self.body_of(response), [1, 2])

    def test_non_json_upstream_body_is_502(self):
        for bad in ("", "not json", "{"):
            with self.subTest(bad=bad):
                self.next_response = {"status": 200, "body": bad}
                response = self.call("/resp-wrap")
                self.assertEqual(response["status"], 502)
                payload = self.body_of(response)
                self.assertEqual(payload["error"], "invalid upstream response body")
                self.assertEqual(payload["request_id"], response["request_id"])

    def test_unwrap_rejects_non_objects_and_missing_fields(self):
        for bad in ("[1]", "1", '{"other": 1}'):
            with self.subTest(bad=bad):
                self.next_response = {"status": 200, "body": bad}
                response = self.call("/resp-unwrap")
                self.assertEqual(response["status"], 502)
                self.assertEqual(self.body_of(response)["error"],
                                 "invalid upstream response body")

    def test_502_keeps_the_attempt_count_and_is_not_cached(self):
        headers = {"x-idempotency-key": "k-resp"}
        self.next_response = {"status": 200, "body": "not json"}
        first = self.call("/resp-wrap", "{}", headers)
        self.assertEqual(first["status"], 502)
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual((entry["status"], entry["attempts"]), (502, 1))
        # The failure was not cached: the retry reaches the upstream again.
        self.next_response = {"status": 200, "body": {"ok": True}}
        second = self.call("/resp-wrap", "{}", headers, now_ms=1)
        self.assertEqual(second["status"], 200)
        self.assertNotIn("X-Idempotent-Replay", second["headers"])
        self.assertEqual(len(self.calls), 2)

    def test_5xx_passes_through_untransformed(self):
        self.next_response = {"status": 500, "body": "not json"}
        response = self.call("/resp-wrap")
        self.assertEqual(response["status"], 500)
        self.assertEqual(response["body"], "not json")

    def test_transformed_response_is_cached_and_replayed(self):
        headers = {"x-idempotency-key": "k-cache"}
        self.next_response = {"status": 200, "body": {"a": 1}}
        first = self.call("/resp-wrap", "{}", headers)
        replay = self.call("/resp-wrap", "{}", headers, now_ms=1)
        self.assertEqual(first["status"], 200)
        self.assertEqual(replay["headers"]["X-Idempotent-Replay"], "true")
        self.assertEqual(self.body_of(replay), {"result": {"a": 1}})
        self.assertEqual(len(self.calls), 1)  # the replay never hit the upstream

    def test_transform_applies_once_to_the_final_failover_response(self):
        self.gateway.upstreams.register("down",
                                        lambda request: (_ for _ in ()).throw(
                                            UpstreamError("boom")))
        self.gateway.add_route(route("r-fb", "/fb",
                                     {"response_body": {"operation": "wrap",
                                                        "field": "result"}},
                                     upstream="down", fallback_upstreams=["up"]))
        self.next_response = {"status": 200, "body": {"a": 1}}
        response = self.call("/fb", "{}", {"x-idempotency-key": "k-fb"})
        self.assertEqual(response["status"], 200)
        self.assertEqual(self.body_of(response), {"result": {"a": 1}})


class BodyTransformConfigTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-body-config-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = os.path.join(self.root, "config.json")

    def load_routes(self, transform):
        write_config(self.path, {"routes": [route("r", "/a", transform)]})
        return load(self.path).routes[0]

    def test_valid_transforms_round_trip(self):
        loaded = self.load_routes({"request_body": {"operation": "wrap", "field": "p"},
                                   "response_body": {"operation": "unwrap", "field": "q"},
                                   "request_headers": {"X-A": "1"}})
        self.assertEqual(loaded.request_body.to_dict(),
                         {"operation": "wrap", "field": "p"})
        self.assertEqual(loaded.response_body.to_dict(),
                         {"operation": "unwrap", "field": "q"})
        out = loaded.to_dict()["transform"]
        self.assertEqual(out["request_body"], {"operation": "wrap", "field": "p"})
        self.assertEqual(out["response_body"], {"operation": "unwrap", "field": "q"})
        self.assertEqual(out["request_headers"], {"X-A": "1"})

    def test_omitted_body_transforms_keep_the_legacy_shape(self):
        loaded = self.load_routes({"request_headers": {"X-A": "1"}})
        self.assertIsNone(loaded.request_body)
        self.assertIsNone(loaded.response_body)
        self.assertEqual(loaded.to_dict()["transform"],
                         {"request_headers": {"X-A": "1"}, "response_headers": {}})

    def test_malformed_body_transforms_are_rejected(self):
        cases = {
            "null": None,
            "not an object": "wrap",
            "extra key": {"operation": "wrap", "field": "p", "mode": "x"},
            "missing operation": {"field": "p"},
            "missing field": {"operation": "wrap"},
            "bad operation": {"operation": "nest", "field": "p"},
            "non-string field": {"operation": "wrap", "field": 1},
            "empty field": {"operation": "unwrap", "field": ""},
        }
        for label, value in cases.items():
            for key in ("request_body", "response_body"):
                with self.subTest(label=label, key=key):
                    with self.assertRaises(GatewayError):
                        self.load_routes({key: value})

    def test_route_add_rejects_bad_transforms_without_changing_state(self):
        write_config(self.path, document())
        gateway = Gateway(config_path=self.path,
                          data_dir=os.path.join(self.root, "data"))
        before = json.dumps(gateway.sanitized_config(), sort_keys=True)
        revision = gateway.store.revision
        bad = route("r-bad", "/bad",
                    {"request_body": {"operation": "nest", "field": "p"}})
        with self.assertRaises(GatewayError):
            gateway.add_route(bad)
        with self.assertRaises(GatewayError):
            gateway.add_route([route("r-ok", "/ok"), bad])
        self.assertEqual(json.dumps(gateway.sanitized_config(), sort_keys=True), before)
        self.assertEqual(gateway.store.revision, revision)
        with open(self.path, "r", encoding="utf-8") as handle:
            self.assertNotIn("r-bad", handle.read())

    def test_invalid_hot_reload_keeps_the_last_good_config(self):
        write_config(self.path, document())
        gateway = Gateway(config_path=self.path,
                          data_dir=os.path.join(self.root, "data"))
        revision = gateway.store.revision
        doc = document()
        doc["routes"].append(route("r-bad", "/bad",
                                   {"response_body": {"operation": "wrap"}}))
        write_config(self.path, doc)
        self.assertFalse(gateway.reload_config())
        self.assertFalse(gateway.store.ready)
        self.assertEqual(gateway.store.revision, revision)
        self.assertNotIn("r-bad", {r.id for r in gateway.config.routes})

    def test_sanitized_config_echoes_body_transforms(self):
        write_config(self.path, document())
        gateway = Gateway(config_path=self.path,
                          data_dir=os.path.join(self.root, "data"))
        routes = {r["id"]: r for r in gateway.sanitized_config()["routes"]}
        self.assertEqual(routes["r-wrap"]["transform"]["request_body"],
                         {"operation": "wrap", "field": "payload"})
        self.assertEqual(routes["r-resp-unwrap"]["transform"]["response_body"],
                         {"operation": "unwrap", "field": "result"})
        self.assertNotIn("request_body", routes["r-plain"]["transform"])
        self.assertNotIn("response_body", routes["r-plain"]["transform"])


if __name__ == "__main__":
    unittest.main()
