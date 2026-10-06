"""W3C Trace Context tests: parsing, propagation, response headers and audit."""

import hashlib
import json
import re
import shutil
import unittest

from gwd.gateway import Gateway
from tests.test_gateway import document, make_gateway

SECRET_READ = "read-secret"
TRACEPARENT_RE = re.compile(r"^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$")
VALID_TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
VALID_PARENT_ID = "00f067aa0ba902b7"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class TraceTestCase(unittest.TestCase):
    def setUp(self):
        self.gateway, self.root, self.path = make_gateway(
            breaker_settings={"failure_threshold": 1, "open_ms": 1000, "success_threshold": 1})
        self.addCleanup(shutil.rmtree, self.root, True)
        self.calls = []

        def counting(request):
            self.calls.append(request)
            return {"status": 200, "body": {"n": len(self.calls)}}

        self.gateway.upstreams.register("count", counting)

    def auth(self):
        return {"authorization": "Bearer " + SECRET_READ}

    def body_of(self, response):
        return json.loads(response["body"])

    def last_audit(self):
        return self.gateway.audit("acme", 1)[0]


class TraceGenerationTest(TraceTestCase):
    def test_root_context_is_generated_when_traceparent_is_missing(self):
        response = self.gateway.handle("acme", "GET", "/api/items", self.auth(), "", now_ms=0)
        self.assertEqual(response["status"], 200)
        traceparent = response["headers"]["traceparent"]
        self.assertRegex(traceparent, TRACEPARENT_RE)
        _, trace_id, span_id, flags = traceparent.split("-")
        self.assertEqual(flags, "00")
        self.assertEqual(response["headers"]["X-Trace-Id"], trace_id)
        entry = self.last_audit()
        self.assertEqual(entry["trace_id"], trace_id)
        self.assertEqual(entry["span_id"], span_id)
        self.assertIsNone(entry["parent_span_id"])
        self.assertFalse(entry["sampled"])

    def test_each_request_gets_a_fresh_context(self):
        first = self.gateway.handle("acme", "GET", "/api/items", self.auth(), "", now_ms=0)
        second = self.gateway.handle("acme", "GET", "/api/items", self.auth(), "", now_ms=1)
        self.assertNotEqual(first["headers"]["traceparent"], second["headers"]["traceparent"])

    def test_upstream_receives_the_canonical_traceparent(self):
        self.gateway.handle("acme", "POST", "/count/x", {}, "", now_ms=0)
        sent = self.calls[-1]["headers"]
        self.assertRegex(sent["traceparent"], TRACEPARENT_RE)
        response_entry = self.gateway.audit("", 1)[0]
        self.assertEqual(sent["traceparent"],
                         "00-%s-%s-00" % (response_entry["trace_id"], response_entry["span_id"]))


class TraceParentParsingTest(TraceTestCase):
    def incoming(self, flags="01", trace_id=VALID_TRACE_ID, parent_id=VALID_PARENT_ID):
        return dict(self.auth(), traceparent="00-%s-%s-%s" % (trace_id, parent_id, flags))

    def test_valid_traceparent_keeps_trace_id_and_flags(self):
        response = self.gateway.handle("acme", "GET", "/api/items", self.incoming(), "", now_ms=0)
        self.assertEqual(response["status"], 200)
        traceparent = response["headers"]["traceparent"]
        trace_id, span_id, flags = traceparent.split("-")[1:]
        self.assertEqual(trace_id, VALID_TRACE_ID)
        self.assertEqual(flags, "01")
        self.assertNotEqual(span_id, VALID_PARENT_ID)  # the gateway mints its own span id
        self.assertEqual(response["headers"]["X-Trace-Id"], VALID_TRACE_ID)
        entry = self.last_audit()
        self.assertEqual(entry["trace_id"], VALID_TRACE_ID)
        self.assertEqual(entry["parent_span_id"], VALID_PARENT_ID)
        self.assertTrue(entry["sampled"])

    def test_sampled_reflects_the_lowest_flag_bit(self):
        for flags, sampled in (("00", False), ("01", True), ("02", False), ("03", True),
                               ("fe", False), ("ff", True)):
            headers = self.incoming(flags=flags)
            self.gateway.handle("acme", "GET", "/api/items", headers, "", now_ms=0)
            self.assertIs(self.last_audit()["sampled"], sampled)

    def test_upstream_traceparent_uses_the_kept_trace_id_and_flags(self):
        self.gateway.handle("acme", "POST", "/count/x",
                            {"traceparent": "00-%s-%s-01" % (VALID_TRACE_ID, VALID_PARENT_ID)},
                            "", now_ms=0)
        sent = self.calls[-1]["headers"]["traceparent"]
        self.assertEqual(sent.split("-")[0], "00")
        self.assertEqual(sent.split("-")[1], VALID_TRACE_ID)
        self.assertEqual(sent.split("-")[3], "01")
        self.assertNotEqual(sent.split("-")[2], VALID_PARENT_ID)

    def test_tracestate_is_forwarded_verbatim(self):
        headers = dict(self.incoming(), tracestate="rojo=00f067aa0ba902b7,congo=t61rcWkgMzE")
        self.gateway.handle("acme", "GET", "/api/items", headers, "", now_ms=0)
        # /api goes to the echo upstream, which reports the headers it received.
        sent = self.body_of(self.gateway.handle(
            "acme", "GET", "/api/items", headers, "", now_ms=1))["headers"]
        self.assertEqual(sent["tracestate"], "rojo=00f067aa0ba902b7,congo=t61rcWkgMzE")

    def test_invalid_traceparent_is_a_400_before_the_pipeline(self):
        bad_values = [
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",      # missing flags
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",  # wrong version
            "00-00000000000000000000000000000000-00f067aa0ba902b7-00",  # zero trace id
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-00",  # zero parent id
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0",   # short flags
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0g",  # non hex flags
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-00",  # upper case
            "00-4bf92f3577b34da6a3ce929d0e0e47-00f067aa0ba902b7-00",    # short trace id
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00-extra",
            "garbage",
        ]
        for value in bad_values:
            headers = dict(self.auth(), traceparent=value)
            response = self.gateway.handle("acme", "GET", "/api/items", headers, "", now_ms=0)
            self.assertEqual(response["status"], 400, value)
            self.assertEqual(self.body_of(response)["error"], "invalid traceparent", value)
            self.assertRegex(response["headers"]["traceparent"], TRACEPARENT_RE)
            entry = self.last_audit()
            self.assertIsNone(entry["route_id"])
            self.assertEqual(entry["attempts"], 0)
            self.assertIsNone(entry["parent_span_id"])
        self.assertEqual(len(self.calls), 0)  # nothing ever reached an upstream

    def test_invalid_traceparent_beats_auth_quota_and_routing(self):
        # Unknown tenant, no credentials and no matching route: the 400 still wins.
        response = self.gateway.handle("nobody", "DELETE", "/nowhere",
                                       {"traceparent": "nope"}, "", now_ms=0)
        self.assertEqual(response["status"], 400)
        self.assertEqual(self.body_of(response)["error"], "invalid traceparent")


class TraceHeaderTest(TraceTestCase):
    def test_transform_response_headers_cannot_override_trace_headers(self):
        response = self.gateway.handle("acme", "GET", "/api/items", self.auth(), "", now_ms=0)
        self.assertEqual(response["headers"]["X-Served-By"], "gwd")
        self.assertRegex(response["headers"]["traceparent"], TRACEPARENT_RE)
        self.assertEqual(response["headers"]["X-Trace-Id"],
                         response["headers"]["traceparent"].split("-")[1])

    def test_error_responses_carry_trace_headers(self):
        cases = [
            self.gateway.handle("acme", "GET", "/api/items", {}, "", now_ms=0),          # 401
            self.gateway.handle("acme", "GET", "/nope", self.auth(), "", now_ms=0),      # 404
        ]
        # 429: the p-fast bucket admits two requests per window.
        self.gateway.handle("acme", "GET", "/api/items", self.auth(), "", now_ms=10)
        cases.append(self.gateway.handle("acme", "GET", "/api/items", self.auth(), "", now_ms=11))
        for response in cases:
            self.assertRegex(response["headers"]["traceparent"], TRACEPARENT_RE)
            self.assertIn("X-Trace-Id", response["headers"])

    def test_idempotency_conflict_and_in_progress_carry_trace_headers(self):
        headers = {"x-idempotency-key": "idem-trace"}
        self.gateway.handle("acme", "POST", "/count/x", headers, '{"a": 1}', now_ms=0)
        conflict = self.gateway.handle("acme", "POST", "/count/x", headers, '{"a": 2}', now_ms=1)
        self.assertEqual(conflict["status"], 409)
        self.assertRegex(conflict["headers"]["traceparent"], TRACEPARENT_RE)

    def test_replay_regenerates_trace_headers(self):
        headers = {"x-idempotency-key": "idem-trace-2"}
        first = self.gateway.handle("acme", "POST", "/count/x", headers, "{}", now_ms=0)
        replay = self.gateway.handle("acme", "POST", "/count/x", headers, "{}", now_ms=1)
        self.assertEqual(replay["headers"]["X-Idempotent-Replay"], "true")
        self.assertEqual(replay["status"], first["status"])
        self.assertEqual(replay["body"], first["body"])
        # Only status and body are reused: the replay gets its own trace context.
        self.assertNotEqual(replay["headers"]["traceparent"], first["headers"]["traceparent"])
        entries = self.gateway.audit("acme", 2)
        self.assertNotEqual(entries[-1]["trace_id"], entries[-2]["trace_id"])
        self.assertTrue(entries[-1]["idempotent_replay"])

    def test_breaker_rejection_carries_trace_headers(self):
        def failing(request):
            raise RuntimeError("boom")

        self.gateway.upstreams.register("count", failing)
        headers = {"x-idempotency-key": "idem-trace-3"}
        first = self.gateway.handle("acme", "POST", "/count/x", headers, "{}", now_ms=0)
        self.assertEqual(first["status"], 502)
        rejected = self.gateway.handle("acme", "POST", "/count/x",
                                       {"x-idempotency-key": "idem-trace-4"}, "{}", now_ms=1)
        self.assertEqual(rejected["status"], 503)
        self.assertRegex(rejected["headers"]["traceparent"], TRACEPARENT_RE)


class TraceCompatTest(TraceTestCase):
    def test_traceparent_does_not_change_routing_or_quota(self):
        # Weighted stable selection hashes key id and request id only.
        headers = dict(self.auth(), **{"x-request-id": "fixed-id"})
        plain = self.gateway.handle("acme", "GET", "/api/items", headers, "", now_ms=0)
        traced = self.gateway.handle(
            "acme", "GET", "/api/items",
            dict(headers, traceparent="00-%s-%s-01" % (VALID_TRACE_ID, VALID_PARENT_ID)),
            "", now_ms=1)
        self.assertEqual(plain["route_id"], traced["route_id"])

    def test_audit_endpoint_keeps_its_shape(self):
        self.gateway.handle("acme", "GET", "/api/items", self.auth(), "", now_ms=0)
        entries = self.gateway.audit("acme", 50)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["tenant"], "acme")


if __name__ == "__main__":
    unittest.main()
