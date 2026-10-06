"""W3C Trace Context: local root minting, strict inbound validation, upstream
correlation on retries/failover, response headers, tracestate passthrough and
the audit correlation fields -- at the Gateway.handle level and over HTTP.
"""

import hashlib
import json
import os
import re
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from gwd.gateway import Gateway
from gwd.http_app import create_server
from gwd.tracing import TraceContext, parse_traceparent
from gwd.upstream import UpstreamError

TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
SPAN_ID_RE = re.compile(r"^[0-9a-f]{16}$")
TRACEPARENT_RE = re.compile(r"^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$")

TRACE = "0af7651916cd43dd8448eb211c80319c"
PARENT = "00f067aa0ba902b7"


def traceparent(flags="00", trace_id=TRACE, parent_id=PARENT):
    return "00-%s-%s-%s" % (trace_id, parent_id, flags)


def document():
    return {
        "quota_policies": [],
        "keys": [],
        "routes": [
            {"id": "r-open", "tenant": "*",
             "match": {"method": "GET", "path_prefix": "/t"},
             "upstream": "capture", "auth_required": False,
             # The transform must never be able to override the correlation
             # headers, neither on the upstream hop nor on the response.
             "transform": {"request_headers": {"Traceparent": "spoof-request",
                                                "tracestate": "spoof-state"},
                           "response_headers": {"traceparent": "spoof-response",
                                                "X-Trace-Id": "spoof-id",
                                                "X-Served-By": "gwd"}}},
            {"id": "r-fb", "tenant": "*", "match": {"method": "GET", "path_prefix": "/fb"},
             "upstream": "primary", "auth_required": False,
             "fallback_upstreams": ["backup"]},
        ],
    }


def write_config(path, doc):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle)


def make_gateway(doc=None, **kwargs):
    root = tempfile.mkdtemp(prefix="gwd-trace-")
    path = os.path.join(root, "config.json")
    write_config(path, document() if doc is None else doc)
    gateway = Gateway(config_path=path, data_dir=os.path.join(root, "data"), **kwargs)
    return gateway, root, path


class TraceContextTest(unittest.TestCase):
    def test_root_is_valid_and_not_sampled(self):
        ctx = TraceContext.root()
        self.assertRegex(ctx.trace_id, TRACE_ID_RE)
        self.assertRegex(ctx.span_id, SPAN_ID_RE)
        self.assertIsNone(ctx.parent_span_id)
        self.assertEqual(ctx.flags, "00")
        self.assertFalse(ctx.sampled)
        self.assertRegex(ctx.traceparent(), TRACEPARENT_RE)
        self.assertEqual(ctx.traceparent(), "00-%s-%s-00" % (ctx.trace_id, ctx.span_id))

    def test_roots_are_unique(self):
        self.assertNotEqual(TraceContext.root().trace_id, TraceContext.root().trace_id)

    def test_parse_adopts_trace_flags_and_parent(self):
        ctx = parse_traceparent(traceparent("01"))
        self.assertEqual(ctx.trace_id, TRACE)
        self.assertEqual(ctx.parent_span_id, PARENT)
        self.assertEqual(ctx.flags, "01")
        self.assertTrue(ctx.sampled)
        self.assertRegex(ctx.span_id, SPAN_ID_RE)
        self.assertNotEqual(ctx.span_id, PARENT)
        # the rendered hop keeps trace id and flags but uses the gateway span
        self.assertEqual(ctx.traceparent(), "00-%s-%s-01" % (TRACE, ctx.span_id))

    def test_sampled_reflects_the_lowest_flag_bit(self):
        self.assertTrue(parse_traceparent(traceparent("ff")).sampled)
        self.assertTrue(parse_traceparent(traceparent("03")).sampled)
        self.assertFalse(parse_traceparent(traceparent("02")).sampled)
        self.assertFalse(parse_traceparent(traceparent("fe")).sampled)

    def test_invalid_traceparents_are_rejected(self):
        bad = [
            None, "", "   ",
            "01-%s-%s-00" % (TRACE, PARENT),          # unsupported version
            "00-%s-%s-00-extra" % (TRACE, PARENT),    # trailing field
            "00-%s-%s" % (TRACE, PARENT),             # missing flags
            "00-00000000000000000000000000000000-%s-00" % PARENT,  # zero trace id
            "00-%s-0000000000000000-00" % TRACE,      # zero parent id
            "00-%s-%s-0" % (TRACE, PARENT),           # one flags digit
            "00-%s-%s-000" % (TRACE, PARENT),         # three flags digits
            "00-%s-%s-gg" % (TRACE, PARENT),          # non hex flags
            "00-" + TRACE.upper() + "-" + PARENT + "-00",          # uppercase trace
            "00-%s-%s-00 " % (TRACE, PARENT),         # trailing whitespace
            "garbage",
        ]
        for value in bad:
            with self.assertRaises(ValueError, msg=repr(value)):
                parse_traceparent(value)


class GatewayTraceTest(unittest.TestCase):
    def setUp(self):
        self.gateway, self.root, self.path = make_gateway(
            breaker_settings={"failure_threshold": 1, "open_ms": 1000,
                              "success_threshold": 1})
        self.addCleanup(shutil.rmtree, self.root, True)
        self.calls = []

        def capture(request):
            self.calls.append(dict(request["headers"]))
            return {"status": 200, "body": {"ok": True},
                    # an upstream must not be able to set correlation headers
                    "headers": {"traceparent": "from-upstream",
                                "x-trace-id": "from-upstream"}}

        self.gateway.upstreams.register("capture", capture)

    def body_of(self, response):
        return json.loads(response["body"])

    def test_missing_traceparent_mints_a_root_and_returns_correlation_headers(self):
        response = self.gateway.handle("acme", "GET", "/t/x", {}, "", now_ms=0)
        self.assertEqual(response["status"], 200)
        sent = self.calls[0]
        self.assertRegex(sent["traceparent"], TRACEPARENT_RE)
        trace_id, span_id, flags = sent["traceparent"].split("-")[1:]
        self.assertRegex(trace_id, TRACE_ID_RE)
        self.assertRegex(span_id, SPAN_ID_RE)
        self.assertEqual(flags, "00")
        self.assertEqual(response["headers"]["traceparent"], sent["traceparent"])
        self.assertEqual(response["headers"]["X-Trace-Id"], trace_id)
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual(entry["trace_id"], trace_id)
        self.assertEqual(entry["span_id"], span_id)
        self.assertIsNone(entry["parent_span_id"])
        self.assertFalse(entry["sampled"])
        self.assertNotIn("tracestate", sent)
        # unrelated transforms still apply
        self.assertEqual(response["headers"]["X-Served-By"], "gwd")

    def test_valid_traceparent_is_adopted_and_propagated(self):
        inbound = traceparent("01")
        response = self.gateway.handle("acme", "GET", "/t/x", {"traceparent": inbound},
                                       "", now_ms=0)
        self.assertEqual(response["status"], 200)
        sent = self.calls[0]
        self.assertTrue(sent["traceparent"].startswith("00-%s-" % TRACE))
        self.assertTrue(sent["traceparent"].endswith("-01"))
        gateway_span = sent["traceparent"].split("-")[2]
        self.assertRegex(gateway_span, SPAN_ID_RE)
        self.assertNotEqual(gateway_span, PARENT)
        self.assertEqual(response["headers"]["traceparent"], sent["traceparent"])
        self.assertEqual(response["headers"]["X-Trace-Id"], TRACE)
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual(entry["trace_id"], TRACE)
        self.assertEqual(entry["span_id"], gateway_span)
        self.assertEqual(entry["parent_span_id"], PARENT)
        self.assertTrue(entry["sampled"])

    def test_tracestate_is_forwarded_verbatim_and_wins_over_the_transform(self):
        response = self.gateway.handle(
            "acme", "GET", "/t/x",
            {"traceparent": traceparent("00"), "tracestate": "congo=BfRLGLwR"}, "", now_ms=0)
        self.assertEqual(response["status"], 200)
        self.assertEqual(self.calls[0]["tracestate"], "congo=BfRLGLwR")

    def test_request_transform_cannot_override_traceparent(self):
        self.gateway.handle("acme", "GET", "/t/x",
                            {"traceparent": traceparent("00")}, "", now_ms=0)
        sent = self.calls[0]
        self.assertTrue(sent["traceparent"].startswith("00-%s-" % TRACE))
        self.assertNotEqual(sent["traceparent"], "spoof-request")

    def test_response_transform_and_upstream_cannot_override_trace_headers(self):
        response = self.gateway.handle("acme", "GET", "/t/x",
                                       {"traceparent": traceparent("00")}, "", now_ms=0)
        self.assertEqual(response["headers"]["traceparent"], self.calls[0]["traceparent"])
        self.assertEqual(response["headers"]["X-Trace-Id"], TRACE)

    def test_invalid_traceparent_returns_400_and_audits_without_pipeline_side_effects(self):
        response = self.gateway.handle("acme", "GET", "/t/x",
                                       {"traceparent": "not-a-traceparent"}, "", now_ms=0)
        self.assertEqual(response["status"], 400)
        self.assertEqual(self.body_of(response)["error"], "invalid traceparent")
        self.assertIn("request_id", self.body_of(response))
        # no upstream, no quota ledger, no idempotency scope
        self.assertEqual(self.calls, [])
        self.assertEqual(self.gateway.usage("acme")["requests"], 0)
        self.assertEqual(self.gateway._idempotency, {})
        # one audit record: route_id null, attempts 0
        entries = self.gateway.audit()
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual((entry["status"], entry["attempts"], entry["route_id"]),
                         (400, 0, None))
        self.assertIsNone(entry["key_id"])
        self.assertRegex(entry["trace_id"], TRACE_ID_RE)
        self.assertIsNone(entry["parent_span_id"])
        self.assertFalse(entry["sampled"])
        # the 400 still carries the correlation headers for a fresh local root
        self.assertEqual(response["headers"]["X-Trace-Id"], entry["trace_id"])
        self.assertEqual(response["headers"]["traceparent"],
                         "00-%s-%s-00" % (entry["trace_id"], entry["span_id"]))

    def test_invalid_traceparent_skips_authentication_and_idempotency(self):
        headers = {"traceparent": "00-bad", "x-idempotency-key": "scope-x"}
        response = self.gateway.handle("acme", "GET", "/t/x", headers, "{}", now_ms=0)
        self.assertEqual(response["status"], 400)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.gateway._idempotency, {})

    def test_all_zero_trace_id_is_rejected(self):
        response = self.gateway.handle(
            "acme", "GET", "/t/x",
            {"traceparent": "00-00000000000000000000000000000000-%s-00" % PARENT},
            "", now_ms=0)
        self.assertEqual(response["status"], 400)

    def test_error_breaker_425_and_409_answers_still_carry_trace_headers(self):
        # 401 on an authed route
        doc = document()
        doc["routes"] = [r for r in doc["routes"] if r["id"] == "r-open"]
        doc["routes"][0] = {"id": "r-auth", "tenant": "*",
                            "match": {"method": "GET", "path_prefix": "/a"},
                            "upstream": "capture", "auth_required": True}
        write_config(self.path, doc)
        self.assertTrue(self.gateway.reload_config())
        unauth = self.gateway.handle("acme", "GET", "/a/x",
                                     {"traceparent": traceparent("00")}, "", now_ms=0)
        self.assertEqual(unauth["status"], 401)
        self.assertEqual(unauth["headers"]["X-Trace-Id"], TRACE)
        self.assertEqual(unauth["headers"]["traceparent"].split("-")[1], TRACE)

        # breaker-open 503 (no attempt)
        self.gateway.breakers.get("capture").record(False, 0)
        open_route = {"id": "r-open2", "tenant": "*",
                      "match": {"method": "POST", "path_prefix": "/c"},
                      "upstream": "capture", "auth_required": False}
        self.gateway.add_route(open_route)
        refused = self.gateway.handle("acme", "POST", "/c/x",
                                      {"traceparent": traceparent("00")}, "{}", now_ms=1)
        self.assertEqual(refused["status"], 503)
        self.assertEqual(refused["headers"]["X-Trace-Id"], TRACE)
        self.assertEqual(refused["headers"]["traceparent"].split("-")[1], TRACE)

        # 425 in-flight then cached replay (200)
        block_gate = threading.Event()
        entered = threading.Event()

        def blocking(request):
            entered.set()
            block_gate.wait(5)
            return {"status": 200, "body": {"ok": True}}

        self.gateway.upstreams.register("block", blocking)
        self.gateway.add_route({"id": "r-block", "tenant": "*",
                                "match": {"method": "POST", "path_prefix": "/b"},
                                "upstream": "block", "auth_required": False})

        def run():
            return self.gateway.handle(
                "acme", "POST", "/b/x",
                {"x-idempotency-key": "k", "x-request-id": "hold",
                 "traceparent": traceparent("01")}, "{}", now_ms=2)

        holder = {}
        thread = threading.Thread(target=lambda: holder.update(r=run()))
        thread.start()
        self.assertTrue(entered.wait(5))
        early = self.gateway.handle(
            "acme", "POST", "/b/x",
            {"x-idempotency-key": "k", "x-request-id": "dup",
             "traceparent": traceparent("01")}, "{}", now_ms=3)
        self.assertEqual(early["status"], 425)
        self.assertEqual(early["headers"]["X-Trace-Id"], TRACE)
        self.assertNotIn("X-Idempotent-Replay", early["headers"])
        block_gate.set()
        thread.join(5)
        self.assertEqual(holder["r"]["status"], 200)
        replay = self.gateway.handle(
            "acme", "POST", "/b/x",
            {"x-idempotency-key": "k", "x-request-id": "rep",
             "traceparent": traceparent("01")}, "{}", now_ms=4)
        self.assertEqual(replay["status"], 200)
        self.assertEqual(replay["headers"]["X-Idempotent-Replay"], "true")
        # replay reuses status/body but regenerates trace headers for this event
        self.assertEqual(replay["headers"]["X-Trace-Id"], TRACE)
        replay_span = replay["headers"]["traceparent"].split("-")[2]
        self.assertRegex(replay_span, SPAN_ID_RE)
        self.assertNotEqual(replay_span, holder["r"]["headers"]["traceparent"].split("-")[2])
        replay_entry = self.gateway.audit("acme", 1)[0]
        self.assertTrue(replay_entry["idempotent_replay"])
        self.assertEqual(replay_entry["span_id"], replay_span)
        self.assertEqual(replay_entry["parent_span_id"], PARENT)

    def test_every_retry_and_failover_attempt_carries_the_same_gateway_traceparent(self):
        seen = {"primary": [], "backup": []}

        def primary(request):
            seen["primary"].append(dict(request["headers"]))
            raise UpstreamError("boom")

        def backup(request):
            seen["backup"].append(dict(request["headers"]))
            return {"status": 200, "body": {"ok": True}}

        self.gateway.upstreams.register("primary", primary)
        self.gateway.upstreams.register("backup", backup)
        response = self.gateway.handle("acme", "GET", "/fb/x",
                                       {"traceparent": traceparent("01"),
                                        "tracestate": "vendor=1"}, "", now_ms=0)
        self.assertEqual(response["status"], 200)
        hop = "00-%s-" % TRACE
        all_attempts = seen["primary"] + seen["backup"]
        self.assertEqual(len(all_attempts), 4)  # 3 retries on primary + 1 backup
        gateway_spans = {h["traceparent"].split("-")[2] for h in all_attempts}
        self.assertEqual(gateway_spans, {response["headers"]["traceparent"].split("-")[2]})
        self.assertTrue(all(h["traceparent"].startswith(hop) for h in all_attempts))
        self.assertTrue(all(h["traceparent"].endswith("-01") for h in all_attempts))
        self.assertEqual([h["tracestate"] for h in all_attempts], ["vendor=1"] * 4)
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual((entry["attempts"], entry["upstream"], entry["trace_id"]),
                         (4, "backup", TRACE))

    def test_trace_headers_do_not_affect_weighted_route_selection(self):
        # same request_id and key must land on the same route regardless of the
        # tracing headers; selection stays key_id|request_id based
        doc = {"quota_policies": [], "keys": [], "routes": [
            {"id": "r-a", "tenant": "*", "match": {"method": "GET", "path_prefix": "/w"},
             "upstream": "capture", "auth_required": False, "weight": 1},
            {"id": "r-b", "tenant": "*", "match": {"method": "GET", "path_prefix": "/w"},
             "upstream": "capture", "auth_required": False, "weight": 3}]}
        write_config(self.path, doc)
        self.assertTrue(self.gateway.reload_config())
        first = self.gateway.handle("acme", "GET", "/w/x", {"x-request-id": "fixed"},
                                    "", now_ms=0)
        second = self.gateway.handle("acme", "GET", "/w/x",
                                     {"x-request-id": "fixed",
                                      "traceparent": traceparent("01")}, "", now_ms=0)
        self.assertEqual(first["route_id"], second["route_id"])


class TraceHttpTest(unittest.TestCase):
    def setUp(self):
        self.gateway, self.root, self.path = make_gateway()
        self.addCleanup(shutil.rmtree, self.root, True)

        def capture(request):
            return {"status": 200, "body": {"ok": True}}

        self.gateway.upstreams.register("capture", capture)
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

    def test_root_headers_over_http(self):
        status, headers, _ = self.request("/gw/t/x?tenant=acme")
        self.assertEqual(status, 200)
        self.assertRegex(headers["traceparent"], TRACEPARENT_RE)
        self.assertRegex(headers["X-Trace-Id"], TRACE_ID_RE)
        self.assertEqual(headers["X-Trace-Id"], headers["traceparent"].split("-")[1])

    def test_adopted_headers_over_http(self):
        status, headers, _ = self.request(
            "/gw/t/x?tenant=acme", {"Traceparent": traceparent("01"),
                                    "Tracestate": "congo=BfRLGLwR"})
        self.assertEqual(status, 200)
        self.assertEqual(headers["traceparent"].split("-")[1], TRACE)
        self.assertEqual(headers["traceparent"].split("-")[3], "01")
        self.assertEqual(headers["X-Trace-Id"], TRACE)

    def test_invalid_traceparent_is_400_over_http(self):
        status, headers, text = self.request("/gw/t/x?tenant=acme",
                                             {"Traceparent": "00-bad"})
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(text)["error"], "invalid traceparent")
        self.assertRegex(headers["traceparent"], TRACEPARENT_RE)
        self.assertRegex(headers["X-Trace-Id"], TRACE_ID_RE)

    def test_audit_endpoint_keeps_its_shape_and_exposes_trace_fields(self):
        self.request("/gw/t/x?tenant=acme", {"Traceparent": traceparent("01")})
        status, _, payload = self.request("/v1/audit?tenant=acme&limit=1")
        self.assertEqual(status, 200)
        entry = json.loads(payload)["entries"][0]
        self.assertEqual(entry["trace_id"], TRACE)
        self.assertEqual(entry["parent_span_id"], PARENT)
        self.assertTrue(entry["sampled"])
        self.assertRegex(entry["span_id"], SPAN_ID_RE)


if __name__ == "__main__":
    unittest.main()
