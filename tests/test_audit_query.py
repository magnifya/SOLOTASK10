"""Audit retrieval filters: AuditLog.entries, GET /v1/audit and the audit CLI."""

import contextlib
import io
import json
import os
import shutil
import tempfile
import threading
import unittest

from gwd.cli import main as cli_main
from gwd.config import GatewayError
from gwd.gateway import Gateway
from gwd.http_app import create_server
from gwd.limits import AuditLog, parse_audit_filters

TRACE_A = "a" * 32
TRACE_B = "0123456789abcdef0123456789abcdef"


def _entry(at, tenant="acme", request_id="req-1", trace_id=TRACE_A,
           route_id="r-1", status=200, **extra):
    entry = {"at": at, "request_id": request_id, "tenant": tenant,
             "key_id": None, "route_id": route_id, "upstream": "echo",
             "status": status, "attempts": 1, "latency_ms": 1,
             "quota": {"policy_id": None, "allowed": True, "remaining": None},
             "idempotent_replay": False, "trace_id": trace_id,
             "span_id": "0" * 16, "parent_span_id": None, "sampled": False}
    entry.update(extra)
    return entry


class AuditLogFilterTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-audit-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.log = AuditLog(self.root)
        self.log.append(_entry(100, request_id="req-1", trace_id=TRACE_A,
                               route_id="r-1", status=200))
        self.log.append(_entry(200, request_id="req-2", trace_id=TRACE_B,
                               route_id="r-2", status=429, tenant="other"))
        self.log.append(_entry(300, request_id="req-3", trace_id=TRACE_A,
                               route_id="r-1", status=502))
        # A historical record without the new fields never matches them.
        self.log.append({"at": 400, "tenant": "acme", "status": 200})

    def test_no_filters_keeps_append_order(self):
        entries = self.log.entries()
        self.assertEqual([e["at"] for e in entries], [100, 200, 300, 400])

    def test_request_id_and_route_id_are_exact(self):
        self.assertEqual([e["at"] for e in self.log.entries(request_id="req-1")], [100])
        self.assertEqual(self.log.entries(request_id="req-1x"), [])
        self.assertEqual([e["at"] for e in self.log.entries(route_id="r-1")], [100, 300])

    def test_trace_id_finds_the_whole_link(self):
        entries = self.log.entries(trace_id=TRACE_A)
        self.assertEqual([e["request_id"] for e in entries], ["req-1", "req-3"])

    def test_status_matches_exactly(self):
        self.assertEqual([e["at"] for e in self.log.entries(status=200)], [100, 400])
        self.assertEqual([e["at"] for e in self.log.entries(status=429)], [200])

    def test_since_is_inclusive_and_until_exclusive(self):
        self.assertEqual([e["at"] for e in self.log.entries(since_ms=200)], [200, 300, 400])
        self.assertEqual([e["at"] for e in self.log.entries(until_ms=300)], [100, 200])
        self.assertEqual([e["at"] for e in self.log.entries(since_ms=200, until_ms=300)], [200])
        self.assertEqual(self.log.entries(since_ms=300, until_ms=300), [])

    def test_missing_field_never_matches(self):
        self.assertEqual(self.log.entries(trace_id=TRACE_A, since_ms=400), [])
        self.assertEqual(self.log.entries(request_id="req-1", tenant="acme")[0]["at"], 100)

    def test_filters_combine_and_limit_takes_the_last_matches(self):
        entries = self.log.entries(tenant="acme", trace_id=TRACE_A, limit=1)
        self.assertEqual([e["request_id"] for e in entries], ["req-3"])

    def test_torn_trailing_line_is_skipped(self):
        with open(self.log.path, "a", encoding="utf-8") as handle:
            handle.write('{"at": 500, "trace_id": ')
        self.assertEqual([e["at"] for e in self.log.entries()], [100, 200, 300, 400])


class ParseAuditFiltersTest(unittest.TestCase):
    def test_absent_filters_yield_no_keys(self):
        self.assertEqual(parse_audit_filters(), {})

    def test_strings_pass_through(self):
        filters = parse_audit_filters(request_id="r", trace_id=TRACE_B, route_id="r-1")
        self.assertEqual(filters, {"request_id": "r", "trace_id": TRACE_B, "route_id": "r-1"})

    def test_trace_id_must_be_32_lowercase_hex(self):
        for bad in ("", "abc", TRACE_A.upper(), "g" * 32, TRACE_A + "0"):
            with self.assertRaises(GatewayError) as ctx:
                parse_audit_filters(trace_id=bad)
            self.assertEqual(ctx.exception.message, "invalid audit query")
            self.assertEqual(ctx.exception.parameter, "trace_id")
            self.assertEqual(ctx.exception.status, 400)

    def test_status_must_be_100_to_599(self):
        self.assertEqual(parse_audit_filters(status="200"), {"status": 200})
        for bad in ("99", "600", "abc", "20x", "-1", "200.5"):
            with self.assertRaises(GatewayError) as ctx:
                parse_audit_filters(status=bad)
            self.assertEqual(ctx.exception.parameter, "status")

    def test_since_and_until_parse_as_integers(self):
        self.assertEqual(parse_audit_filters(since="10", until="20"),
                         {"since_ms": 10, "until_ms": 20})
        with self.assertRaises(GatewayError) as ctx:
            parse_audit_filters(since="soon")
        self.assertEqual(ctx.exception.parameter, "since")
        with self.assertRaises(GatewayError) as ctx:
            parse_audit_filters(until="1.5")
        self.assertEqual(ctx.exception.parameter, "until")

    def test_until_earlier_than_since_is_rejected(self):
        with self.assertRaises(GatewayError) as ctx:
            parse_audit_filters(since="20", until="10")
        self.assertEqual(ctx.exception.parameter, "until")
        # Equal bounds are an empty but valid range.
        self.assertEqual(parse_audit_filters(since="10", until="10"),
                         {"since_ms": 10, "until_ms": 10})


class AuditHttpTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-audit-http-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.config_path = os.path.join(self.root, "config.json")
        with open(self.config_path, "w", encoding="utf-8") as handle:
            json.dump({"routes": [], "keys": [], "quota_policies": []}, handle)
        self.gateway = Gateway(config_path=self.config_path,
                               data_dir=os.path.join(self.root, "data"))
        self.log = AuditLog(os.path.join(self.root, "data"))
        self.log.append(_entry(100, request_id="req-1", trace_id=TRACE_A, status=200))
        self.log.append(_entry(200, request_id="req-2", trace_id=TRACE_B, status=404))
        self.server = create_server(self.gateway, "127.0.0.1", 0, quiet=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]

    def _stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def get(self, path):
        import urllib.error
        import urllib.request
        request = urllib.request.Request(self.base + path, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_no_new_filters_matches_the_legacy_shape(self):
        status, payload = self.get("/v1/audit?tenant=acme&limit=10")
        self.assertEqual(status, 200)
        self.assertEqual(payload["tenant"], "acme")
        self.assertEqual(payload["count"], 2)
        self.assertEqual([e["request_id"] for e in payload["entries"]], ["req-1", "req-2"])

    def test_filter_by_trace_id_and_status(self):
        status, payload = self.get("/v1/audit?trace_id=" + TRACE_A)
        self.assertEqual(status, 200)
        self.assertEqual([e["request_id"] for e in payload["entries"]], ["req-1"])
        status, payload = self.get("/v1/audit?status=404")
        self.assertEqual([e["request_id"] for e in payload["entries"]], ["req-2"])
        status, payload = self.get("/v1/audit?request_id=req-2&route_id=r-1")
        self.assertEqual(payload["count"], 1)

    def test_time_bounds(self):
        status, payload = self.get("/v1/audit?since=100&until=200")
        self.assertEqual([e["at"] for e in payload["entries"]], [100])
        status, payload = self.get("/v1/audit?since=500")
        self.assertEqual((status, payload["count"], payload["entries"]), (200, 0, []))

    def test_invalid_filters_are_400_with_parameter(self):
        for path, parameter in (
                ("/v1/audit?trace_id=xyz", "trace_id"),
                ("/v1/audit?trace_id=" + TRACE_A.upper(), "trace_id"),
                ("/v1/audit?status=99", "status"),
                ("/v1/audit?status=600", "status"),
                ("/v1/audit?status=ok", "status"),
                ("/v1/audit?since=abc", "since"),
                ("/v1/audit?until=1.5", "until"),
                ("/v1/audit?since=200&until=100", "until")):
            status, payload = self.get(path)
            self.assertEqual(status, 400, path)
            self.assertEqual(payload["error"], "invalid audit query", path)
            self.assertEqual(payload["parameter"], parameter, path)
            self.assertIn("request_id", payload)

    def test_query_does_not_write_or_reload(self):
        revision = self.gateway.store.revision
        before_audit = os.path.getsize(self.log.path)
        usage_path = os.path.join(self.root, "data", "usage.jsonl")
        self.get("/v1/audit?trace_id=" + TRACE_A)
        self.assertEqual(os.path.getsize(self.log.path), before_audit)
        self.assertFalse(os.path.exists(usage_path))
        self.assertEqual(self.gateway.store.revision, revision)


class AuditCliTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-audit-cli-")
        self.addCleanup(shutil.rmtree, self.root, True)
        log = AuditLog(self.root)
        log.append(_entry(100, request_id="req-1", trace_id=TRACE_A, status=200))
        log.append(_entry(200, request_id="req-2", trace_id=TRACE_B, status=503))

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli_main(["--data-dir", self.root, "audit", *argv])
        return code, out.getvalue(), err.getvalue()

    def test_single_line_json_output(self):
        code, out, _ = self.run_cli("--tenant", "acme")
        self.assertEqual(code, 0)
        lines = out.strip().splitlines()
        self.assertEqual(len(lines), 1)
        payload = json.loads(lines[0])
        self.assertEqual(payload["count"], 2)

    def test_new_filters(self):
        code, out, _ = self.run_cli("--trace-id", TRACE_B)
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual([e["request_id"] for e in payload["entries"]], ["req-2"])
        code, out, _ = self.run_cli("--status", "200", "--since", "100",
                                    "--until", "101", "--request-id", "req-1",
                                    "--route-id", "r-1", "--limit", "5")
        self.assertEqual(json.loads(out)["count"], 1)

    def test_invalid_filter_uses_the_existing_error_surface(self):
        code, out, err = self.run_cli("--trace-id", "nope")
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(json.loads(err)["error"], "invalid audit query")


if __name__ == "__main__":
    unittest.main()
