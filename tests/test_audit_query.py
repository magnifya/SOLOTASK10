"""Audit trail query filters: AuditLog.entries, GET /v1/audit and the audit CLI."""

import contextlib
import hashlib
import io
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
from gwd.limits import AuditLog, AuditQueryError, parse_audit_filters

SECRET = "audit-secret"
TRACE_A = "a" * 32
TRACE_B = "b" * 32


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def config_document():
    return {
        "quota_policies": [],
        "keys": [{"key_id": "k-audit", "tenant": "acme", "secret_sha256": sha(SECRET),
                  "scopes": ["read"]}],
        "routes": [
            {"id": "r-audit", "tenant": "acme", "match": {"method": "GET", "path_prefix": "/api"},
             "upstream": "echo", "scopes": ["read"]},
        ],
    }


def write_trail(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def sample_rows():
    return [
        {"at": 1000, "request_id": "req-1", "tenant": "acme", "route_id": "r-a",
         "status": 200, "trace_id": TRACE_A, "span_id": "1" * 16,
         "parent_span_id": None, "sampled": True, "quota": {"allowed": True},
         "attempts": 1},
        {"at": 2000, "request_id": "req-2", "tenant": "acme", "route_id": "r-b",
         "status": 401, "trace_id": TRACE_A, "span_id": "2" * 16,
         "parent_span_id": None, "sampled": True, "quota": {"allowed": True},
         "attempts": 0},
        {"at": 3000, "request_id": "req-3", "tenant": "globex", "route_id": "r-a",
         "status": 200, "trace_id": TRACE_B, "span_id": "3" * 16,
         "parent_span_id": None, "sampled": False, "quota": {"allowed": False},
         "attempts": 2},
        {"at": 4000, "request_id": "req-4", "tenant": "acme", "route_id": "r-a",
         "status": 429},
        {"at": 5000, "tenant": "acme", "status": 200},  # legacy row, sparse fields
    ]


class AuditLogEntriesTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-audit-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.log = AuditLog(self.root)
        write_trail(self.log.path, sample_rows())

    def ids(self, rows):
        return [row.get("request_id") for row in rows]

    def test_no_filters_keeps_append_order(self):
        self.assertEqual(self.ids(self.log.entries()),
                         ["req-1", "req-2", "req-3", "req-4", None])

    def test_exact_string_filters(self):
        self.assertEqual(self.ids(self.log.entries(request_id="req-2")), ["req-2"])
        self.assertEqual(self.ids(self.log.entries(trace_id=TRACE_A)), ["req-1", "req-2"])
        self.assertEqual(self.ids(self.log.entries(route_id="r-a")),
                         ["req-1", "req-3", "req-4"])
        self.assertEqual(self.log.entries(request_id="REQ-1"), [])  # case sensitive
        self.assertEqual(self.log.entries(trace_id=TRACE_A.upper()), [])

    def test_status_and_time_filters(self):
        self.assertEqual(self.ids(self.log.entries(status=200)), ["req-1", "req-3", None])
        self.assertEqual(self.ids(self.log.entries(since_ms=2000)),
                         ["req-2", "req-3", "req-4", None])  # inclusive
        self.assertEqual(self.ids(self.log.entries(until_ms=4000)),
                         ["req-1", "req-2", "req-3"])  # exclusive
        self.assertEqual(self.ids(self.log.entries(since_ms=2000, until_ms=4000)),
                         ["req-2", "req-3"])

    def test_missing_field_never_matches(self):
        # the legacy row has no request_id / trace_id / route_id
        self.assertNotIn(None, self.ids(self.log.entries(request_id="req-1")))
        self.assertEqual(self.log.entries(trace_id=TRACE_B)[0]["request_id"], "req-3")
        self.assertEqual(self.ids(self.log.entries(route_id="r-a", status=200)),
                         ["req-1", "req-3"])

    def test_limit_keeps_the_last_matches(self):
        self.assertEqual(self.ids(self.log.entries(route_id="r-a", limit=2)),
                         ["req-3", "req-4"])
        self.assertEqual(self.ids(self.log.entries(limit=1)), [None])

    def test_conditions_combine(self):
        rows = self.log.entries(tenant="acme", trace_id=TRACE_A, status=200)
        self.assertEqual(self.ids(rows), ["req-1"])
        self.assertEqual(self.log.entries(tenant="acme", trace_id=TRACE_B), [])

    def test_torn_trailing_line_is_skipped_and_reads_never_write(self):
        with open(self.log.path, "a", encoding="utf-8") as handle:
            handle.write('{"at": 6000, "request_id": "req-5", "ten')  # torn by a crash
        with open(self.log.path, "rb") as handle:
            before = handle.read()
        self.assertEqual(self.log.entries()[-1]["at"], 5000)
        self.assertEqual(self.log.entries(request_id="req-5"), [])
        with open(self.log.path, "rb") as handle:
            self.assertEqual(handle.read(), before)  # the read did not rewrite the file
        self.assertFalse(os.path.exists(os.path.join(self.root, "usage.jsonl")))


class ParseAuditFiltersTest(unittest.TestCase):
    def test_valid_filters(self):
        filters = parse_audit_filters({
            "request_id": "req-1", "trace_id": TRACE_A, "route_id": "r-a",
            "status": "200", "since": "1000", "until": "2000"})
        self.assertEqual(filters, {"request_id": "req-1", "trace_id": TRACE_A,
                                   "route_id": "r-a", "status": 200,
                                   "since_ms": 1000, "until_ms": 2000})
        self.assertEqual(parse_audit_filters({}), {})
        self.assertEqual(parse_audit_filters({"status": "", "since": None}), {})

    def test_invalid_values_name_the_parameter(self):
        bad = ({"trace_id": "abc"}, {"trace_id": TRACE_A.upper()},
               {"trace_id": TRACE_A + "0"}, {"status": "abc"}, {"status": "99"},
               {"status": "600"}, {"status": "20.0"}, {"since": "soon"},
               {"until": "1.5"})
        for raw in bad:
            with self.assertRaises(AuditQueryError) as caught:
                parse_audit_filters(raw)
            name = next(iter(raw))
            self.assertEqual(caught.exception.parameter, name)
            self.assertEqual(caught.exception.message, "invalid audit query")
            self.assertEqual(caught.exception.status, 400)

    def test_until_before_since_is_rejected(self):
        with self.assertRaises(AuditQueryError) as caught:
            parse_audit_filters({"since": "2000", "until": "1000"})
        self.assertEqual(caught.exception.parameter, "until")
        # equal bounds are allowed: the window is simply empty
        self.assertEqual(parse_audit_filters({"since": "1000", "until": "1000"}),
                         {"since_ms": 1000, "until_ms": 1000})


class AuditHttpTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-audit-http-")
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

    def json_request(self, method, path, headers=None):
        request = urllib.request.Request(self.base + path, method=method,
                                         headers=headers or {})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def proxy(self, trace_id):
        headers = {"authorization": "Bearer " + SECRET}
        if trace_id:
            headers["traceparent"] = "00-%s-%s-01" % (trace_id, "1" * 16)
        return self.json_request("GET", "/api/items", headers=headers)

    def test_filter_by_trace_request_route_and_status(self):
        self.proxy(TRACE_A)
        self.proxy(TRACE_B)
        self.json_request("GET", "/api/items")  # 401, no key
        status, payload = self.json_request("GET", "/v1/audit?trace_id=" + TRACE_A)
        self.assertEqual(status, 200)
        self.assertEqual(payload["count"], 1)
        entry = payload["entries"][0]
        self.assertEqual(entry["trace_id"], TRACE_A)
        for field in ("span_id", "parent_span_id", "sampled", "quota", "attempts"):
            self.assertIn(field, entry)
        status, payload = self.json_request(
            "GET", "/v1/audit?request_id=" + entry["request_id"])
        self.assertEqual((status, payload["count"]), (200, 1))
        status, payload = self.json_request("GET", "/v1/audit?route_id=r-audit&status=200")
        self.assertEqual(payload["count"], 2)
        status, payload = self.json_request("GET", "/v1/audit?status=401")
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["entries"][0]["tenant"], "")  # no key to attribute

    def test_time_bounds_and_limit(self):
        self.proxy(TRACE_A)
        self.proxy(TRACE_B)
        entries = self.json_request("GET", "/v1/audit?limit=50")[1]["entries"]
        first_at = entries[0]["at"]
        status, payload = self.json_request("GET", "/v1/audit?since=%d" % first_at)
        self.assertEqual(payload["count"], 2)  # inclusive
        status, payload = self.json_request("GET", "/v1/audit?until=%d" % first_at)
        self.assertEqual(payload["count"], 0)  # exclusive
        self.assertEqual(payload["entries"], [])
        status, payload = self.json_request("GET", "/v1/audit?limit=1")
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["entries"][0]["trace_id"], TRACE_B)

    def test_invalid_filters_are_400_with_parameter(self):
        bad = [("trace_id", "ABC"), ("trace_id", "a" * 31), ("status", "99"),
               ("status", "600"), ("status", "ok"), ("since", "soon"), ("until", "1.5")]
        for name, value in bad:
            status, payload = self.json_request("GET", "/v1/audit?%s=%s" % (name, value))
            self.assertEqual(status, 400, (name, value))
            self.assertEqual(payload["error"], "invalid audit query")
            self.assertEqual(payload["parameter"], name)
            self.assertIn("request_id", payload)
        status, payload = self.json_request("GET", "/v1/audit?since=2000&until=1000")
        self.assertEqual(status, 400)
        self.assertEqual(payload["parameter"], "until")
        # the pre-existing limit validation keeps its own error shape
        status, payload = self.json_request("GET", "/v1/audit?limit=lots")
        self.assertEqual(status, 400)
        self.assertNotEqual(payload.get("error"), "invalid audit query")

    def test_no_new_filters_matches_the_legacy_output(self):
        self.proxy(TRACE_A)
        status, legacy = self.json_request("GET", "/v1/audit?tenant=acme&limit=10")
        self.assertEqual(status, 200)
        self.assertEqual(set(legacy), {"tenant", "count", "entries"})
        self.assertEqual(legacy["count"], 1)


class AuditCliTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-audit-cli-")
        self.addCleanup(shutil.rmtree, self.root, True)
        write_trail(os.path.join(self.root, "audit.jsonl"), sample_rows())

    def run_cli(self, *argv):
        from gwd.cli import main
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["--data-dir", self.root, "audit"] + list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_filters_print_one_json_line(self):
        code, out, err = self.run_cli("--tenant", "acme", "--trace-id", TRACE_A,
                                      "--status", "200")
        self.assertEqual((code, err), (0, ""))
        lines = out.strip().splitlines()
        self.assertEqual(len(lines), 1)
        payload = json.loads(lines[0])
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["entries"][0]["request_id"], "req-1")
        code, out, _ = self.run_cli("--route-id", "r-a", "--limit", "1")
        self.assertEqual(json.loads(out)["entries"][0]["request_id"], "req-4")
        code, out, _ = self.run_cli("--since", "2000", "--until", "3000")
        self.assertEqual([e["request_id"] for e in json.loads(out)["entries"]], ["req-2"])

    def test_invalid_filters_keep_the_cli_error_shape(self):
        code, out, err = self.run_cli("--trace-id", "nope")
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(json.loads(err)["error"], "invalid audit query")
        code, _, err = self.run_cli("--status", "600")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "invalid audit query")
        code, _, err = self.run_cli("--since", "3000", "--until", "1000")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "invalid audit query")


if __name__ == "__main__":
    unittest.main()
