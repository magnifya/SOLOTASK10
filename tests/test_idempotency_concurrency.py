"""Concurrent in-flight idempotency protection: Gateway.handle threads and the
real ThreadingHTTPServer proxy surface.

The gateway keeps one in-flight marker per (tenant, full key) scope. While the
first request is inside the whole upstream chain (retries and failover
included), a concurrent request with the same body gets an immediate ``425``
(``Retry-After: 1``, ``"idempotency request in progress"``) and one with a
different body keeps the historical ``409``; neither ever calls an upstream.
"""

import hashlib
import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from gwd.gateway import Gateway, IN_PROGRESS_ERROR
from gwd.http_app import create_server
from gwd.upstream import UpstreamError


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


SECRET = "secret-a"


def write_config(path, doc):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle)
    stat = os.stat(path)
    os.utime(path, ns=(stat.st_atime_ns + 1_000_000, stat.st_mtime_ns + 1_000_000))


def concurrent_document():
    return {
        "quota_policies": [
            # generous tenant bucket so every concurrent request passes quota
            {"id": "p-slide", "tenant": "*", "algorithm": "sliding-window",
             "limit": 100000, "window_ms": 60000, "partition_by": "tenant"},
            # tight joint buckets used to prove a quota 429 takes no scope
            {"id": "p-j1", "tenant": "*", "algorithm": "token-bucket",
             "limit": 1, "window_ms": 60000, "burst": 1, "partition_by": "tenant"},
            {"id": "p-j2", "tenant": "*", "algorithm": "token-bucket",
             "limit": 5, "window_ms": 60000, "burst": 5, "partition_by": "tenant"},
        ],
        "keys": [{"key_id": "k-a", "tenant": "acme", "secret_sha256": sha(SECRET),
                  "scopes": ["read"]}],
        "routes": [
            {"id": "r-block", "tenant": "*", "match": {"method": "POST", "path_prefix": "/c"},
             "upstream": "block", "auth_required": False, "quota_policy": "p-slide"},
            {"id": "r-open", "tenant": "*", "match": {"method": "POST", "path_prefix": "/o"},
             "upstream": "block", "auth_required": False},
            {"id": "r-joint", "tenant": "*", "match": {"method": "POST", "path_prefix": "/j"},
             "upstream": "block", "auth_required": False,
             "quota_policies": ["p-j1", "p-j2"]},
            {"id": "r-err", "tenant": "*", "match": {"method": "POST", "path_prefix": "/e"},
             "upstream": "http500", "auth_required": False},
            {"id": "r-boom", "tenant": "*", "match": {"method": "POST", "path_prefix": "/boom"},
             "upstream": "boom", "auth_required": False},
            {"id": "r-closed", "tenant": "*", "match": {"method": "POST", "path_prefix": "/closed"},
             "upstream": "never", "auth_required": False},
            {"id": "r-fb", "tenant": "*", "match": {"method": "POST", "path_prefix": "/fb"},
             "upstream": "primary", "auth_required": False,
             "fallback_upstreams": ["backup"]},
        ],
    }


class BlockingUpstream:
    """Holds calls whose request id is in ``hold_ids`` until ``release`` is set."""

    def __init__(self, hold_ids=()):
        self.hold_ids = set(hold_ids)
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls = []
        self.lock = threading.Lock()

    def __call__(self, request):
        rid = request["request_id"]
        with self.lock:
            self.calls.append(rid)
        if rid in self.hold_ids:
            self.entered.set()
            if not self.release.wait(5):
                raise UpstreamError("test timed out waiting for release")
        return {"status": 200, "body": {"ok": True, "rid": rid}}


class ConcurrentIdempotencyTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-idem-conc-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = os.path.join(self.root, "config.json")
        write_config(self.path, concurrent_document())
        self.gateway = Gateway(
            config_path=self.path, data_dir=os.path.join(self.root, "data"),
            breaker_settings={"failure_threshold": 1, "open_ms": 1000,
                              "success_threshold": 1})
        self.block = BlockingUpstream(hold_ids={"hold"})
        self.gateway.upstreams.register("block", self.block)
        self.error_calls = []

        def http500(request):
            self.error_calls.append(request["request_id"])
            return {"status": 500, "body": {"error": "down"}}

        self.boom_calls = []

        def boom(request):
            self.boom_calls.append(request["request_id"])
            raise UpstreamError("boom")

        self.gateway.upstreams.register("http500", http500)
        self.gateway.upstreams.register("boom", boom)

    def body_of(self, response):
        return json.loads(response["body"])

    def headers(self, key, request_id):
        return {"x-idempotency-key": key, "x-request-id": request_id}

    def start_held(self, tenant="acme", key="k1", body='{"a": 1}', request_id="hold",
                   path="/c/x", now_ms=1000):
        result = {}

        def run():
            result["response"] = self.gateway.handle(
                tenant, "POST", path, self.headers(key, request_id), body, now_ms=now_ms)

        thread = threading.Thread(target=run)
        thread.start()
        self.assertTrue(self.block.entered.wait(5), "held request never reached the upstream")
        return thread, result

    def test_same_body_while_in_flight_is_425_then_replays_after_release(self):
        thread, result = self.start_held()
        duplicate = self.gateway.handle(
            "acme", "POST", "/c/x", self.headers("k1", "dup"), '{"a": 1}', now_ms=2000)
        self.assertEqual(duplicate["status"], 425)
        self.assertEqual(duplicate["headers"]["Retry-After"], "1")
        self.assertEqual(self.body_of(duplicate),
                         {"error": IN_PROGRESS_ERROR, "request_id": "dup"})
        self.assertNotIn("X-Idempotent-Replay", duplicate["headers"])
        self.assertEqual(self.block.calls, ["hold"])

        self.block.release.set()
        thread.join(5)
        self.assertEqual(result["response"]["status"], 200)
        self.assertNotIn("X-Idempotent-Replay", result["response"]["headers"])

        replay = self.gateway.handle(
            "acme", "POST", "/c/x", self.headers("k1", "rep"), '{"a": 1}', now_ms=3000)
        self.assertEqual(replay["status"], 200)
        self.assertEqual(replay["headers"]["X-Idempotent-Replay"], "true")
        self.assertEqual(result["response"]["body"], replay["body"])
        self.assertEqual(self.block.calls, ["hold"])

    def test_different_body_while_in_flight_is_409(self):
        thread, result = self.start_held()
        conflict = self.gateway.handle(
            "acme", "POST", "/c/x", self.headers("k1", "conf"), '{"a": 2}', now_ms=2000)
        self.assertEqual(conflict["status"], 409)
        self.assertNotIn("Retry-After", conflict["headers"])
        self.assertNotIn("X-Idempotent-Replay", conflict["headers"])
        self.assertEqual(self.body_of(conflict)["request_id"], "conf")
        self.assertEqual(self.block.calls, ["hold"])
        self.block.release.set()
        thread.join(5)

    def test_protection_outlives_the_caching_window(self):
        thread, result = self.start_held()
        # Long after the 10 minute window would have expired a finished
        # response, the in-flight marker still owns the scope.
        late = self.gateway.handle(
            "acme", "POST", "/c/x", self.headers("k1", "late"), '{"a": 1}',
            now_ms=10_000_000)
        self.assertEqual(late["status"], 425)
        self.block.release.set()
        thread.join(5)

    def test_different_scopes_run_concurrently_and_separator_bytes_cannot_merge_them(self):
        # Held scope is the pair ("acme", "a|b").
        thread, result = self.start_held(key="a|b", request_id="hold")
        for tenant, key, request_id in (
                ("acme", "k2", "other-key"),          # different key
                ("globex", "a|b", "other-tenant"),    # different tenant
                ("acme|a", "b", "separator-swap")):   # tuple, not a joined string
            response = self.gateway.handle(
                tenant, "POST", "/c/x", self.headers(key, request_id), '{"a": 1}', now_ms=2000)
            self.assertEqual(response["status"], 200, request_id)
            self.assertNotIn("X-Idempotent-Replay", response["headers"])
        self.assertEqual(sorted(self.block.calls),
                         ["hold", "other-key", "other-tenant", "separator-swap"])
        self.block.release.set()
        thread.join(5)

    def test_missing_or_empty_idempotency_header_keeps_going_to_the_upstream(self):
        thread, result = self.start_held()
        no_header = self.gateway.handle(
            "acme", "POST", "/c/x", {"x-request-id": "no-header"}, '{"a": 1}', now_ms=2000)
        empty_header = self.gateway.handle(
            "acme", "POST", "/c/x",
            {"x-idempotency-key": "", "x-request-id": "empty-header"}, '{"a": 1}', now_ms=2000)
        self.assertEqual((no_header["status"], empty_header["status"]), (200, 200))
        self.block.release.set()
        thread.join(5)

    def test_each_concurrent_request_passes_quota_on_its_own_and_audits_zero_attempts(self):
        thread, result = self.start_held()
        for request_id in ("dup-1", "dup-2"):
            duplicate = self.gateway.handle(
                "acme", "POST", "/c/x", self.headers("k1", request_id), '{"a": 1}', now_ms=2000)
            self.assertEqual(duplicate["status"], 425)
        # Both rejections were billed independently against their own request.
        usage = self.gateway.usage("acme")
        self.assertEqual((usage["requests"], usage["allowed"], usage["rejected"]), (3, 3, 0))
        entries = {e["request_id"]: e for e in self.gateway.audit("acme", 10)}
        expected_remaining = {"dup-1": 99998, "dup-2": 99997}
        for request_id in ("dup-1", "dup-2"):
            entry = entries[request_id]
            self.assertEqual((entry["status"], entry["attempts"], entry["idempotent_replay"]),
                             (425, 0, False))
            self.assertEqual(entry["quota"], {"policy_id": "p-slide", "allowed": True,
                                              "remaining": expected_remaining[request_id]})
            self.assertEqual(entry["route_id"], "r-block")
        self.block.release.set()
        thread.join(5)

    def test_joint_quota_rejection_is_all_or_nothing_and_never_takes_the_scope(self):
        first = self.gateway.handle(
            "acme", "POST", "/j/x", self.headers("kj", "j1"), '{}', now_ms=0)
        self.assertEqual(first["status"], 200)
        # p-j1 is exhausted: the joint group rejects as a whole (429), the
        # request never reaches idempotency admission, so the scope is free.
        throttled = self.gateway.handle(
            "acme", "POST", "/j/x", self.headers("kj", "j2"), '{}', now_ms=0)
        self.assertEqual(throttled["status"], 429)
        self.assertEqual(self.block.calls, ["j1"])
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual(entry["request_id"], "j2")
        self.assertEqual(entry["attempts"], 0)
        self.assertEqual(entry["quota"]["policy_id"], "p-j1")
        self.assertEqual(entry["quotas"], [
            {"policy_id": "p-j1", "allowed": False, "remaining": 0},
            {"policy_id": "p-j2", "allowed": False, "remaining": 4}])
        # One usage record per named policy per request.
        self.assertEqual(self.gateway.usage("acme")["requests"], 4)
        # After the bucket refills *and* the finished response window has
        # passed, the scope executes normally: no phantom in-flight marker was
        # left by the 429.
        retried = self.gateway.handle(
            "acme", "POST", "/j/x", self.headers("kj", "j3"), '{}', now_ms=600_001)
        self.assertEqual(retried["status"], 200)
        self.assertEqual(self.block.calls, ["j1", "j3"])

    def test_final_5xx_releases_the_scope_without_caching(self):
        first = self.gateway.handle(
            "acme", "POST", "/e/x", self.headers("ke", "e1"), '{}', now_ms=0)
        self.assertEqual(first["status"], 500)
        self.assertEqual(self.error_calls, ["e1"] * 3)  # the retry budget was spent
        # The 5xx chain tripped the breaker; reset it so a retry really reaches
        # the upstream again instead of being refused as 503.
        self.gateway.breaker_reset("http500")
        second = self.gateway.handle(
            "acme", "POST", "/e/x", self.headers("ke", "e2"), '{}', now_ms=1)
        self.assertEqual(second["status"], 500)
        self.assertNotIn("X-Idempotent-Replay", second["headers"])
        # The scope was released: the second request executed its own chain.
        self.assertEqual(self.error_calls, ["e1"] * 3 + ["e2"] * 3)

    def test_transport_failure_releases_the_scope(self):
        first = self.gateway.handle(
            "acme", "POST", "/boom/x", self.headers("kb", "b1"), '{}', now_ms=0)
        self.assertEqual(first["status"], 502)
        self.assertEqual(self.boom_calls, ["b1"] * 3)
        self.gateway.breaker_reset("boom")
        second = self.gateway.handle(
            "acme", "POST", "/boom/x", self.headers("kb", "b2"), '{}', now_ms=1)
        self.assertEqual(second["status"], 502)
        self.assertNotIn("X-Idempotent-Replay", second["headers"])
        self.assertEqual(self.boom_calls, ["b1"] * 3 + ["b2"] * 3)

    def test_all_breakers_open_releases_the_scope_without_caching(self):
        for _ in range(3):
            self.gateway.handle(
                "acme", "POST", "/closed/x", self.headers("kn", "n1"), '{}', now_ms=0)
        rejected = self.gateway.handle(
            "acme", "POST", "/closed/x", self.headers("kn", "n2"), '{}', now_ms=1)
        self.assertEqual(rejected["status"], 503)
        self.assertEqual(self.body_of(rejected)["state"], "open")
        # The breaker refusal must not have pinned the scope: reset and retry.
        self.gateway.breaker_reset("never")
        self.gateway.upstreams.register("never", self.block)
        retried = self.gateway.handle(
            "acme", "POST", "/closed/x", self.headers("kn", "n3"), '{}', now_ms=2)
        self.assertEqual(retried["status"], 200)
        self.assertNotIn("X-Idempotent-Replay", retried["headers"])
        self.assertEqual(self.block.calls, ["n3"])

    def test_retries_and_failover_stay_inside_the_one_protected_execution(self):
        primary_calls = []

        def primary(request):
            primary_calls.append(request["request_id"])
            raise UpstreamError("boom")

        backup_calls = []

        def backup(request):
            backup_calls.append(request["request_id"])
            return {"status": 200, "body": {"ok": True}}

        self.gateway.upstreams.register("primary", primary)
        self.gateway.upstreams.register("backup", backup)

        slept = threading.Event()
        gate = threading.Event()

        def sleep_fn(delay_ms):
            if not slept.is_set():
                slept.set()
                gate.wait(5)

        self.gateway.sleep_fn = sleep_fn
        result = {}
        headers = self.headers("fbk", "fb-hold")
        thread = threading.Thread(target=lambda: result.update(response=self.gateway.handle(
            "acme", "POST", "/fb/x", headers, '{}', now_ms=0)))
        thread.start()
        self.assertTrue(slept.wait(5), "primary retry never parked in the sleep hook")
        # The request is mid-retry: the scope is already protected.
        duplicate = self.gateway.handle(
            "acme", "POST", "/fb/x", self.headers("fbk", "fb-dup"), '{}', now_ms=0)
        self.assertEqual(duplicate["status"], 425)
        gate.set()
        thread.join(5)
        self.assertEqual(result["response"]["status"], 200)
        self.assertEqual(len(primary_calls), 3)
        self.assertEqual(backup_calls, ["fb-hold"])
        # The finished failover response is cached for the scope.
        replay = self.gateway.handle(
            "acme", "POST", "/fb/x", self.headers("fbk", "fb-rep"), '{}', now_ms=1)
        self.assertEqual(replay["status"], 200)
        self.assertEqual(replay["headers"]["X-Idempotent-Replay"], "true")
        self.assertEqual(len(primary_calls), 3)
        self.assertEqual(backup_calls, ["fb-hold"])

    def test_hammering_one_scope_executes_the_upstream_exactly_once(self):
        thread, held_result = self.start_held(key="race", request_id="hold")
        results = []
        results_lock = threading.Lock()
        ready = threading.Event()
        go = threading.Event()
        started = [0]
        started_lock = threading.Lock()

        def duplicate(index):
            with started_lock:
                started[0] += 1
                if started[0] == 24:
                    ready.set()
            self.assertTrue(go.wait(5))
            response = self.gateway.handle(
                "acme", "POST", "/c/x", self.headers("race", "race-%d" % index),
                '{"a": 1}', now_ms=2000)
            with results_lock:
                results.append(response)

        threads = [threading.Thread(target=duplicate, args=(i,)) for i in range(24)]
        for worker in threads:
            worker.start()
        self.assertTrue(ready.wait(5), "duplicate workers never queued")
        # Release the held execution and fan the duplicates in at the same
        # instant: some meet the in-flight marker (425), others the freshly
        # cached response (200), but none may execute the upstream again.
        self.block.release.set()
        go.set()
        thread.join(5)
        for worker in threads:
            worker.join(5)
        self.assertEqual(self.block.calls, ["hold"])
        statuses = sorted(response["status"] for response in results)
        self.assertTrue(set(statuses) <= {200, 425}, statuses)
        for response in results:
            if response["status"] == 200:
                self.assertEqual(response["headers"]["X-Idempotent-Replay"], "true")
            else:
                self.assertEqual(response["headers"]["Retry-After"], "1")
                self.assertEqual(self.body_of(response)["error"], IN_PROGRESS_ERROR)

    def test_hot_reload_keeps_the_in_flight_marker_and_unexpired_responses(self):
        finished = self.gateway.handle(
            "acme", "POST", "/o/x", self.headers("done", "d1"), '{}', now_ms=0)
        self.assertEqual(finished["status"], 200)
        thread, held_result = self.start_held(path="/o/y", key="live", request_id="hold",
                                              body='{}')
        write_config(self.path, concurrent_document())  # same content, newer mtime
        self.assertTrue(self.gateway.reload_config())
        duplicate = self.gateway.handle(
            "acme", "POST", "/o/y", self.headers("live", "dup"), '{}', now_ms=1)
        self.assertEqual(duplicate["status"], 425)
        replay = self.gateway.handle(
            "acme", "POST", "/o/x", self.headers("done", "d2"), '{}', now_ms=1)
        self.assertEqual(replay["status"], 200)
        self.assertEqual(replay["headers"]["X-Idempotent-Replay"], "true")
        self.block.release.set()
        thread.join(5)

    def test_capacity_eviction_preserves_the_in_flight_marker_and_live_responses(self):
        thread, held_result = self.start_held(path="/o/y", key="kept", request_id="hold",
                                              body='{}')
        # Fill the table past its sweep threshold with entries that expire at
        # 600000 (window measured from now=0).
        for index in range(1025):
            response = self.gateway.handle(
                "acme", "POST", "/o/z", self.headers("fill-%d" % index, "f%d" % index),
                '{}', now_ms=0)
            self.assertEqual(response["status"], 200)
        # Later: the fill entries are stale, but the long-running marker must
        # never be swept. Publishing the anchor runs the sweep: every stale
        # response disappears while the marker and the fresh anchor remain.
        anchor = self.gateway.handle(
            "acme", "POST", "/o/x", self.headers("anchor", "a0"), '{}', now_ms=700_000)
        self.assertEqual(anchor["status"], 200)
        duplicate = self.gateway.handle(
            "acme", "POST", "/o/y", self.headers("kept", "dup"), '{}', now_ms=700_001)
        self.assertEqual(duplicate["status"], 425)
        anchor_replay = self.gateway.handle(
            "acme", "POST", "/o/x", self.headers("anchor", "a1"), '{}', now_ms=700_001)
        self.assertEqual(anchor_replay["status"], 200)
        self.assertEqual(anchor_replay["headers"]["X-Idempotent-Replay"], "true")
        # A swept stale key is free to execute again instead of replaying.
        stale = self.gateway.handle(
            "acme", "POST", "/o/z", self.headers("fill-0", "f-again"), '{}', now_ms=700_001)
        self.assertEqual(stale["status"], 200)
        self.assertNotIn("X-Idempotent-Replay", stale["headers"])
        self.block.release.set()
        thread.join(5)


class ConcurrentIdempotencyHttpTest(unittest.TestCase):
    """End to end through the real threading HTTP proxy."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-idem-http-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = os.path.join(self.root, "config.json")
        doc = {
            "quota_policies": [],
            "keys": [],
            "routes": [
                {"id": "r-block", "tenant": "*",
                 "match": {"method": "POST", "path_prefix": "/block"},
                 "upstream": "block", "auth_required": False}],
        }
        write_config(self.path, doc)
        self.gateway = Gateway(config_path=self.path,
                               data_dir=os.path.join(self.root, "data"))
        self.block = BlockingUpstream(hold_ids={"http-hold"})
        self.gateway.upstreams.register("block", self.block)
        self.server = create_server(self.gateway, "127.0.0.1", 0, quiet=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]

    def _stop(self):
        self.block.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def post(self, path, body, headers):
        request = urllib.request.Request(
            self.base + path, data=json.dumps(body).encode("utf-8"), method="POST",
            headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, dict(response.headers), response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers or {}), exc.read().decode("utf-8")

    def test_425_409_then_replay_over_http(self):
        held_headers = {"Content-Type": "application/json",
                        "X-Idempotency-Key": "http-k", "X-Request-Id": "http-hold"}
        held = {}

        def call_held():
            held["result"] = self.post("/block/x", {"a": 1}, held_headers)

        thread = threading.Thread(target=call_held)
        thread.start()
        self.assertTrue(self.block.entered.wait(5))

        status, headers, text = self.post(
            "/block/x", {"a": 1},
            {"Content-Type": "application/json", "X-Idempotency-Key": "http-k",
             "X-Request-Id": "http-dup"})
        self.assertEqual(status, 425)
        self.assertEqual(headers["Retry-After"], "1")
        self.assertNotIn("X-Idempotent-Replay", headers)
        payload = json.loads(text)
        self.assertEqual(payload, {"error": IN_PROGRESS_ERROR, "request_id": "http-dup"})

        status, headers, text = self.post(
            "/block/x", {"a": 2},
            {"Content-Type": "application/json", "X-Idempotency-Key": "http-k",
             "X-Request-Id": "http-conf"})
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(text)["request_id"], "http-conf")
        self.assertEqual(self.block.calls, ["http-hold"])

        self.block.release.set()
        thread.join(5)
        self.assertEqual(held["result"][0], 200)

        status, headers, text = self.post(
            "/block/x", {"a": 1},
            {"Content-Type": "application/json", "X-Idempotency-Key": "http-k",
             "X-Request-Id": "http-rep"})
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Idempotent-Replay"], "true")
        self.assertEqual(self.block.calls, ["http-hold"])


if __name__ == "__main__":
    unittest.main()
