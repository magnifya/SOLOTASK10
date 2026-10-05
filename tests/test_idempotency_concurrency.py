"""Concurrency tests for the in-progress idempotency guard.

A blocking upstream (released explicitly by the test) parks the first request
inside the upstream chain while follower requests run on other threads, so the
425/409 behaviour is exercised against real concurrency without sleeping.
"""

import json
import os
import shutil
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from gwd.gateway import Gateway
from gwd.http_app import create_server
from gwd.upstream import UpstreamError

from tests.test_gateway import document, make_gateway, write_config


class BlockingUpstream:
    """Parks every call until ``release`` is set; tracks concurrency."""

    def __init__(self, response=None):
        self.entered = threading.Event()
        self.release = threading.Event()
        self._lock = threading.Lock()
        self.calls = 0
        self.active = 0
        self.max_active = 0
        self.response = response if response is not None else {
            "status": 200, "body": {"ok": True}}

    def __call__(self, request):
        with self._lock:
            self.calls += 1
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.entered.set()
        self.release.wait(5)
        with self._lock:
            self.active -= 1
        return dict(self.response)

    def wait_for_active(self, count, timeout=2.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.max_active >= count:
                return True
            time.sleep(0.01)
        return False


class FailingUpstream:
    def __init__(self, failure):
        self.failure = failure
        self.calls = 0

    def __call__(self, request):
        self.calls += 1
        if self.failure == "transport":
            raise UpstreamError("boom")
        return {"status": int(self.failure), "body": {"error": "down"}}


class InProgressIdempotencyTest(unittest.TestCase):
    def setUp(self):
        # A high failure threshold lets a failed leader retry later without an
        # open breaker masking whether the guard was released.
        self.gateway, self.root, self.path = make_gateway(
            breaker_settings={"failure_threshold": 9, "open_ms": 1000,
                              "success_threshold": 1})
        self.addCleanup(shutil.rmtree, self.root, True)
        self.blocker = BlockingUpstream()
        self.gateway.upstreams.register("count", self.blocker)
        self.gateway.upstreams.register("echo", self.blocker)

    def body_of(self, response):
        return json.loads(response["body"])

    def start(self, target, *args, **kwargs):
        box = {}

        def work():
            box["response"] = target(*args, **kwargs)

        thread = threading.Thread(target=work)
        thread.start()
        return thread, box

    def hold(self, key="k-1", tenant="acme", body='{"a": 1}', path="/count/x",
             method="POST", request_id=None, now_ms=0):
        headers = {"x-idempotency-key": key}
        if request_id is not None:
            headers["x-request-id"] = request_id
        thread, box = self.start(self.gateway.handle, tenant, method, path,
                                 headers, body, now_ms)
        self.assertTrue(self.blocker.entered.wait(2), "leader never entered the upstream")
        return thread, box, headers

    def release_and_join(self, thread, box):
        self.blocker.release.set()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        return box["response"]

    # ------------------------------------------------------------- 425 / 409
    def test_same_scope_same_body_in_flight_is_425(self):
        thread, box, headers = self.hold(request_id="leader-1")
        follower = self.gateway.handle("acme", "POST", "/count/x",
                                      dict(headers, **{"x-request-id": "follower-1"}),
                                      '{"a": 1}', now_ms=0)
        self.assertEqual(follower["status"], 425)
        self.assertEqual(self.body_of(follower)["error"], "idempotency request in progress")
        self.assertEqual(self.body_of(follower)["request_id"], "follower-1")
        self.assertEqual(follower["request_id"], "follower-1")
        self.assertEqual(follower["headers"]["Retry-After"], "1")
        self.assertNotIn("X-Idempotent-Replay", follower["headers"])
        self.assertEqual(self.blocker.calls, 1)
        leader = self.release_and_join(thread, box)
        self.assertEqual(leader["status"], 200)
        self.assertEqual(leader["request_id"], "leader-1")

    def test_same_scope_different_body_in_flight_is_the_existing_409(self):
        thread, box, headers = self.hold()
        follower = self.gateway.handle("acme", "POST", "/count/x", headers,
                                      '{"a": 2}', now_ms=0)
        self.assertEqual(follower["status"], 409)
        self.assertIn("different request body", self.body_of(follower)["error"])
        self.assertNotIn("Retry-After", follower["headers"])
        self.assertNotIn("X-Idempotent-Replay", follower["headers"])
        self.assertEqual(self.blocker.calls, 1)
        self.release_and_join(thread, box)

    def test_neither_rejection_calls_the_upstream_or_carries_a_replay_mark(self):
        thread, box, headers = self.hold()
        same = self.gateway.handle("acme", "POST", "/count/x", headers, '{"a": 1}', now_ms=0)
        other = self.gateway.handle("acme", "POST", "/count/x", headers, '{"a": 2}', now_ms=0)
        self.assertEqual((same["status"], other["status"]), (425, 409))
        for response in (same, other):
            self.assertNotIn("X-Idempotent-Replay", response["headers"])
        self.assertEqual(self.blocker.calls, 1)
        self.release_and_join(thread, box)

    def test_guard_holds_past_the_replay_window(self):
        # The follower's now_ms is beyond the first request's cache window while
        # the first request is still running: it must not be forwarded.
        thread, box, headers = self.hold(now_ms=0)
        late = self.gateway.handle("acme", "POST", "/count/x", headers,
                                   '{"a": 1}', now_ms=10 ** 9)
        self.assertEqual(late["status"], 425)
        self.assertEqual(self.blocker.calls, 1)
        self.release_and_join(thread, box)

    # --------------------------------------------------------- after release
    def test_after_success_the_response_replays_within_the_window(self):
        thread, box, headers = self.hold()
        self.release_and_join(thread, box)
        replay = self.gateway.handle("acme", "POST", "/count/x", headers,
                                     '{"a": 1}', now_ms=100)
        self.assertEqual(replay["status"], 200)
        self.assertEqual(replay["headers"]["X-Idempotent-Replay"], "true")
        self.assertEqual(self.blocker.calls, 1)
        conflict = self.gateway.handle("acme", "POST", "/count/x", headers,
                                       '{"a": 9}', now_ms=100)
        self.assertEqual(conflict["status"], 409)
        self.assertEqual(self.blocker.calls, 1)

    def test_rejections_while_in_progress_are_never_cached(self):
        thread, box, headers = self.hold()
        rejected = self.gateway.handle("acme", "POST", "/count/x", headers,
                                       '{"a": 1}', now_ms=0)
        self.assertEqual(rejected["status"], 425)
        self.release_and_join(thread, box)
        # The stored response is the leader's 200, not the 425: a follow-up
        # replays 200 and still makes no new upstream call.
        replay = self.gateway.handle("acme", "POST", "/count/x", headers,
                                     '{"a": 1}', now_ms=1)
        self.assertEqual(replay["status"], 200)
        self.assertEqual(replay["headers"]["X-Idempotent-Replay"], "true")
        self.assertEqual(self.blocker.calls, 1)

    def test_final_transport_failure_releases_the_guard_and_is_not_cached(self):
        failing = FailingUpstream("transport")
        self.gateway.upstreams.register("count", failing)
        headers = {"x-idempotency-key": "fail-1"}
        first = self.gateway.handle("acme", "POST", "/count/x", headers, "{}", now_ms=0)
        self.assertEqual(first["status"], 502)
        self.assertEqual(failing.calls, 3)  # the usual retry budget, no cache
        second = self.gateway.handle("acme", "POST", "/count/x", headers, "{}", now_ms=1)
        self.assertEqual(second["status"], 502)
        self.assertNotIn("X-Idempotent-Replay", second["headers"])
        self.assertEqual(failing.calls, 6)  # released: the request executed again
        self.assertNotIn(("acme", "fail-1"), self.gateway._idem_inflight)

    def test_final_5xx_releases_the_guard(self):
        failing = FailingUpstream(500)
        self.gateway.upstreams.register("count", failing)
        headers = {"x-idempotency-key": "fail-5xx"}
        first = self.gateway.handle("acme", "POST", "/count/x", headers, "{}", now_ms=0)
        self.assertEqual(first["status"], 500)
        second = self.gateway.handle("acme", "POST", "/count/x", headers, "{}", now_ms=1)
        self.assertEqual(second["status"], 500)
        self.assertEqual(failing.calls, 6)
        self.assertNotIn(("acme", "fail-5xx"), self.gateway._idem_inflight)

    def test_all_breakers_rejected_releases_without_caching(self):
        for _ in range(9):  # setUp's failure threshold is 9
            self.gateway.breakers.get("count").record(False, 0)
        headers = {"x-idempotency-key": "breaker-1"}
        rejected = self.gateway.handle("acme", "POST", "/count/x", headers, "{}", now_ms=1)
        self.assertEqual(rejected["status"], 503)
        self.assertNotIn(("acme", "breaker-1"), self.gateway._idem_inflight)
        self.gateway.breaker_reset("count")
        self.blocker.release.set()  # let the retried request finish without parking
        retry = self.gateway.handle("acme", "POST", "/count/x", headers, "{}", now_ms=2)
        self.assertEqual(retry["status"], 200)  # the scope was free to execute again
        self.assertEqual(self.blocker.calls, 1)

    # --------------------------------------------------------------- scoping
    def _parallel_route(self, route_id, tenant, upstream_name, blocker):
        self.gateway.upstreams.register(upstream_name, blocker)
        self.gateway.add_route({"id": route_id, "tenant": tenant,
                                "match": {"method": "POST", "path_prefix": "/" + upstream_name},
                                "upstream": upstream_name, "auth_required": False})

    def test_different_tenants_run_concurrently(self):
        other = BlockingUpstream()
        self._parallel_route("r-other", "globex", "other", other)
        first, box1, _ = self.hold(tenant="acme", key="shared")
        second, box2 = self.start(
            self.gateway.handle, "globex", "POST", "/other/x",
            {"x-idempotency-key": "shared"}, '{"a": 1}', 0)
        self.assertTrue(other.entered.wait(2))
        self.assertEqual((self.blocker.calls, other.calls), (1, 1))
        self.blocker.release.set()
        other.release.set()
        first.join(5)
        second.join(5)
        self.assertEqual((box1["response"]["status"], box2["response"]["status"]), (200, 200))

    def test_different_keys_run_concurrently(self):
        other = BlockingUpstream()
        self._parallel_route("r-other", "acme", "other", other)
        first, box1, _ = self.hold(tenant="acme", key="key-a")
        second, box2 = self.start(
            self.gateway.handle, "acme", "POST", "/other/x",
            {"x-idempotency-key": "key-b"}, '{"a": 1}', 0)
        self.assertTrue(other.entered.wait(2))
        self.assertEqual((self.blocker.calls, other.calls), (1, 1))
        self.blocker.release.set()
        other.release.set()
        first.join(5)
        second.join(5)
        self.assertEqual((box1["response"]["status"], box2["response"]["status"]), (200, 200))

    def test_scope_is_a_tuple_separator_in_values_cannot_alias(self):
        # Under the old "%s|%s" string scope these two would alias; as
        # (tenant, key) tuples they are different scopes and run together.
        other = BlockingUpstream()
        self._parallel_route("r-other", "*", "other", other)
        first, box1, _ = self.hold(tenant="a", key="b|c")
        second, box2 = self.start(
            self.gateway.handle, "a|b", "POST", "/other/x",
            {"x-idempotency-key": "c"}, '{"a": 1}', 0)
        self.assertTrue(other.entered.wait(2))
        self.assertEqual((self.blocker.calls, other.calls), (1, 1))
        self.blocker.release.set()
        other.release.set()
        first.join(5)
        second.join(5)
        self.assertEqual((box1["response"]["status"], box2["response"]["status"]), (200, 200))

    def test_missing_or_empty_idempotency_key_keeps_concurrent_behaviour(self):
        # No guard: a keyless and an empty-key request sit in the chain together.
        first, box1 = self.start(self.gateway.handle, "acme", "POST", "/count/x",
                                 {}, '{"a": 1}', 0)
        self.assertTrue(self.blocker.entered.wait(2))
        second, box2 = self.start(self.gateway.handle, "acme", "POST", "/count/x",
                                  {"x-idempotency-key": ""}, '{"a": 1}', 0)
        self.assertTrue(self.blocker.wait_for_active(2))
        self.blocker.release.set()
        first.join(5)
        second.join(5)
        self.assertEqual((box1["response"]["status"], box2["response"]["status"]), (200, 200))

    # ---------------------------------------------------------------- quota
    def auth_headers(self, key="idem-q"):
        # r-api in the shared document requires the read secret and quota p-fast.
        return {"authorization": "Bearer read-secret", "x-idempotency-key": key}

    def test_each_concurrent_request_passes_quota_independently_before_the_guard(self):
        headers = self.auth_headers()
        thread, box = self.start(
            self.gateway.handle, "acme", "GET", "/api/items", headers, "", 0)
        self.assertTrue(self.blocker.entered.wait(2))
        follower = self.gateway.handle(
            "acme", "GET", "/api/items",
            dict(headers, **{"x-request-id": "follower-q"}), "", 0)
        self.assertEqual(follower["status"], 425)
        # Both requests passed quota and paid one unit each (p-fast limit 2).
        usage = self.gateway.usage("acme")
        self.assertEqual((usage["requests"], usage["allowed"], usage["allowed_cost"]), (2, 2, 2))
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual((entry["request_id"], entry["status"], entry["attempts"],
                          entry["idempotent_replay"]),
                         ("follower-q", 425, 0, False))
        self.assertEqual(entry["quota"], {"policy_id": "p-fast", "allowed": True,
                                          "remaining": 0})
        self.assertEqual(entry["route_id"], "r-api")
        self.blocker.release.set()
        thread.join(5)

    def test_quota_rejection_wins_and_never_occupies_the_scope(self):
        headers = self.auth_headers()
        thread, box = self.start(
            self.gateway.handle, "acme", "GET", "/api/items", headers, "", 0)
        self.assertTrue(self.blocker.entered.wait(2))
        self.assertEqual(self.gateway.handle(
            "acme", "GET", "/api/items", headers, "", 0)["status"], 425)
        # Third unit: over p-fast (limit 2), quota wins before the guard runs.
        throttled = self.gateway.handle(
            "acme", "GET", "/api/items", headers, "", 0)
        self.assertEqual(throttled["status"], 429)
        self.assertEqual(throttled["headers"]["Retry-After"], "30")
        self.blocker.release.set()
        thread.join(5)
        # The 429 never touched the scope: a fresh key after the refill can run.
        rerun = self.gateway.handle(
            "acme", "GET", "/api/items",
            {"authorization": "Bearer read-secret", "x-idempotency-key": "idem-q2"},
            "", 60000)
        self.assertEqual(rerun["status"], 200)

    def test_joint_quota_is_all_or_none_and_billed_per_request(self):
        doc = document()
        doc["quota_policies"].extend([
            {"id": "p-a", "tenant": "acme", "algorithm": "token-bucket",
             "limit": 2, "window_ms": 60000, "burst": 2},
            {"id": "p-b", "tenant": "acme", "algorithm": "token-bucket",
             "limit": 2, "window_ms": 60000, "burst": 2}])
        doc["routes"].append({
            "id": "r-joint", "tenant": "acme", "match": {"method": "POST", "path_prefix": "/joint"},
            "upstream": "count", "auth_required": False,
            "quota_policies": ["p-a", "p-b"]})
        write_config(self.path, doc)
        self.assertTrue(self.gateway.reload_config())
        headers = {"x-idempotency-key": "joint-1"}
        thread, box = self.start(
            self.gateway.handle, "acme", "POST", "/joint/x", headers, "{}", 0)
        self.assertTrue(self.blocker.entered.wait(2))
        follower = self.gateway.handle("acme", "POST", "/joint/x", headers, "{}", 0)
        self.assertEqual(follower["status"], 425)
        usage = self.gateway.usage("acme")
        # Two requests, one record per policy each, every record admitted.
        self.assertEqual(usage["requests"], 4)
        self.assertEqual(usage["allowed"], 4)
        entry = self.gateway.audit("acme", 1)[0]
        self.assertEqual([q["policy_id"] for q in entry["quotas"]], ["p-a", "p-b"])
        self.assertTrue(all(q["allowed"] for q in entry["quotas"]))
        self.blocker.release.set()
        thread.join(5)

    def test_auth_rejection_does_not_occupy_the_scope(self):
        headers = {"x-idempotency-key": "auth-scope"}
        denied = self.gateway.handle("acme", "GET", "/api/items", headers, "", now_ms=0)
        self.assertEqual(denied["status"], 401)
        self.assertNotIn(("acme", "auth-scope"), self.gateway._idem_inflight)
        self.blocker.release.set()  # the authorized retry must not park
        allowed = self.gateway.handle(
            "acme", "GET", "/api/items",
            {"authorization": "Bearer read-secret", "x-idempotency-key": "auth-scope"},
            "", now_ms=1)
        self.assertEqual(allowed["status"], 200)  # the scope was free

    # ---------------------------------------------------------------- audit
    def test_one_audit_entry_per_request_with_zero_attempts_for_rejections(self):
        thread, box, headers = self.hold()
        self.gateway.handle("acme", "POST", "/count/x",
                           dict(headers, **{"x-request-id": "f-same"}), '{"a": 1}', 0)
        self.gateway.handle("acme", "POST", "/count/x",
                           dict(headers, **{"x-request-id": "f-diff"}), '{"a": 2}', 0)
        self.release_and_join(thread, box)
        entries = self.gateway.audit("acme", 3)
        by_id = {e["request_id"]: e for e in entries}
        for rid, status in (("f-same", 425), ("f-diff", 409)):
            entry = by_id[rid]
            self.assertEqual(entry["status"], status)
            self.assertEqual((entry["attempts"], entry["idempotent_replay"]), (0, False))
            self.assertIsNone(entry["quota"]["policy_id"])  # /count names no policy

    # --------------------------------------------------------- fan-out / gap
    def test_fan_out_while_in_flight_runs_the_upstream_exactly_once(self):
        thread, box = self.start(
            self.gateway.handle, "acme", "POST", "/count/x",
            {"x-idempotency-key": "fan-1", "x-request-id": "leader"}, '{"a": 1}', 0)
        self.assertTrue(self.blocker.entered.wait(2))
        results = []

        def follower(index):
            response = self.gateway.handle(
                "acme", "POST", "/count/x",
                {"x-idempotency-key": "fan-1", "x-request-id": "f-%02d" % index},
                '{"a": 1}', 0)
            results.append(response["status"])

        followers = [threading.Thread(target=follower, args=(i,)) for i in range(20)]
        for worker in followers:
            worker.start()
        for worker in followers:
            worker.join(5)
        self.assertEqual(results, [425] * 20)
        self.assertEqual(self.blocker.calls, 1)
        leader = self.release_and_join(thread, box)
        self.assertEqual(leader["status"], 200)
        # Once published, retries are replays with no gap allowing a 2nd call.
        for index in range(20):
            replay = self.gateway.handle(
                "acme", "POST", "/count/x",
                {"x-idempotency-key": "fan-1", "x-request-id": "r-%02d" % index},
                '{"a": 1}', 100)
            self.assertEqual(replay["headers"]["X-Idempotent-Replay"], "true")
        self.assertEqual(self.blocker.calls, 1)

    def test_publish_race_has_no_window_allowing_a_second_execution(self):
        # Fire a burst at the exact moment the leader finishes: every follower
        # must either still see 425 or see the published replay. A 200 without
        # the replay header would mean a gap that let the chain run twice.
        gate = threading.Event()
        thread, box = self.start(
            self.gateway.handle, "acme", "POST", "/count/x",
            {"x-idempotency-key": "race-1", "x-request-id": "leader"}, '{"a": 1}', 0)
        self.assertTrue(self.blocker.entered.wait(2))
        outcomes = []

        def follower(index):
            gate.wait(5)
            response = self.gateway.handle(
                "acme", "POST", "/count/x",
                {"x-idempotency-key": "race-1", "x-request-id": "g-%02d" % index},
                '{"a": 1}', 0)
            outcomes.append(response)

        workers = [threading.Thread(target=follower, args=(i,)) for i in range(30)]
        for worker in workers:
            worker.start()
        self.blocker.release.set()
        gate.set()  # burst collides with publish
        thread.join(5)
        for worker in workers:
            worker.join(5)
        self.assertEqual(box["response"]["status"], 200)
        statuses = {r["status"] for r in outcomes}
        self.assertTrue(statuses <= {200, 425}, statuses)
        for response in outcomes:
            if response["status"] == 200:
                self.assertEqual(response["headers"]["X-Idempotent-Replay"], "true")
        self.assertEqual(self.blocker.calls, 1)

    def test_cache_pruning_keeps_the_in_flight_guard_and_unexpired_responses(self):
        fast = BlockingUpstream()
        fast.release.set()
        self._parallel_route("r-fast", "*", "fast", fast)
        thread, box, held = self.hold(key="prune-hold")
        # Push past the 1024-entry prune threshold on other, completed scopes.
        for index in range(1030):
            response = self.gateway.handle(
                "acme", "POST", "/fast/x",
                {"x-idempotency-key": "bulk-%04d" % index}, '{"a": 1}', 0)
            self.assertEqual(response["status"], 200)
        # Pruning replaced the response dict, but the held scope is still guarded
        # and an unexpired bulk response still replays.
        follower = self.gateway.handle("acme", "POST", "/count/x", held,
                                       '{"a": 1}', 0)
        self.assertEqual(follower["status"], 425)
        bulk_replay = self.gateway.handle(
            "acme", "POST", "/fast/x", {"x-idempotency-key": "bulk-0007"},
            '{"a": 1}', 0)
        self.assertEqual(bulk_replay["headers"]["X-Idempotent-Replay"], "true")
        self.assertEqual(fast.calls, 1030)  # the replay added none
        self.release_and_join(thread, box)

    def test_hot_reload_keeps_the_in_flight_guard_and_cached_responses(self):
        thread, box, headers = self.hold(key="reload-1")
        write_config(self.path, document())
        self.assertTrue(self.gateway.reload_config())
        follower = self.gateway.handle("acme", "POST", "/count/x", headers,
                                       '{"a": 1}', 0)
        self.assertEqual(follower["status"], 425)
        self.release_and_join(thread, box)
        replay = self.gateway.handle("acme", "POST", "/count/x", headers,
                                     '{"a": 1}', 100)
        self.assertEqual(replay["headers"]["X-Idempotent-Replay"], "true")
        self.assertEqual(self.blocker.calls, 1)


class InProgressHttpTest(unittest.TestCase):
    """End to end through the ThreadingHTTPServer proxy surface."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-idem-http-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.config_path = os.path.join(self.root, "config.json")
        with open(self.config_path, "w", encoding="utf-8") as handle:
            json.dump(document(), handle)
        self.gateway = Gateway(config_path=self.config_path,
                               data_dir=os.path.join(self.root, "data"))
        self.blocker = BlockingUpstream()
        self.gateway.upstreams.register("echo", self.blocker)
        self.server = create_server(self.gateway, "127.0.0.1", 0, quiet=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]

    def _stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def post(self, request_id, key="http-inflight", body=None):
        data = json.dumps({"a": 1} if body is None else body).encode("utf-8")
        request = urllib.request.Request(
            self.base + "/open/x", data=data, method="POST",
            headers={"Content-Type": "application/json",
                     "X-Idempotency-Key": key, "X-Request-Id": request_id})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, dict(response.headers), response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers or {}), exc.read().decode("utf-8")

    def test_in_flight_425_over_http_then_replay(self):
        box = {}

        def leader():
            box["response"] = self.post("leader-http")

        first = threading.Thread(target=leader)
        first.start()
        self.assertTrue(self.blocker.entered.wait(2))
        status, headers, text = self.post("follower-http")
        self.assertEqual(status, 425)
        self.assertEqual(headers["Retry-After"], "1")
        payload = json.loads(text)
        self.assertEqual(payload["error"], "idempotency request in progress")
        self.assertEqual(payload["request_id"], "follower-http")
        self.blocker.release.set()
        first.join(5)
        self.assertEqual(box["response"][0], 200)
        status, headers, text = self.post("replay-http")
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Idempotent-Replay"], "true")
        self.assertEqual(self.blocker.calls, 1)

    def test_in_flight_different_body_is_409_over_http(self):
        box = {}

        def leader():
            box["response"] = self.post("leader-http-2")

        first = threading.Thread(target=leader)
        first.start()
        self.assertTrue(self.blocker.entered.wait(2))
        status, headers, text = self.post("follower-http-2", body={"a": 2})
        self.assertEqual(status, 409)
        self.assertNotIn("Retry-After", headers)
        self.blocker.release.set()
        first.join(5)
        self.assertEqual(self.blocker.calls, 1)


if __name__ == "__main__":
    unittest.main()
