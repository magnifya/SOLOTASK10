"""Deterministic tests for the rate limit algorithms and the usage ledger."""

import json
import os
import shutil
import tempfile
import unittest

from gwd.config import GatewayError
from gwd.limits import LeakyBucket, Limiter, QuotaLedger, SlidingWindow, TokenBucket


class TokenBucketTest(unittest.TestCase):
    def test_capacity_then_linear_refill(self):
        bucket = TokenBucket(3, 3 / 1000.0)  # 3 tokens per 1000 ms
        results = [bucket.allow(1, 0) for _ in range(4)]
        self.assertEqual([r["allowed"] for r in results], [True, True, True, False])
        self.assertEqual(results[3]["remaining"], 0)
        self.assertEqual(results[3]["reset_at_ms"], 334)  # ceil(1 / 0.003)
        self.assertFalse(bucket.allow(1, 333)["allowed"])  # 0.999 tokens is not enough
        self.assertTrue(bucket.allow(1, 334)["allowed"])

    def test_burst_is_the_capacity(self):
        bucket = TokenBucket(5, 5 / 1000.0)
        self.assertTrue(bucket.allow(5, 0)["allowed"])
        self.assertEqual(bucket.allow(5, 0)["remaining"], 0)
        self.assertFalse(bucket.allow(1, 0)["allowed"])

    def test_refill_is_capped_at_capacity(self):
        bucket = TokenBucket(2, 2 / 1000.0)
        bucket.allow(1, 0)
        result = bucket.allow(1, 100000)
        self.assertTrue(result["allowed"])
        self.assertEqual(result["remaining"], 1)

    def test_clock_skew_does_not_refill(self):
        bucket = TokenBucket(1, 1 / 1000.0)
        self.assertTrue(bucket.allow(1, 1000)["allowed"])
        self.assertFalse(bucket.allow(1, 0)["allowed"])


class LeakyBucketTest(unittest.TestCase):
    def test_overflow_is_rejected_then_leaks(self):
        bucket = LeakyBucket(2, 1 / 1000.0)  # 1 unit per 1000 ms
        self.assertTrue(bucket.allow(1, 0)["allowed"])
        self.assertTrue(bucket.allow(1, 0)["allowed"])
        rejected = bucket.allow(1, 0)
        self.assertFalse(rejected["allowed"])
        self.assertEqual(rejected["remaining"], 0)
        self.assertEqual(rejected["reset_at_ms"], 1000)  # ceil(1 / 0.001)
        self.assertFalse(bucket.allow(1, 999)["allowed"])
        self.assertTrue(bucket.allow(1, 1000)["allowed"])

    def test_cost_larger_than_capacity_is_rejected(self):
        bucket = LeakyBucket(3, 1 / 1000.0)
        self.assertFalse(bucket.allow(4, 0)["allowed"])


class SlidingWindowTest(unittest.TestCase):
    def test_trailing_window_edges(self):
        window = SlidingWindow(3, 1000)
        self.assertEqual([window.allow(1, 0)["allowed"] for _ in range(3)], [True, True, True])
        rejected = window.allow(1, 999)
        self.assertFalse(rejected["allowed"])
        self.assertEqual(rejected["remaining"], 0)
        self.assertEqual(rejected["reset_at_ms"], 1000)
        allowed = window.allow(1, 1000)  # the t=0 stamps just left the window
        self.assertTrue(allowed["allowed"])
        self.assertEqual(allowed["remaining"], 2)

    def test_cost_aware_rejection(self):
        window = SlidingWindow(5, 100)
        self.assertTrue(window.allow(4, 0)["allowed"])
        rejected = window.allow(2, 0)
        self.assertFalse(rejected["allowed"])
        self.assertEqual(rejected["remaining"], 1)
        self.assertEqual(rejected["reset_at_ms"], 100)


class LimiterTest(unittest.TestCase):
    def test_dispatch_and_unknown_policy(self):
        limiter = Limiter([{"id": "p1", "tenant": "t1", "algorithm": "token-bucket",
                            "limit": 2, "window_ms": 1000}])
        first = limiter.allow("p1", 1, 0)
        self.assertTrue(first["allowed"])
        self.assertEqual(first["algorithm"], "token-bucket")
        self.assertEqual(first["policy_id"], "p1")
        self.assertTrue(limiter.allow("p1", 1, 0)["allowed"])
        self.assertFalse(limiter.allow("p1", 1, 0)["allowed"])
        with self.assertRaises(GatewayError):
            limiter.allow("missing", 1, 0)

    def test_sync_keeps_state_and_rebuilds_on_change(self):
        policy = {"id": "p", "tenant": "t", "algorithm": "token-bucket",
                  "limit": 1, "window_ms": 1000}
        limiter = Limiter([policy])
        self.assertTrue(limiter.allow("p", 1, 0)["allowed"])
        limiter.sync([dict(policy)])
        self.assertFalse(limiter.allow("p", 1, 0)["allowed"])
        limiter.sync([dict(policy, limit=2)])
        self.assertTrue(limiter.allow("p", 1, 0)["allowed"])
        limiter.sync([])
        with self.assertRaises(GatewayError):
            limiter.allow("p", 1, 0)


class QuotaLedgerTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gwd-ledger-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.ledger = QuotaLedger(self.root)

    def test_aggregation_and_persistence(self):
        self.ledger.record("t1", "p1", "k1", 1, True, 1000)
        self.ledger.record("t1", "p1", "k1", 1, False, 1100)
        self.ledger.record("t2", "p2", "k2", 3, True, 1200)
        usage = self.ledger.usage("t1")
        self.assertEqual((usage["requests"], usage["allowed"], usage["rejected"]), (2, 1, 1))
        self.assertEqual(usage["allowed_cost"], 1)
        self.assertEqual(usage["by_policy"]["p1"]["rejected"], 1)
        self.assertEqual(self.ledger.usage()["requests"], 3)
        self.assertEqual(self.ledger.usage(None, 1200)["requests"], 1)
        reloaded = QuotaLedger(self.root)
        self.assertEqual(reloaded.usage("t1")["cost"], 2)
        self.assertEqual(len(reloaded.entries("t1")), 2)

    def test_entries_are_one_json_object_per_line(self):
        self.ledger.record("t1", "p1", "k1", 1, True, 1000)
        with open(self.ledger.path, "r", encoding="utf-8") as handle:
            lines = [line for line in handle.read().splitlines() if line]
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry, {"at": 1000, "tenant": "t1", "policy_id": "p1",
                                 "key_id": "k1", "cost": 1, "allowed": True})

    def test_torn_trailing_line_is_ignored(self):
        self.ledger.record("t1", "p1", "k1", 1, True, 1000)
        with open(self.ledger.path, "a", encoding="utf-8") as handle:
            handle.write('{"at": 1001, "tenant": "t1"')
        self.assertEqual(self.ledger.usage("t1")["requests"], 1)


if __name__ == "__main__":
    unittest.main()
