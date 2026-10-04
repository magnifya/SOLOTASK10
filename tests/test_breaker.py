"""Deterministic tests for the circuit breaker and the retry policy."""

import unittest

from gwd.breaker import CLOSED, HALF_OPEN, OPEN, BreakerRegistry, CircuitBreaker, RetryPolicy


class CircuitBreakerTest(unittest.TestCase):
    def test_closed_open_half_open_closed(self):
        breaker = CircuitBreaker(name="up", failure_threshold=2, open_ms=1000,
                                 half_open_max_probes=1, success_threshold=2)
        self.assertEqual(breaker.state, CLOSED)
        self.assertTrue(breaker.allow(0))
        self.assertEqual(breaker.record(False, 0), CLOSED)  # 1 failure, below threshold
        self.assertEqual(breaker.record(False, 0), OPEN)    # threshold reached
        self.assertFalse(breaker.allow(999))                # still inside open_ms
        self.assertEqual(breaker.rejected, 1)
        self.assertTrue(breaker.allow(1000))                # probe admitted
        self.assertEqual(breaker.state, HALF_OPEN)
        self.assertEqual(breaker.record(True, 1000), HALF_OPEN)  # 1 of 2 successes
        self.assertTrue(breaker.allow(1001))
        self.assertEqual(breaker.record(True, 1001), CLOSED)
        self.assertTrue(breaker.allow(1002))
        self.assertEqual(breaker.failures, 0)

    def test_success_in_closed_resets_the_failure_streak(self):
        breaker = CircuitBreaker(failure_threshold=2, open_ms=1000)
        breaker.record(False, 0)
        breaker.record(True, 1)
        breaker.record(False, 2)
        self.assertEqual(breaker.state, CLOSED)

    def test_half_open_failure_reopens_and_restarts_the_timer(self):
        breaker = CircuitBreaker(failure_threshold=1, open_ms=500, success_threshold=1)
        breaker.allow(0)
        breaker.record(False, 0)
        self.assertEqual(breaker.state, OPEN)
        self.assertTrue(breaker.allow(500))
        self.assertEqual(breaker.record(False, 500), OPEN)
        self.assertFalse(breaker.allow(999))
        self.assertTrue(breaker.allow(1000))
        self.assertEqual(breaker.trips, 2)

    def test_probe_budget_bounds_concurrency(self):
        breaker = CircuitBreaker(failure_threshold=1, open_ms=100, half_open_max_probes=2,
                                 success_threshold=1)
        breaker.allow(0)
        breaker.record(False, 0)
        self.assertFalse(breaker.allow(99))
        self.assertTrue(breaker.allow(100))
        self.assertTrue(breaker.allow(100))
        self.assertFalse(breaker.allow(100))
        self.assertEqual(breaker.record(True, 100), CLOSED)

    def test_snapshot_reports_every_field(self):
        breaker = CircuitBreaker(name="payments", failure_threshold=3, open_ms=7000)
        breaker.allow(0)
        breaker.record(False, 0)
        snapshot = breaker.snapshot()
        self.assertEqual(snapshot["name"], "payments")
        self.assertEqual(snapshot["state"], CLOSED)
        self.assertEqual(snapshot["failures"], 1)
        self.assertEqual(snapshot["failure_threshold"], 3)
        self.assertEqual(snapshot["open_ms"], 7000)
        self.assertIn("opened_at_ms", snapshot)

    def test_registry_reuses_and_resets(self):
        registry = BreakerRegistry(failure_threshold=1, open_ms=10)
        first = registry.get("a")
        self.assertIs(first, registry.get("a"))
        first.allow(0)
        first.record(False, 0)
        self.assertEqual(registry.snapshot()["a"]["state"], OPEN)
        self.assertEqual(registry.reset("a"), ["a"])
        self.assertEqual(registry.get("a").state, CLOSED)
        with self.assertRaises(TypeError):
            BreakerRegistry(nope=1)


class RetryPolicyTest(unittest.TestCase):
    def test_exponential_backoff_is_capped(self):
        policy = RetryPolicy(max_attempts=5, base_ms=100, max_ms=500)
        self.assertEqual([policy.delay_ms(a) for a in (1, 2, 3, 4)], [100, 200, 400, 500])

    def test_should_retry_only_configured_statuses(self):
        policy = RetryPolicy(max_attempts=3)
        self.assertTrue(policy.should_retry(1, 503))
        self.assertTrue(policy.should_retry(1, 0))    # transport error
        self.assertFalse(policy.should_retry(1, 404))
        self.assertFalse(policy.should_retry(3, 503))  # attempt budget exhausted

    def test_default_jitter_is_off(self):
        policy = RetryPolicy()
        self.assertEqual(policy.jitter_ratio, 0.0)
        self.assertEqual(policy.delay_ms(2), policy.delay_ms(2))

    def test_optional_jitter_is_still_deterministic(self):
        policy = RetryPolicy(base_ms=100, jitter_ratio=0.5)
        self.assertEqual(policy.delay_ms(3), policy.delay_ms(3))
        self.assertLessEqual(policy.delay_ms(3), 400)
        self.assertGreater(policy.delay_ms(3), 200)


if __name__ == "__main__":
    unittest.main()
