"""Unit tests for RateLimiter."""
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from rate_limiter import RateLimiter


class TestRateLimiter:
    def test_allows_requests_within_limit(self):
        limiter = RateLimiter(max_requests=3, window_seconds=10)
        assert limiter.is_allowed('127.0.0.1') is True
        assert limiter.is_allowed('127.0.0.1') is True
        assert limiter.is_allowed('127.0.0.1') is True

    def test_blocks_request_over_limit(self):
        limiter = RateLimiter(max_requests=2, window_seconds=10)
        limiter.is_allowed('10.0.0.1')
        limiter.is_allowed('10.0.0.1')
        assert limiter.is_allowed('10.0.0.1') is False

    def test_allows_after_window_expires(self):
        limiter = RateLimiter(max_requests=1, window_seconds=1)
        assert limiter.is_allowed('192.168.1.1') is True
        assert limiter.is_allowed('192.168.1.1') is False
        time.sleep(1.1)
        assert limiter.is_allowed('192.168.1.1') is True

    def test_single_request_limit(self):
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        assert limiter.is_allowed('172.16.0.1') is True
        assert limiter.is_allowed('172.16.0.1') is False

    def test_initial_state_allows(self):
        limiter = RateLimiter(max_requests=100, window_seconds=60)
        assert limiter.is_allowed('1.2.3.4') is True

    def test_different_clients_tracked_independently(self):
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        assert limiter.is_allowed('10.0.0.1') is True
        assert limiter.is_allowed('10.0.0.1') is False
        # Different client should still be allowed
        assert limiter.is_allowed('10.0.0.2') is True
