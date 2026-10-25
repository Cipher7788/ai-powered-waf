"""Thread-safe, bounded in-memory sliding-window rate limiter."""
from collections import deque
import threading
import time


class RateLimiter:
    def __init__(self, max_requests=100, window_seconds=60, max_clients=10000):
        self.max_requests = self._positive_int(max_requests, "max_requests")
        self.window_seconds = self._positive_number(window_seconds, "window_seconds")
        self.max_clients = self._positive_int(max_clients, "max_clients")
        self._clients = {}
        self._lock = threading.Lock()

    @staticmethod
    def _positive_int(value, name):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"{name} must be a positive integer")
        return value

    @staticmethod
    def _positive_number(value, name):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            raise ValueError(f"{name} must be a positive number")
        return float(value)

    def configure(self, max_requests=None, window_seconds=None):
        with self._lock:
            if max_requests is not None:
                self.max_requests = self._positive_int(max_requests, "max_requests")
            if window_seconds is not None:
                self.window_seconds = self._positive_number(window_seconds, "window_seconds")

    def is_allowed(self, client_id="default"):
        now = time.monotonic()
        key = str(client_id or "unknown")[:256]
        with self._lock:
            for client, timestamps in list(self._clients.items()):
                while timestamps and now - timestamps[0] >= self.window_seconds:
                    timestamps.popleft()
                if not timestamps:
                    self._clients.pop(client, None)
            timestamps = self._clients.get(key)
            if timestamps is None:
                if len(self._clients) >= self.max_clients:
                    oldest = min(self._clients, key=lambda item: self._clients[item][0])
                    self._clients.pop(oldest, None)
                timestamps = deque()
                self._clients[key] = timestamps
            if len(timestamps) >= self.max_requests:
                return False
            timestamps.append(now)
            return True
