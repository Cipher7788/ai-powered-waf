import time


class RateLimiter:
    def __init__(self, max_requests, window_seconds):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # Track request timestamps per client identifier
        self._clients = {}

    def is_allowed(self, client_id='default'):
        # Sliding window rate limiting logic per client
        now = time.time()
        timestamps = self._clients.get(client_id, [])
        # Remove timestamps outside the current window
        timestamps = [ts for ts in timestamps if now - ts < self.window_seconds]
        if len(timestamps) < self.max_requests:
            timestamps.append(now)
            self._clients[client_id] = timestamps
            return True
        self._clients[client_id] = timestamps
        return False
