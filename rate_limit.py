"""
Global rate limiter for SerpAPI calls.

Shared by both Prospect Search and Daily Discovery.
Ensures only one SerpAPI call at a time per worker process,
with configurable minimum delay and exponential backoff on 429s.
"""
import os
import time
import random
import threading


MIN_DELAY = float(os.getenv('SERP_MIN_DELAY_SECONDS', '3'))
MAX_RETRIES = 5


class SerpRateLimiter:
    """Thread-safe token-bucket style limiter for SerpAPI."""

    def __init__(self, min_delay=MIN_DELAY):
        self._lock = threading.Lock()
        self._min_delay = min_delay
        self._last_call = 0.0
        self._backoff_until = 0.0  # timestamp until which we should wait

    def wait(self):
        """Block until it's safe to make the next SerpAPI call."""
        with self._lock:
            now = time.time()

            # Respect backoff from a previous 429
            if now < self._backoff_until:
                sleep_time = self._backoff_until - now
                print(f"[RateLimit] Backoff active, sleeping {sleep_time:.1f}s")
                time.sleep(sleep_time)
                now = time.time()

            # Enforce minimum delay between calls
            elapsed = now - self._last_call
            if elapsed < self._min_delay:
                sleep_time = self._min_delay - elapsed
                time.sleep(sleep_time)

            self._last_call = time.time()

    def report_429(self, retry_after_header=None):
        """Called when SerpAPI returns 429. Sets backoff window."""
        with self._lock:
            if retry_after_header:
                try:
                    wait = int(retry_after_header)
                except (ValueError, TypeError):
                    wait = 30
            else:
                wait = 30

            # Add jitter
            wait += random.uniform(1, 5)
            self._backoff_until = time.time() + wait
            print(f"[RateLimit] 429 received, backing off for {wait:.1f}s")


# Global singleton shared across the process
serp_limiter = SerpRateLimiter()
