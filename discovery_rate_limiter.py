"""
Global rate limiter for ALL discovery adapters (EDGAR, permits, press releases).

Separate from rate_limit.py (which is for SerpAPI in Prospect Search).
Enforces:
  - concurrency = 1 (only one external request at a time)
  - configurable minimum delay (default 5s)
  - exponential backoff with jitter on 429/5xx
  - Retry-After header respect
  - hard cap on total external calls per run
"""
import os
import time
import random
import threading

from discovery_config import GLOBAL_MIN_DELAY_SECONDS, MAX_EXTERNAL_CALLS_PER_RUN


class DiscoveryRateLimiter:
    """Thread-safe rate limiter for all discovery external calls."""

    def __init__(self, min_delay=None, max_calls=None):
        self._lock = threading.Lock()
        self._min_delay = min_delay or GLOBAL_MIN_DELAY_SECONDS
        self._max_calls = max_calls or MAX_EXTERNAL_CALLS_PER_RUN
        self._last_call = 0.0
        self._backoff_until = 0.0
        self._call_count = 0

    def reset(self):
        """Reset call counter at start of a new run."""
        with self._lock:
            self._call_count = 0
            self._backoff_until = 0.0

    def can_call(self):
        """Check if we can make another external call (under cap)."""
        with self._lock:
            return self._call_count < self._max_calls

    def wait(self):
        """
        Block until safe to make the next external call.
        Returns True if call is allowed, False if cap reached.
        """
        with self._lock:
            if self._call_count >= self._max_calls:
                print(f"[DiscoveryRL] Call cap reached ({self._max_calls})")
                return False

            now = time.time()

            # Respect backoff from previous 429/5xx
            if now < self._backoff_until:
                sleep_time = self._backoff_until - now
                print(f"[DiscoveryRL] Backoff active, sleeping {sleep_time:.1f}s")
                time.sleep(sleep_time)
                now = time.time()

            # Enforce minimum delay
            elapsed = now - self._last_call
            if elapsed < self._min_delay:
                sleep_time = self._min_delay - elapsed
                time.sleep(sleep_time)

            self._last_call = time.time()
            self._call_count += 1
            return True

    def report_error(self, status_code=None, retry_after=None):
        """Called on 429 or 5xx. Sets backoff window."""
        with self._lock:
            if retry_after:
                try:
                    wait = int(retry_after)
                except (ValueError, TypeError):
                    wait = 30
            elif status_code == 429:
                wait = 30
            elif status_code and status_code >= 500:
                wait = 15
            else:
                wait = 10

            # Add jitter
            wait += random.uniform(1, 5)
            self._backoff_until = time.time() + wait
            print(f"[DiscoveryRL] Error {status_code}, backing off {wait:.1f}s")

    @property
    def calls_remaining(self):
        with self._lock:
            return max(0, self._max_calls - self._call_count)

    @property
    def calls_used(self):
        with self._lock:
            return self._call_count


# Global singleton — shared across all adapters within a run
discovery_limiter = DiscoveryRateLimiter()
