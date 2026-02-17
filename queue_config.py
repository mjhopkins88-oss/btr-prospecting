"""
Job queue with automatic Redis/RQ detection.
Falls back to threading when Redis is not available.
"""
import os
import threading

REDIS_URL = os.getenv('REDIS_URL')
_use_redis = False
_redis_conn = None
_queue = None

if REDIS_URL:
    try:
        from rq import Queue
        import redis as redis_lib
        _redis_conn = redis_lib.from_url(REDIS_URL)
        _redis_conn.ping()
        _use_redis = True
        _queue = Queue(connection=_redis_conn)
        print("[Queue] Connected to Redis — using RQ")
    except Exception as e:
        print(f"[Queue] Redis unavailable ({e}), using thread fallback")
else:
    print("[Queue] No REDIS_URL set, using thread fallback")


def enqueue(func, *args, job_timeout=600):
    """Enqueue a job. Uses RQ if Redis is available, otherwise spawns a thread."""
    if _use_redis and _queue:
        _queue.enqueue(func, *args, job_timeout=job_timeout)
    else:
        t = threading.Thread(target=func, args=args, daemon=True)
        t.start()


def get_redis_connection():
    """Return the Redis connection if available, else None."""
    return _redis_conn


def is_redis_available():
    return _use_redis
