#!/usr/bin/env python
"""
RQ worker for processing prospecting jobs.
Requires REDIS_URL environment variable.

Usage:
    python worker.py
"""
import os
import sys
from dotenv import load_dotenv
load_dotenv()

REDIS_URL = os.getenv('REDIS_URL')
if not REDIS_URL:
    print("[Worker] REDIS_URL not set. The web process will use thread fallback instead.")
    print("[Worker] Set REDIS_URL to use a dedicated worker process.")
    sys.exit(0)

try:
    from rq import Worker, Queue
    import redis
except ImportError:
    print("[Worker] rq/redis packages not installed. Run: pip install rq redis")
    sys.exit(1)

conn = redis.from_url(REDIS_URL)

if __name__ == '__main__':
    print(f"[Worker] Starting RQ worker, connected to Redis...")
    worker = Worker([Queue(connection=conn)], connection=conn)
    worker.work()
