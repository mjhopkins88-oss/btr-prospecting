"""
Queue helpers for the Lead Intelligence Platform.
Re-exports from queue_config.py and adds pipeline-specific queue names.
"""
from queue_config import enqueue as _enqueue, get_redis_connection, is_redis_available

# Named queues for different pipeline stages
QUEUE_COLLECT = 'li_collect'
QUEUE_NORMALIZE = 'li_normalize'
QUEUE_RESOLVE = 'li_resolve'
QUEUE_ENRICH = 'li_enrich'
QUEUE_SCORE = 'li_score'
QUEUE_ROUTE = 'li_route'
QUEUE_BRIEF = 'li_brief'


def enqueue(func, *args, queue_name=None, job_timeout=600):
    """
    Enqueue a job.  If Redis is available and queue_name is given,
    enqueue on that specific RQ queue; otherwise fall back to the
    default enqueue (thread fallback when no Redis).
    """
    if queue_name and is_redis_available():
        try:
            from rq import Queue
            conn = get_redis_connection()
            q = Queue(queue_name, connection=conn)
            return q.enqueue(func, *args, job_timeout=job_timeout)
        except Exception:
            pass
    # fallback
    return _enqueue(func, *args, job_timeout=job_timeout)
