"""
Base adapter class for discovery sources.

Each adapter returns a list of discovery items with a standard schema:
{
    'title': str,
    'url': str,
    'snippet': str,
    'published_at': str,
    'source_name': str,
    'source_type': 'filing' | 'permit' | 'news' | 'press_release',
    'confidence': 'high' | 'medium' | 'low',
    'city': str,
    'state': str,
    'entity_name': str,       # company or project name (if known)
    'signal_type': str,       # pre-classified if adapter can determine it
}
"""
import traceback


class BaseAdapter:
    """Abstract base for discovery source adapters."""

    name = 'base'
    source_type = 'news'  # default; subclasses override

    def __init__(self, limiter):
        self.limiter = limiter

    def fetch(self, cities, config):
        """
        Fetch discovery items for the given cities.
        Must return a list of item dicts (see schema above).
        Implementations must call self.limiter.wait() before each external request.
        """
        raise NotImplementedError

    def safe_fetch(self, cities, config):
        """Wrapper that catches exceptions so one adapter failing doesn't crash the run."""
        try:
            return self.fetch(cities, config)
        except Exception as e:
            print(f"[{self.name}] Adapter failed: {e}")
            traceback.print_exc()
            return []
