"""
Press Release Adapter — searches PRNewswire/BusinessWire + company IR pages via SerpAPI.

Uses the existing SerpAPI infrastructure (cached_serpapi_search) with
discovery-specific queries. Results cached for 24h via serpapi_client cache.
"""
import os
from datetime import datetime

from adapters.base import BaseAdapter
from discovery_config import MONITORED_OPERATORS

# Press release query templates
PR_QUERIES = [
    'site:prnewswire.com ("build to rent" OR "single family rental" OR BTR) "{city}" {year}',
    'site:businesswire.com ("build to rent" OR "single family rental" OR BTR) "{city}" {year}',
]

# Operator-specific IR queries (one per operator)
OPERATOR_IR_QUERIES = [
    '("{operator}" AND ("build to rent" OR BTR OR "single family rental") AND (acquisition OR expansion OR new OR development)) {year}',
]


class PressReleaseAdapter(BaseAdapter):
    name = 'press_release'
    source_type = 'press_release'

    def fetch(self, cities, config):
        items = []
        year = datetime.now().year

        # 1. City-based PR searches
        for city_info in cities:
            if not self.limiter.can_call():
                break

            city = city_info['city']
            state = city_info['state']
            city_items = self._search_city_prs(city, state, year)
            items.extend(city_items)

        # 2. Operator-specific IR searches
        for operator_name in MONITORED_OPERATORS:
            if not self.limiter.can_call():
                break

            op_items = self._search_operator_prs(operator_name, year)
            items.extend(op_items)

        return items

    def _search_city_prs(self, city, state, year):
        """Search for city-specific press releases via SerpAPI."""
        items = []

        for query_template in PR_QUERIES:
            if not self.limiter.wait():
                break

            query = query_template.format(city=city, year=year)

            try:
                results = self._serpapi_search(query, city, state)
                for r in results:
                    items.append({
                        'title': r.get('title', ''),
                        'url': r.get('link', ''),
                        'snippet': r.get('snippet', ''),
                        'published_at': r.get('date', ''),
                        'source_name': r.get('source', 'PRNewswire/BusinessWire'),
                        'source_type': 'press_release',
                        'confidence': 'high',
                        'city': city,
                        'state': state,
                        'entity_name': '',
                        'signal_type': '',  # will be classified later
                    })
            except Exception as e:
                print(f"[PressRelease] Error searching {city}: {e}")

        return items

    def _search_operator_prs(self, operator_name, year):
        """Search for operator-specific press releases."""
        items = []

        for query_template in OPERATOR_IR_QUERIES:
            if not self.limiter.wait():
                break

            query = query_template.format(operator=operator_name, year=year)

            try:
                results = self._serpapi_search(query, '', '')
                for r in results:
                    items.append({
                        'title': r.get('title', ''),
                        'url': r.get('link', ''),
                        'snippet': r.get('snippet', ''),
                        'published_at': r.get('date', ''),
                        'source_name': r.get('source', ''),
                        'source_type': 'press_release',
                        'confidence': 'medium',
                        'city': '',
                        'state': '',
                        'entity_name': operator_name,
                        'signal_type': '',
                    })
            except Exception as e:
                print(f"[PressRelease] Error searching operator {operator_name}: {e}")

        return items

    def _serpapi_search(self, query, city, state):
        """
        Search via SerpAPI or Claude web_search fallback.
        Uses the existing serpapi_client cache (24h TTL).
        """
        serp_key = os.getenv('SERPAPI_API_KEY', '')
        if serp_key:
            from serpapi_client import cached_serpapi_search
            return cached_serpapi_search(
                query, num=5, feature='discovery_pr', city=city, state=state
            )
        else:
            # Fallback: use Claude web_search
            return self._claude_web_search(query, city, state)

    def _claude_web_search(self, query, city, state):
        """Fallback search using Claude web_search tool."""
        import anthropic
        import json

        client = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))

        prompt = f"""Search for: {query}

Return ONLY a JSON array of search results:
[
  {{"title": "...", "link": "https://...", "snippet": "...", "date": "...", "source": "..."}}
]

Return up to 5 results. Return ONLY the JSON array, no other text."""

        try:
            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2048,
                tools=[{"type": "web_search_20250305", "name": "web_search", "max_uses": 3}],
                messages=[{"role": "user", "content": prompt}]
            )

            response_text = ""
            for block in message.content:
                if block.type == "text":
                    response_text += block.text

            json_start = response_text.find('[')
            json_end = response_text.rfind(']') + 1
            if json_start >= 0 and json_end > json_start:
                return json.loads(response_text[json_start:json_end])
        except Exception as e:
            print(f"[PressRelease] Claude web_search fallback error: {e}")

        return []
