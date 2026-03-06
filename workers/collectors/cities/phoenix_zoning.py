"""
Phoenix, AZ — Zoning and planning signal collector.
Sources: City of Phoenix Open Data portal (free).
"""
import json
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None

from workers.collectors.cities.base_collector import BaseCollector


# Phoenix Open Data endpoints (Socrata-based, free)
PHOENIX_ZONING_URL = 'https://www.phoenixopendata.com/resource/zoning-cases.json'
PHOENIX_PERMITS_URL = 'https://www.phoenixopendata.com/resource/building-permits.json'


class PhoenixZoningCollector(BaseCollector):
    name = 'phoenix_zoning'
    city = 'Phoenix'
    state = 'AZ'
    source = 'phoenix_open_data'

    def collect(self):
        signals = []
        signals.extend(self._collect_zoning_cases())
        signals.extend(self._collect_site_plans())
        return signals

    def _collect_zoning_cases(self):
        """Fetch zoning cases from Phoenix open data."""
        if not requests:
            return []
        signals = []
        try:
            params = {
                '$limit': 50,
                '$order': 'submitted_date DESC',
            }
            resp = requests.get(PHOENIX_ZONING_URL, params=params, timeout=30)
            if resp.status_code != 200:
                print(f"[phoenix_zoning] Zoning API returned {resp.status_code}")
                return []
            records = resp.json()
            for r in records:
                desc = (r.get('description') or r.get('project_description') or '').upper()
                case_type = (r.get('case_type') or '').upper()
                if any(kw in desc + case_type for kw in [
                    'MULTI', 'RESIDEN', 'APARTMENT', 'BTR', 'RENTAL',
                    'PUD', 'MIXED USE', 'R-3', 'R-4', 'R-5'
                ]):
                    signals.append({
                        'signal_type': 'ZONING_APPLICATION',
                        'project_name': r.get('case_number') or r.get('project_name'),
                        'developer': r.get('applicant') or r.get('owner'),
                        'address': r.get('location') or r.get('address'),
                        'parcel_id': r.get('parcel_number') or r.get('apn'),
                        'city': 'Phoenix',
                        'state': 'AZ',
                        'timestamp': r.get('submitted_date') or r.get('hearing_date'),
                    })
        except Exception as e:
            print(f"[phoenix_zoning] Zoning error: {e}")
        return signals

    def _collect_site_plans(self):
        """Fetch building permits (site plan proxy) from Phoenix open data."""
        if not requests:
            return []
        signals = []
        try:
            params = {
                '$limit': 50,
                '$order': 'issue_date DESC',
                '$where': "permit_type LIKE '%NEW%' OR permit_type LIKE '%COMMERCIAL%'",
            }
            resp = requests.get(PHOENIX_PERMITS_URL, params=params, timeout=30)
            if resp.status_code != 200:
                return []
            records = resp.json()
            for r in records:
                desc = (r.get('description') or '').upper()
                if any(kw in desc for kw in ['MULTI', 'APART', 'RESIDEN', 'UNIT', 'DWELLING']):
                    signals.append({
                        'signal_type': 'SITE_PLAN_SUBMISSION',
                        'project_name': r.get('project_name') or r.get('permit_number'),
                        'developer': r.get('contractor') or r.get('owner_name'),
                        'address': r.get('address') or r.get('location'),
                        'parcel_id': r.get('parcel_number'),
                        'city': 'Phoenix',
                        'state': 'AZ',
                        'timestamp': r.get('issue_date'),
                        'estimated_value': r.get('valuation'),
                    })
        except Exception as e:
            print(f"[phoenix_zoning] Site plans error: {e}")
        return signals


def collect():
    """Entry point for job scheduler."""
    return PhoenixZoningCollector().run()
