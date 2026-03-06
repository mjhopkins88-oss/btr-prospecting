"""
Dallas, TX — Building permit and zoning signal collector.
Sources: City of Dallas Open Data portal (free).
"""
import json
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None

from workers.collectors.cities.base_collector import BaseCollector


# Dallas Open Data API endpoints (Socrata-based, free)
DALLAS_PERMITS_URL = 'https://www.dallasopendata.com/resource/building-permits.json'
DALLAS_ZONING_URL = 'https://www.dallasopendata.com/resource/zoning-cases.json'


class DallasPermitsCollector(BaseCollector):
    name = 'dallas_permits'
    city = 'Dallas'
    state = 'TX'
    source = 'dallas_open_data'

    def collect(self):
        signals = []
        signals.extend(self._collect_permits())
        signals.extend(self._collect_zoning())
        return signals

    def _collect_permits(self):
        """Fetch building permits from Dallas open data."""
        if not requests:
            return []
        signals = []
        try:
            params = {
                '$limit': 50,
                '$order': 'issue_date DESC',
                '$where': "work_type LIKE '%NEW%' OR work_type LIKE '%MULTI%' OR work_type LIKE '%APARTMENT%'",
            }
            resp = requests.get(DALLAS_PERMITS_URL, params=params, timeout=30)
            if resp.status_code != 200:
                print(f"[dallas_permits] Permits API returned {resp.status_code}")
                return []
            records = resp.json()
            for r in records:
                work_type = (r.get('work_type') or '').upper()
                if not any(kw in work_type for kw in ['NEW', 'MULTI', 'APART', 'RESIDENTIAL']):
                    continue
                signals.append({
                    'signal_type': 'BUILDING_PERMIT',
                    'project_name': r.get('project_name') or r.get('description'),
                    'developer': r.get('contractor_name') or r.get('owner_name'),
                    'address': r.get('address') or r.get('location'),
                    'parcel_id': r.get('parcel_id') or r.get('account_number'),
                    'city': 'Dallas',
                    'state': 'TX',
                    'timestamp': r.get('issue_date'),
                    'unit_count': r.get('units') or r.get('dwelling_units'),
                    'estimated_value': r.get('valuation') or r.get('estimated_cost'),
                })
        except Exception as e:
            print(f"[dallas_permits] Permits error: {e}")
        return signals

    def _collect_zoning(self):
        """Fetch zoning cases from Dallas open data."""
        if not requests:
            return []
        signals = []
        try:
            params = {
                '$limit': 50,
                '$order': 'filing_date DESC',
            }
            resp = requests.get(DALLAS_ZONING_URL, params=params, timeout=30)
            if resp.status_code != 200:
                return []
            records = resp.json()
            for r in records:
                desc = (r.get('description') or '').upper()
                req_zoning = (r.get('requested_zoning') or '').upper()
                if any(kw in desc + req_zoning for kw in ['MULTI', 'RESIDEN', 'PD', 'MIXED', 'BTR']):
                    signals.append({
                        'signal_type': 'ZONING_APPLICATION',
                        'project_name': r.get('case_number'),
                        'developer': r.get('applicant_name') or r.get('owner_name'),
                        'address': r.get('location') or r.get('address'),
                        'city': 'Dallas',
                        'state': 'TX',
                        'timestamp': r.get('filing_date'),
                    })
        except Exception as e:
            print(f"[dallas_permits] Zoning error: {e}")
        return signals


def collect():
    """Entry point for job scheduler."""
    return DallasPermitsCollector().run()
