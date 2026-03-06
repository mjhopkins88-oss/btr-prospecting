"""
Austin, TX — Site plan and permit signal collector.
Sources: City of Austin Open Data portal (free, Socrata-based).
"""
import json
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None

from workers.collectors.cities.base_collector import BaseCollector


# Austin Open Data endpoints (Socrata, free)
AUSTIN_PERMITS_URL = 'https://data.austintexas.gov/resource/3syk-w9eu.json'
AUSTIN_SITE_PLANS_URL = 'https://data.austintexas.gov/resource/site-plan-cases.json'


class AustinSitePlansCollector(BaseCollector):
    name = 'austin_siteplans'
    city = 'Austin'
    state = 'TX'
    source = 'austin_open_data'

    def collect(self):
        signals = []
        signals.extend(self._collect_permits())
        signals.extend(self._collect_site_plans())
        return signals

    def _collect_permits(self):
        """Fetch building permits from Austin open data."""
        if not requests:
            return []
        signals = []
        try:
            params = {
                '$limit': 50,
                '$order': 'issued_date DESC',
                '$where': "work_class = 'New' AND "
                          "(description LIKE '%MULTI%' OR description LIKE '%APART%' "
                          "OR description LIKE '%RESIDEN%' OR description LIKE '%DWELLING%')",
            }
            resp = requests.get(AUSTIN_PERMITS_URL, params=params, timeout=30)
            if resp.status_code != 200:
                print(f"[austin_siteplans] Permits API returned {resp.status_code}")
                return []
            records = resp.json()
            for r in records:
                signals.append({
                    'signal_type': 'BUILDING_PERMIT',
                    'project_name': r.get('permit_number') or r.get('project_name'),
                    'developer': r.get('applicant_full_name') or r.get('contractor'),
                    'address': r.get('original_address') or r.get('address'),
                    'parcel_id': r.get('tcad_id') or r.get('property_id'),
                    'city': 'Austin',
                    'state': 'TX',
                    'timestamp': r.get('issued_date'),
                    'unit_count': r.get('number_of_floors') or r.get('units'),
                    'estimated_value': r.get('project_valuation'),
                })
        except Exception as e:
            print(f"[austin_siteplans] Permits error: {e}")
        return signals

    def _collect_site_plans(self):
        """Fetch site plan cases from Austin open data."""
        if not requests:
            return []
        signals = []
        try:
            params = {
                '$limit': 50,
                '$order': 'submitted_date DESC',
            }
            resp = requests.get(AUSTIN_SITE_PLANS_URL, params=params, timeout=30)
            if resp.status_code != 200:
                return []
            records = resp.json()
            for r in records:
                desc = (r.get('description') or r.get('project_name') or '').upper()
                if any(kw in desc for kw in ['MULTI', 'RESIDEN', 'APART', 'BTR', 'RENTAL', 'MIXED']):
                    signals.append({
                        'signal_type': 'SITE_PLAN_SUBMISSION',
                        'project_name': r.get('case_number') or r.get('project_name'),
                        'developer': r.get('applicant') or r.get('owner'),
                        'address': r.get('address') or r.get('location'),
                        'city': 'Austin',
                        'state': 'TX',
                        'timestamp': r.get('submitted_date'),
                    })
        except Exception as e:
            print(f"[austin_siteplans] Site plans error: {e}")
        return signals


def collect():
    """Entry point for job scheduler."""
    return AustinSitePlansCollector().run()
