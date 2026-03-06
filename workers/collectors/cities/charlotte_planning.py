"""
Charlotte, NC — Planning and rezoning signal collector.
Sources: City of Charlotte Open Data portal (free).
"""
import json
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None

from workers.collectors.cities.base_collector import BaseCollector


# Charlotte/Mecklenburg open data (ArcGIS-based, free)
CHARLOTTE_REZONING_URL = 'https://gis.charlottenc.gov/arcgis/rest/services/Planning/RezoningPetitions/MapServer/0/query'
CHARLOTTE_PERMITS_URL = 'https://gis.charlottenc.gov/arcgis/rest/services/Planning/BuildingPermits/MapServer/0/query'


class CharlottePlanningCollector(BaseCollector):
    name = 'charlotte_planning'
    city = 'Charlotte'
    state = 'NC'
    source = 'charlotte_open_data'

    def collect(self):
        signals = []
        signals.extend(self._collect_rezonings())
        signals.extend(self._collect_permits())
        return signals

    def _collect_rezonings(self):
        """Fetch rezoning petitions from Charlotte open data."""
        if not requests:
            return []
        signals = []
        try:
            params = {
                'where': '1=1',
                'outFields': '*',
                'orderByFields': 'SUBMIT_DATE DESC',
                'resultRecordCount': 50,
                'f': 'json',
            }
            resp = requests.get(CHARLOTTE_REZONING_URL, params=params, timeout=30)
            if resp.status_code != 200:
                print(f"[charlotte_planning] Rezoning API returned {resp.status_code}")
                return []
            data = resp.json()
            features = data.get('features', [])
            for f in features:
                attrs = f.get('attributes', {})
                desc = (attrs.get('DESCRIPTION') or attrs.get('PROJECT_NAME') or '').upper()
                proposed = (attrs.get('PROPOSED_ZONING') or '').upper()
                if any(kw in desc + proposed for kw in [
                    'MULTI', 'RESIDEN', 'APARTMENT', 'TOD', 'MIXED',
                    'MX', 'UR', 'MUDD', 'BTR', 'RENTAL'
                ]):
                    signals.append({
                        'signal_type': 'ZONING_APPLICATION',
                        'project_name': attrs.get('PETITION_NUMBER') or attrs.get('PROJECT_NAME'),
                        'developer': attrs.get('APPLICANT') or attrs.get('OWNER'),
                        'address': attrs.get('LOCATION') or attrs.get('ADDRESS'),
                        'parcel_id': attrs.get('PARCEL_ID') or attrs.get('PID'),
                        'city': 'Charlotte',
                        'state': 'NC',
                        'timestamp': self._epoch_to_iso(attrs.get('SUBMIT_DATE')),
                    })
        except Exception as e:
            print(f"[charlotte_planning] Rezoning error: {e}")
        return signals

    def _collect_permits(self):
        """Fetch building permits from Charlotte open data."""
        if not requests:
            return []
        signals = []
        try:
            params = {
                'where': "PERMIT_TYPE LIKE '%NEW%' OR PERMIT_TYPE LIKE '%MULTI%'",
                'outFields': '*',
                'orderByFields': 'ISSUE_DATE DESC',
                'resultRecordCount': 50,
                'f': 'json',
            }
            resp = requests.get(CHARLOTTE_PERMITS_URL, params=params, timeout=30)
            if resp.status_code != 200:
                return []
            data = resp.json()
            features = data.get('features', [])
            for f in features:
                attrs = f.get('attributes', {})
                desc = (attrs.get('DESCRIPTION') or '').upper()
                if any(kw in desc for kw in ['MULTI', 'APART', 'DWELLING', 'UNIT', 'RESIDEN']):
                    signals.append({
                        'signal_type': 'BUILDING_PERMIT',
                        'project_name': attrs.get('PERMIT_NUMBER'),
                        'developer': attrs.get('CONTRACTOR_NAME') or attrs.get('OWNER_NAME'),
                        'address': attrs.get('ADDRESS') or attrs.get('LOCATION'),
                        'parcel_id': attrs.get('PARCEL_ID'),
                        'city': 'Charlotte',
                        'state': 'NC',
                        'timestamp': self._epoch_to_iso(attrs.get('ISSUE_DATE')),
                        'estimated_value': attrs.get('CONSTRUCTION_COST'),
                    })
        except Exception as e:
            print(f"[charlotte_planning] Permits error: {e}")
        return signals

    @staticmethod
    def _epoch_to_iso(epoch_ms):
        """Convert epoch milliseconds to ISO string."""
        if not epoch_ms:
            return None
        try:
            return datetime.utcfromtimestamp(int(epoch_ms) / 1000).isoformat()
        except Exception:
            return None


def collect():
    """Entry point for job scheduler."""
    return CharlottePlanningCollector().run()
