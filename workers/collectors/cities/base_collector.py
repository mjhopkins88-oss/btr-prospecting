"""
Base collector framework for city-specific signal collection.
All city collectors inherit from BaseCollector and implement collect().
"""
import json
import uuid
from datetime import datetime

from db import get_db


# Valid signal types for property_signals
SIGNAL_TYPES = [
    'LAND_PURCHASE',
    'ZONING_APPLICATION',
    'SITE_PLAN_SUBMISSION',
    'BUILDING_PERMIT',
    'ENGINEERING_ENGAGEMENT',
    'UTILITY_APPLICATION',
    'LLC_FORMATION',
    'DEVELOPER_EXPANSION',
    'NEWS_SIGNAL',
]


class BaseCollector:
    """
    Base class for city-specific signal collectors.

    Subclasses must implement:
        - collect() -> list[dict]

    Each returned dict should have:
        signal_type, project_name, developer, address, city, state
    And optionally: parcel_id, metadata, timestamp
    """

    name = 'base'
    city = ''
    state = ''
    source = ''

    def __init__(self):
        self.signals_collected = 0

    def collect(self):
        """
        Collect signals from the city data source.
        Returns list of normalized signal dicts.
        """
        raise NotImplementedError

    def normalize_signal(self, raw):
        """Normalize a raw signal dict into the property_signals schema."""
        return {
            'id': str(uuid.uuid4()),
            'parcel_id': raw.get('parcel_id'),
            'signal_type': raw.get('signal_type', 'NEWS_SIGNAL'),
            'source': raw.get('source') or self.source or self.name,
            'entity_name': raw.get('developer') or raw.get('entity_name'),
            'address': raw.get('address'),
            'city': raw.get('city') or self.city,
            'state': raw.get('state') or self.state,
            'metadata': json.dumps({
                'project_name': raw.get('project_name'),
                'unit_count': raw.get('unit_count'),
                'estimated_value': raw.get('estimated_value'),
                'raw': {k: v for k, v in raw.items()
                        if k not in ('signal_type', 'developer', 'entity_name',
                                     'address', 'city', 'state', 'parcel_id')},
            }, default=str),
            'created_at': raw.get('timestamp') or datetime.utcnow().isoformat(),
        }

    def store_signals(self, signals):
        """Store normalized signals into property_signals table."""
        conn = get_db()
        cur = conn.cursor()
        stored = 0

        for raw in signals:
            sig = self.normalize_signal(raw)
            try:
                cur.execute('''
                    INSERT OR IGNORE INTO property_signals
                    (id, parcel_id, signal_type, source, entity_name,
                     address, city, state, metadata, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    sig['id'], sig['parcel_id'], sig['signal_type'],
                    sig['source'], sig['entity_name'], sig['address'],
                    sig['city'], sig['state'], sig['metadata'],
                    sig['created_at'],
                ))
                stored += 1
            except Exception as e:
                print(f"[{self.name}] Error storing signal: {e}")

        conn.commit()
        conn.close()
        self.signals_collected = stored
        return stored

    def run(self):
        """Full collection cycle: collect, normalize, store."""
        print(f"[{self.name}] Collecting signals for {self.city}, {self.state}...")
        try:
            signals = self.collect()
            count = self.store_signals(signals)
            print(f"[{self.name}] Stored {count} signals")
            self._emit_intelligence_event(count)
            return count
        except Exception as e:
            print(f"[{self.name}] Collection failed: {e}")
            return 0

    def _emit_intelligence_event(self, count):
        """Log collection result to intelligence feed."""
        if count <= 0:
            return
        try:
            from app import log_intelligence_event
            log_intelligence_event(
                event_type='SIGNAL_COLLECTION',
                title=f"New signals collected — {self.city}, {self.state}",
                description=f"{count} new {self.source} signals detected",
                city=self.city,
                state=self.state,
                related_entity=self.name,
            )
        except Exception:
            pass
