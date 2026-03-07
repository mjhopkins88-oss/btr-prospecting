"""
Building Permit Intelligence Collector.
Collects and analyzes building permit records from city open data portals
to detect large residential development permits before construction begins.

Data sources:
  ArcGIS Open Data portals
  Socrata Open Data APIs
  City open data portals
  CSV permit exports / permit dashboards

Signal types:
  BUILDING_PERMIT
  MULTIFAMILY_PERMIT
  SUBDIVISION_PERMIT
  SITE_DEVELOPMENT_PERMIT
  RESIDENTIAL_COMPLEX_PERMIT
"""
import json
import uuid
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None

try:
    import anthropic
except ImportError:
    anthropic = None

from db import get_db
from shared.config import SERPAPI_KEY, ANTHROPIC_API_KEY, AI_MODEL, TARGET_CITIES


# Signal scoring — feeds into development_probability scoring
PERMIT_SIGNAL_SCORES = {
    'MULTIFAMILY_PERMIT': 40,
    'SUBDIVISION_PERMIT': 35,
    'SITE_DEVELOPMENT_PERMIT': 30,
    'RESIDENTIAL_COMPLEX_PERMIT': 35,
    'BUILDING_PERMIT': 25,
}

# Keywords that indicate development-scale permits (include)
DEVELOPMENT_KEYWORDS = [
    'multifamily', 'apartments', 'townhomes', 'single family rental',
    'residential community', 'subdivision', 'build to rent', 'BTR',
    'multi-family', 'residential complex', 'rental community',
    'mixed use', 'mixed-use', 'planned development', 'housing development',
    'condominium', 'senior living', 'student housing',
]

# Keywords that indicate small/irrelevant permits (exclude)
EXCLUDE_KEYWORDS = [
    'roof repair', 'roof replacement', 'hvac', 'water heater',
    'fence', 'deck', 'pool', 'remodel', 'renovation', 'addition',
    'solar panel', 'siding', 'window replacement', 'plumbing',
    'electrical panel', 'driveway', 'shed', 'carport', 'garage door',
    'single family residence', 'single-family home',
]


def _search_permits(city, state, num=10):
    """Search for building permit data from city open data portals."""
    if not SERPAPI_KEY or not requests:
        return []

    queries = [
        f'{city} {state} building permit multifamily apartment development filed',
        f'{city} {state} new construction permit residential subdivision',
        f'site:{city.lower().replace(" ", "")}.gov OR site:data.{city.lower().replace(" ", "")}.gov building permits residential',
    ]
    results = []
    for q in queries[:2]:
        try:
            resp = requests.get('https://serpapi.com/search.json', params={
                'q': q, 'tbm': 'nws', 'num': num, 'api_key': SERPAPI_KEY,
            }, timeout=30)
            data = resp.json()
            results.extend(data.get('news_results', []))
        except Exception as e:
            print(f"[BuildingPermitCollector] Search error: {e}")

    # Also search organic results for open data portals
    try:
        resp = requests.get('https://serpapi.com/search.json', params={
            'q': queries[2], 'num': num, 'api_key': SERPAPI_KEY,
        }, timeout=30)
        data = resp.json()
        results.extend(data.get('organic_results', []))
    except Exception as e:
        print(f"[BuildingPermitCollector] Portal search error: {e}")

    return results


def _extract_permit_signals(documents, city, state):
    """Use Claude to extract building permit signals from search results."""
    if not ANTHROPIC_API_KEY or not anthropic or not documents:
        return []

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    text = json.dumps(documents[:12], indent=2, default=str)

    prompt = f"""Analyze these search results about building permits in {city}, {state}.
Extract any permits for large-scale residential development projects.

Focus on permits for: multifamily, apartments, townhomes, subdivisions,
build-to-rent communities, residential complexes, mixed-use with residential.

IGNORE small permits for: roof repairs, HVAC, remodels, single home additions,
fences, pools, driveways, solar panels, individual home renovations.

Documents:
{text}

Return a JSON array where each element has:
- "permit_type": one of "MULTIFAMILY_PERMIT", "SUBDIVISION_PERMIT", "SITE_DEVELOPMENT_PERMIT", "RESIDENTIAL_COMPLEX_PERMIT", "BUILDING_PERMIT"
- "project_name": project name if mentioned, or null
- "contractor_name": contractor or builder if mentioned, or null
- "developer_name": developer or applicant if mentioned, or null
- "address": project address or location, or null
- "parcel_id": parcel number or APN if mentioned, or null
- "permit_date": permit date if found, or null
- "estimated_value": estimated construction value as string (e.g. "$48,000,000"), or null
- "unit_count": number of units if mentioned, or null
- "description": brief description of the permit
- "confidence": float 0.0-1.0
- "url": source URL

Only include permits for real development-scale projects (not individual home repairs).
Return ONLY the JSON array."""

    try:
        resp = client.messages.create(
            model=AI_MODEL, max_tokens=3000,
            messages=[{'role': 'user', 'content': prompt}]
        )
        text = resp.content[0].text.strip()
        if text.startswith('```'):
            text = text.split('\n', 1)[1]
            text = text.rsplit('```', 1)[0]
        return json.loads(text)
    except Exception as e:
        print(f"[BuildingPermitCollector] AI extraction error: {e}")
        return []


def _is_development_permit(sig):
    """Filter: return True only for development-scale permits."""
    desc = (sig.get('description') or '').lower()
    project = (sig.get('project_name') or '').lower()
    combined = f"{desc} {project}"

    # Exclude small permits
    for kw in EXCLUDE_KEYWORDS:
        if kw in combined:
            return False

    # Include development permits
    for kw in DEVELOPMENT_KEYWORDS:
        if kw in combined:
            return True

    # Trust AI classification for typed permits
    ptype = sig.get('permit_type', '')
    if ptype in ('MULTIFAMILY_PERMIT', 'SUBDIVISION_PERMIT',
                 'SITE_DEVELOPMENT_PERMIT', 'RESIDENTIAL_COMPLEX_PERMIT'):
        return True

    # Include if confidence is high enough
    if float(sig.get('confidence', 0)) >= 0.7:
        return True

    return False


def _store_permit_signals(signals, city, state):
    """Store permit signals into property_signals and entities."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0

    for sig in signals:
        entity_name = (
            sig.get('developer_name')
            or sig.get('contractor_name')
            or ''
        ).strip()
        description = (sig.get('description') or '').strip()
        if not entity_name and not description:
            continue

        sig_id = str(uuid.uuid4())
        signal_type = sig.get('permit_type', 'BUILDING_PERMIT')
        if signal_type not in PERMIT_SIGNAL_SCORES:
            signal_type = 'BUILDING_PERMIT'

        address = sig.get('address')

        # Build metadata with all extracted fields
        metadata = dict(sig)
        metadata['source_collector'] = 'building_permit_collector'

        try:
            cur.execute('''
                INSERT OR IGNORE INTO property_signals
                (id, signal_type, source, entity_name, address,
                 city, state, parcel_id, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                sig_id, signal_type, 'building_permit_portal',
                entity_name or None, address,
                city, state,
                sig.get('parcel_id'),
                json.dumps(metadata, default=str),
            ))
            stored += 1
        except Exception:
            pass

        # Track developer entity
        developer = (sig.get('developer_name') or '').strip()
        if developer:
            try:
                cur.execute('''
                    INSERT OR IGNORE INTO entities
                    (id, entity_name, normalized_name, entity_type, created_at)
                    VALUES (?, ?, ?, 'developer', CURRENT_TIMESTAMP)
                ''', (str(uuid.uuid4()), developer, developer.upper().strip()))
            except Exception:
                pass

        # Track contractor entity
        contractor = (sig.get('contractor_name') or '').strip()
        if contractor:
            try:
                cur.execute('''
                    INSERT OR IGNORE INTO entities
                    (id, entity_name, normalized_name, entity_type, created_at)
                    VALUES (?, ?, ?, 'contractor', CURRENT_TIMESTAMP)
                ''', (str(uuid.uuid4()), contractor, contractor.upper().strip()))
            except Exception:
                pass

        # Create developer-contractor relationship if both present
        if developer and contractor:
            try:
                cur.execute('''
                    SELECT id FROM entity_relationships
                    WHERE entity_a = ? AND entity_b = ?
                    AND relationship_type = 'DEVELOPER_USES_CONTRACTOR'
                    LIMIT 1
                ''', (developer, contractor))
                if not cur.fetchone():
                    cur.execute('''
                        INSERT INTO entity_relationships
                        (id, entity_a, entity_a_type, entity_b, entity_b_type,
                         relationship_type, source, confidence, created_at)
                        VALUES (?, ?, 'developer', ?, 'contractor',
                                'DEVELOPER_USES_CONTRACTOR', 'building_permit', ?,
                                CURRENT_TIMESTAMP)
                    ''', (
                        str(uuid.uuid4()), developer, contractor,
                        int(float(sig.get('confidence', 0.6)) * 100),
                    ))
            except Exception:
                pass

    conn.commit()
    conn.close()
    return stored


def collect_building_permits(cities=None):
    """
    Main entry point: collect building permit signals for target cities.
    Scans city open data portals and permit feeds for large residential
    development permits.
    """
    cities = cities or TARGET_CITIES
    total_scanned = 0
    total_filtered = 0
    total_stored = 0
    city_counts = {}

    for market in cities:
        city, state = market['city'], market['state']
        print(f"[BuildingPermitCollector] Scanning {city}, {state}...")

        documents = _search_permits(city, state)
        scanned = len(documents)
        total_scanned += scanned

        count = 0
        filtered = 0
        if documents:
            raw_signals = _extract_permit_signals(documents, city, state)
            # Apply development filter
            dev_signals = []
            for sig in raw_signals:
                if _is_development_permit(sig):
                    dev_signals.append(sig)
                else:
                    filtered += 1

            total_filtered += filtered
            count = _store_permit_signals(dev_signals, city, state)
            total_stored += count

            if count:
                print(f"  -> {count} permit signals stored ({filtered} filtered out)")

                # Emit intelligence event
                try:
                    from app import log_intelligence_event
                    # Build description with value info if available
                    desc_parts = [f"{count} development permit signals detected"]
                    values = [s.get('estimated_value') for s in dev_signals if s.get('estimated_value')]
                    if values:
                        desc_parts.append(f"Values: {', '.join(values[:3])}")
                    log_intelligence_event(
                        event_type='PERMIT_SIGNAL',
                        title=f"Building permit signals detected — {city}, {state}",
                        description='. '.join(desc_parts),
                        city=city,
                        state=state,
                    )
                except Exception:
                    pass
            else:
                print(f"  -> 0 development permits ({filtered} filtered out)")
        else:
            print(f"  -> 0 documents found")

        city_counts[f"{city} {state}"] = count

    # Step 10: Signal volume logging
    print(f"\n  [BuildingPermitCollector] COLLECTION SUMMARY")
    print(f"  Permits scanned: {total_scanned}")
    print(f"  Filtered permits: {total_filtered}")
    print(f"  Development signals created: {total_stored}")
    print()
    for city_label, count in city_counts.items():
        print(f"  {city_label}: {count} signals detected")
    print(f"[BuildingPermitCollector] Done. {total_stored} total permit signals collected.")
    return total_stored
