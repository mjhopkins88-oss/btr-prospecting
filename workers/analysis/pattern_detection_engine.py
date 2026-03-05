"""
Pattern Detection Engine.
Scans pattern_signal_history for signal sequences that match known
development_patterns, creates pattern_matches, and logs detections.
Also ingests development_events into pattern_signal_history.
"""
import uuid
import json
from datetime import datetime, timedelta

from db import get_db


def ingest_signals_to_history():
    """
    Copy recent development_events into pattern_signal_history
    for normalized pattern matching.
    Returns count of new signals ingested.
    """
    conn = get_db()
    cur = conn.cursor()

    # Get events from last 180 days not yet in history
    cutoff = (datetime.utcnow() - timedelta(days=180)).isoformat()
    cur.execute('''
        SELECT id, parcel_id, event_type, event_date, source, metadata
        FROM development_events
        WHERE created_at >= ?
        AND parcel_id IS NOT NULL AND parcel_id != ''
    ''', (cutoff,))
    rows = cur.fetchall()
    cols = [d[0] for d in cur.description]
    events = [dict(zip(cols, r)) for r in rows]

    ingested = 0
    for e in events:
        # Check if already ingested (by matching parcel + type + date)
        cur.execute('''
            SELECT COUNT(*) FROM pattern_signal_history
            WHERE parcel_id = ? AND signal_type = ? AND signal_date = ?
        ''', (e['parcel_id'], e['event_type'], e.get('event_date')))
        if cur.fetchone()[0] > 0:
            continue

        try:
            cur.execute('''
                INSERT INTO pattern_signal_history
                (id, parcel_id, signal_type, signal_date, source, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                str(uuid.uuid4()),
                e['parcel_id'],
                e['event_type'],
                e.get('event_date'),
                e.get('source'),
                e.get('metadata'),
            ))
            ingested += 1
        except Exception:
            pass

    conn.commit()
    conn.close()
    print(f"[PatternEngine] Ingested {ingested} signals into history")
    return ingested


def load_patterns():
    """Load all development patterns from the database."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT id, pattern_name, signal_sequence, time_window_days, base_confidence FROM development_patterns')
    rows = cur.fetchall()
    cols = [d[0] for d in cur.description]
    conn.close()

    patterns = []
    for r in rows:
        p = dict(zip(cols, r))
        # signal_sequence stored as comma-separated TEXT
        seq = p.get('signal_sequence') or ''
        p['sequence_list'] = [s.strip() for s in seq.split(',') if s.strip()]
        patterns.append(p)
    return patterns


def detect_pattern_matches():
    """
    Main detection loop:
    1. Load patterns from development_patterns
    2. For each parcel with signals, check against each pattern
    3. Create pattern_matches for hits
    4. Log detections

    Returns dict with counts.
    """
    conn = get_db()
    cur = conn.cursor()

    patterns = load_patterns()
    if not patterns:
        conn.close()
        print("[PatternEngine] No patterns defined — skipping detection")
        return {'matches_created': 0}

    # Get all parcels with recent signals
    cur.execute('''
        SELECT DISTINCT parcel_id FROM pattern_signal_history
        WHERE parcel_id IS NOT NULL AND parcel_id != ''
    ''')
    parcels = [r[0] for r in cur.fetchall()]

    matches_created = 0
    for parcel_id in parcels:
        # Get signals for this parcel, ordered by date
        cur.execute('''
            SELECT signal_type, signal_date
            FROM pattern_signal_history
            WHERE parcel_id = ?
            ORDER BY signal_date ASC
        ''', (parcel_id,))
        signals = cur.fetchall()
        signal_types = set(r[0] for r in signals if r[0])
        signal_dates = [r[1] for r in signals if r[1]]

        for pattern in patterns:
            required = pattern['sequence_list']
            if not required:
                continue

            # Check if all required signal types are present
            if not all(s in signal_types for s in required):
                continue

            # Check time window
            if signal_dates:
                try:
                    first = datetime.fromisoformat(str(signal_dates[0]).replace('Z', '+00:00').replace('+00:00', ''))
                    last = datetime.fromisoformat(str(signal_dates[-1]).replace('Z', '+00:00').replace('+00:00', ''))
                    window_days = (last - first).days
                except Exception:
                    window_days = 0
            else:
                window_days = 0

            if window_days > (pattern.get('time_window_days') or 365):
                continue

            # Check if match already exists
            cur.execute('''
                SELECT id FROM pattern_matches
                WHERE parcel_id = ? AND pattern_id = ?
            ''', (parcel_id, pattern['id']))
            if cur.fetchone():
                continue

            # Calculate confidence
            base = pattern.get('base_confidence') or 70
            matched_ratio = len(signal_types & set(required)) / len(required)
            confidence = int(base * matched_ratio)

            try:
                match_id = str(uuid.uuid4())
                cur.execute('''
                    INSERT INTO pattern_matches
                    (id, parcel_id, pattern_id, match_confidence,
                     signals_detected, first_signal_date, last_signal_date, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (
                    match_id, parcel_id, pattern['id'], confidence,
                    len(signals),
                    str(signal_dates[0]) if signal_dates else None,
                    str(signal_dates[-1]) if signal_dates else None,
                ))

                # Log detection
                cur.execute('''
                    INSERT INTO pattern_engine_log
                    (id, parcel_id, pattern_id, detection_time, confidence, notes)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?, ?)
                ''', (
                    str(uuid.uuid4()), parcel_id, pattern['id'], confidence,
                    f"Pattern {pattern['pattern_name']} detected with {len(signals)} signals in {window_days} days",
                ))

                matches_created += 1
                print(f"[PatternEngine] Match: parcel={parcel_id} pattern={pattern['pattern_name']} confidence={confidence}")
            except Exception as e:
                print(f"[PatternEngine] Error storing match for {parcel_id}: {e}")

    conn.commit()
    conn.close()
    print(f"[PatternEngine] Created {matches_created} new pattern matches")
    return {'matches_created': matches_created}


def boost_predictions_from_patterns():
    """
    Apply pattern match boosts to predicted_projects.
    For each prediction with a pattern match, boost score by
    base_confidence * 0.3 (approximately 25 points).

    Does NOT modify existing scoring logic — runs as additional layer.
    Returns count of predictions boosted.
    """
    conn = get_db()
    cur = conn.cursor()

    # Find predicted_projects that have matching parcels in pattern_matches
    cur.execute('''
        SELECT pp.id, pp.city, pp.state, pp.confidence,
               pm.match_confidence, dp.pattern_name, dp.base_confidence
        FROM predicted_projects pp
        JOIN development_events de ON de.city = pp.city AND de.state = pp.state
        JOIN pattern_matches pm ON pm.parcel_id = de.parcel_id
        JOIN development_patterns dp ON dp.id = pm.pattern_id
        WHERE pp.pattern_detected IS NOT NULL
    ''')
    rows = cur.fetchall()

    boosted = 0
    seen = set()
    for row in rows:
        pp_id = row[0]
        if pp_id in seen:
            continue
        seen.add(pp_id)

        base_confidence = row[6] or 85
        boost = int(base_confidence * 0.3)
        pattern_name = row[5]

        try:
            # Update predicted_projects — score boost is additive, set pattern info
            cur.execute('''
                UPDATE predicted_projects
                SET confidence = MIN(confidence + ?, 100),
                    pattern_name = ?,
                    pattern_confidence = ?
                WHERE id = ? AND confidence < 100
            ''', (boost, pattern_name, base_confidence, pp_id))

            # Also update the index if it exists
            try:
                cur.execute('''
                    UPDATE predicted_project_index
                    SET confidence = MIN(confidence + ?, 100),
                        pattern_name = ?,
                        pattern_confidence = ?
                    WHERE id = ? AND confidence < 100
                ''', (boost, pattern_name, base_confidence, pp_id))
            except Exception:
                pass

            boosted += 1
        except Exception as e:
            print(f"[PatternEngine] Error boosting {pp_id}: {e}")

    conn.commit()
    conn.close()
    print(f"[PatternEngine] Boosted {boosted} predictions from pattern matches")
    return boosted
