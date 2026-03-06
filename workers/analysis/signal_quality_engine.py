"""
Signal Quality Ranking Engine.
Calculates prediction accuracy for each signal source and signal type.
Updates signal_sources.accuracy_score, signal_type_performance,
and source_priority_index.

Also emits intelligence feed events when high-quality sources are discovered.
Runs every 12 hours.
"""
import uuid
from datetime import datetime, timedelta

from db import get_db


def run_signal_quality_engine():
    """
    Main entry point: calculate accuracy scores, update rankings,
    and build the source priority index.
    """
    print(f"[SignalQuality] START — {datetime.utcnow().isoformat()}")

    conn = get_db()
    cur = conn.cursor()

    _ensure_tables(cur, conn)

    # Step 1: Calculate per-source accuracy
    sources_updated = _calculate_source_accuracy(cur)

    # Step 2: Calculate per-signal-type accuracy
    types_updated = _calculate_signal_type_accuracy(cur)

    # Step 3: Build source priority index
    priorities_updated = _build_source_priority_index(cur)

    # Step 4: Emit intelligence events for newly discovered high-value sources
    _emit_high_value_source_events(cur)

    conn.commit()
    conn.close()

    print(f"[SignalQuality] COMPLETE — {sources_updated} sources, "
          f"{types_updated} types, {priorities_updated} priorities updated")
    return {
        'sources_updated': sources_updated,
        'types_updated': types_updated,
        'priorities_updated': priorities_updated,
    }


def _ensure_tables(cur, conn):
    """Create tables if missing (dev/SQLite mode)."""
    tables = {
        'signal_sources': '''
            CREATE TABLE IF NOT EXISTS signal_sources (
                id TEXT PRIMARY KEY,
                source_name TEXT NOT NULL,
                source_type TEXT NOT NULL,
                city TEXT,
                state TEXT,
                signals_generated INTEGER DEFAULT 0,
                signals_confirmed INTEGER DEFAULT 0,
                accuracy_score REAL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''',
        'signal_performance': '''
            CREATE TABLE IF NOT EXISTS signal_performance (
                id TEXT PRIMARY KEY,
                signal_id TEXT,
                source_name TEXT,
                signal_type TEXT,
                parcel_id TEXT,
                predicted_development INTEGER DEFAULT 0,
                confirmed_development INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''',
        'signal_type_performance': '''
            CREATE TABLE IF NOT EXISTS signal_type_performance (
                id TEXT PRIMARY KEY,
                signal_type TEXT NOT NULL UNIQUE,
                signals_generated INTEGER DEFAULT 0,
                signals_confirmed INTEGER DEFAULT 0,
                accuracy_score REAL DEFAULT 0
            )
        ''',
        'source_priority_index': '''
            CREATE TABLE IF NOT EXISTS source_priority_index (
                id TEXT PRIMARY KEY,
                source_name TEXT NOT NULL UNIQUE,
                priority_score REAL DEFAULT 0,
                signals_last_30_days INTEGER DEFAULT 0,
                accuracy_score REAL DEFAULT 0
            )
        ''',
    }
    for table, ddl in tables.items():
        try:
            cur.execute(f"SELECT 1 FROM {table} LIMIT 1")
        except Exception:
            conn.rollback()
            cur.execute(ddl)
            conn.commit()


def _calculate_source_accuracy(cur):
    """
    Calculate accuracy_score = signals_confirmed / signals_generated
    for each signal source.
    """
    updated = 0
    try:
        cur.execute('''
            SELECT source_name,
                   COUNT(*) as total,
                   SUM(CASE WHEN confirmed_development = TRUE THEN 1 ELSE 0 END) as confirmed
            FROM signal_performance
            WHERE source_name IS NOT NULL
            GROUP BY source_name
        ''')
        rows = cur.fetchall()

        for row in rows:
            source_name = row[0]
            total = row[1] or 0
            confirmed = row[2] or 0
            accuracy = confirmed / total if total > 0 else 0.0

            # Update or insert into signal_sources
            cur.execute('''
                SELECT id FROM signal_sources WHERE source_name = ?
            ''', (source_name,))
            existing = cur.fetchone()

            if existing:
                cur.execute('''
                    UPDATE signal_sources
                    SET signals_generated = ?,
                        signals_confirmed = ?,
                        accuracy_score = ?
                    WHERE source_name = ?
                ''', (total, confirmed, round(accuracy, 4), source_name))
            else:
                cur.execute('''
                    INSERT INTO signal_sources
                    (id, source_name, source_type, signals_generated,
                     signals_confirmed, accuracy_score)
                    VALUES (?, ?, 'UNKNOWN', ?, ?, ?)
                ''', (str(uuid.uuid4()), source_name, total, confirmed,
                      round(accuracy, 4)))
            updated += 1

    except Exception as e:
        print(f"[SignalQuality] Source accuracy error: {e}")

    return updated


def _calculate_signal_type_accuracy(cur):
    """
    Calculate accuracy per signal type across all sources.
    """
    updated = 0
    try:
        cur.execute('''
            SELECT signal_type,
                   COUNT(*) as total,
                   SUM(CASE WHEN confirmed_development = TRUE THEN 1 ELSE 0 END) as confirmed
            FROM signal_performance
            WHERE signal_type IS NOT NULL
            GROUP BY signal_type
        ''')
        rows = cur.fetchall()

        for row in rows:
            signal_type = row[0]
            total = row[1] or 0
            confirmed = row[2] or 0
            accuracy = confirmed / total if total > 0 else 0.0

            # Upsert
            cur.execute('''
                SELECT id FROM signal_type_performance WHERE signal_type = ?
            ''', (signal_type,))
            existing = cur.fetchone()

            if existing:
                cur.execute('''
                    UPDATE signal_type_performance
                    SET signals_generated = ?,
                        signals_confirmed = ?,
                        accuracy_score = ?
                    WHERE signal_type = ?
                ''', (total, confirmed, round(accuracy, 4), signal_type))
            else:
                cur.execute('''
                    INSERT INTO signal_type_performance
                    (id, signal_type, signals_generated, signals_confirmed, accuracy_score)
                    VALUES (?, ?, ?, ?, ?)
                ''', (str(uuid.uuid4()), signal_type, total, confirmed,
                      round(accuracy, 4)))
            updated += 1

    except Exception as e:
        print(f"[SignalQuality] Signal type accuracy error: {e}")

    return updated


def _build_source_priority_index(cur):
    """
    Build the source priority index based on accuracy and recent volume.
    priority_score = accuracy_score * 0.7 + volume_score * 0.3
    where volume_score is normalized signal count in last 30 days.
    """
    updated = 0
    try:
        # Get signals in last 30 days per source
        cur.execute('''
            SELECT source_name,
                   COUNT(*) as recent_count
            FROM signal_performance
            WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '30 days'
              AND source_name IS NOT NULL
            GROUP BY source_name
        ''')
    except Exception:
        # SQLite fallback
        try:
            cur.execute('''
                SELECT source_name,
                       COUNT(*) as recent_count
                FROM signal_performance
                WHERE created_at >= datetime('now', '-30 days')
                  AND source_name IS NOT NULL
                GROUP BY source_name
            ''')
        except Exception as e:
            print(f"[SignalQuality] Recent count query error: {e}")
            return 0

    try:
        recent_rows = cur.fetchall()
        recent_map = {row[0]: row[1] for row in recent_rows}

        # Find max for normalization
        max_recent = max(recent_map.values()) if recent_map else 1

        # Get all sources with accuracy
        cur.execute('''
            SELECT source_name, accuracy_score
            FROM signal_sources
            WHERE source_name IS NOT NULL
        ''')
        sources = cur.fetchall()

        for row in sources:
            source_name = row[0]
            accuracy = row[1] or 0.0
            recent_count = recent_map.get(source_name, 0)
            volume_score = recent_count / max_recent if max_recent > 0 else 0

            priority = accuracy * 0.7 + volume_score * 0.3

            # Upsert
            cur.execute('''
                SELECT id FROM source_priority_index WHERE source_name = ?
            ''', (source_name,))
            existing = cur.fetchone()

            if existing:
                cur.execute('''
                    UPDATE source_priority_index
                    SET priority_score = ?,
                        signals_last_30_days = ?,
                        accuracy_score = ?
                    WHERE source_name = ?
                ''', (round(priority, 4), recent_count, round(accuracy, 4),
                      source_name))
            else:
                cur.execute('''
                    INSERT INTO source_priority_index
                    (id, source_name, priority_score, signals_last_30_days, accuracy_score)
                    VALUES (?, ?, ?, ?, ?)
                ''', (str(uuid.uuid4()), source_name, round(priority, 4),
                      recent_count, round(accuracy, 4)))
            updated += 1

    except Exception as e:
        print(f"[SignalQuality] Priority index error: {e}")

    return updated


def _emit_high_value_source_events(cur):
    """
    Emit intelligence feed events for sources with accuracy >= 0.65
    that haven't been announced yet.
    """
    try:
        cur.execute('''
            SELECT ss.source_name, ss.accuracy_score, ss.city, ss.state
            FROM signal_sources ss
            WHERE ss.accuracy_score >= 0.65
              AND ss.signals_generated >= 5
              AND NOT EXISTS (
                  SELECT 1 FROM intelligence_events ie
                  WHERE ie.event_type = 'SIGNAL_QUALITY'
                    AND ie.related_entity = ss.source_name
              )
        ''')
        new_sources = cur.fetchall()

        for row in new_sources:
            source_name = row[0]
            accuracy = row[1]
            city = row[2]
            state = row[3]

            cur.execute('''
                INSERT INTO intelligence_events
                (id, event_type, title, description, city, state,
                 related_entity, entity_id)
                VALUES (?, 'SIGNAL_QUALITY', ?, ?, ?, ?, ?, ?)
            ''', (
                str(uuid.uuid4()),
                f"NEW HIGH VALUE DATA SOURCE",
                f"Source: {source_name} — Accuracy Score: {accuracy:.2f}",
                city, state,
                source_name, source_name,
            ))
            print(f"[SignalQuality] New high-value source: {source_name} "
                  f"(accuracy={accuracy:.2f})")

    except Exception as e:
        print(f"[SignalQuality] Event emission error: {e}")


def get_source_accuracy(source_name):
    """
    Get the accuracy score for a given source.
    Returns float (0.0-1.0) or None if source not tracked.
    """
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute('''
            SELECT accuracy_score FROM signal_sources
            WHERE source_name = ?
        ''', (source_name,))
        row = cur.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception:
        conn.close()
        return None


def get_signal_type_accuracy(signal_type):
    """
    Get the accuracy score for a given signal type.
    Returns float (0.0-1.0) or None if type not tracked.
    """
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute('''
            SELECT accuracy_score FROM signal_type_performance
            WHERE signal_type = ?
        ''', (signal_type,))
        row = cur.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception:
        conn.close()
        return None


def get_collector_schedule_interval(source_name):
    """
    Determine how frequently a collector should run based on its priority score.
    Returns interval in hours.

    priority_score > 0.7  → every 2 hours
    priority_score 0.4-0.7 → every 6 hours
    priority_score < 0.4  → every 24 hours
    """
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute('''
            SELECT priority_score FROM source_priority_index
            WHERE source_name = ?
        ''', (source_name,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return 24  # default for unknown sources

        score = row[0] or 0
        if score > 0.7:
            return 2
        elif score >= 0.4:
            return 6
        else:
            return 24
    except Exception:
        conn.close()
        return 24


def run_signal_quality_worker():
    """Worker wrapper for scheduler/pipeline integration."""
    try:
        result = run_signal_quality_engine()
        print(f"[SignalQuality Worker] Result: {result}")
        return result
    except Exception as e:
        print(f"[SignalQuality Worker] Error: {e}")
        import traceback
        traceback.print_exc()
        return {'error': str(e)}
