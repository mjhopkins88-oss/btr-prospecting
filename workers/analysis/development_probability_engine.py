"""
Development Probability Scoring Engine.
Aggregates multiple signal sources into a single 0-100 development probability score.

Scoring model:
  land_purchase               → +30
  zoning_application          → +25
  permit_activity             → +25
  engineering_activity        → +20
  developer_intent            → +20
  contractor_activity         → +15
  capital_signal              → +25
  parcel_signal_momentum      → +20
  relationship_graph_match    → +20
  civil_engineering_signal    → +20
  site_prep_activity          → +25
  utility_connection_request  → +25
  contractor_bid_signal       → +15

Cap: 100
"""
import json
import uuid
from datetime import datetime, timedelta

from db import get_db


# Signal type scoring weights
SIGNAL_SCORES = {
    'LAND_PURCHASE': 30,
    'ZONING_APPLICATION': 25,
    'BUILDING_PERMIT': 25,
    'SITE_PLAN_SUBMISSION': 20,
    'ENGINEERING_ENGAGEMENT': 20,
    'UTILITY_APPLICATION': 15,
    'LLC_FORMATION': 15,
    'DEVELOPER_EXPANSION': 20,
    'NEWS_SIGNAL': 10,
    'CONTRACTOR_ACTIVITY': 15,
    'CAPITAL_SIGNAL': 25,
    # Construction supply chain signals
    'CIVIL_ENGINEERING_PLAN': 20,
    'SITE_PREP_ACTIVITY': 25,
    'UTILITY_CONNECTION_REQUEST': 25,
    'EARTHWORK_CONTRACTOR': 15,
    'CONCRETE_SUPPLY_SIGNAL': 15,
    'INFRASTRUCTURE_BID': 15,
    # Planning agenda signals
    'ZONING_AGENDA_ITEM': 20,
    'REZONING_REQUEST': 30,
    'SUBDIVISION_APPLICATION': 25,
    'DEVELOPMENT_REVIEW_CASE': 20,
    # Building permit signals
    'MULTIFAMILY_PERMIT': 40,
    'SUBDIVISION_PERMIT': 35,
    'SITE_DEVELOPMENT_PERMIT': 30,
    'RESIDENTIAL_COMPLEX_PERMIT': 35,
    # Land transaction signals
    'DEED_TRANSFER': 25,
    'OWNER_CHANGE': 15,
    # Plat filing signals
    'SUBDIVISION_PLAT': 30,
    'PRELIMINARY_PLAT': 25,
    'FINAL_PLAT': 35,
    'LOT_SPLIT': 20,
    # Construction financing signals
    'CONSTRUCTION_FINANCING': 45,
    'COMMERCIAL_MORTGAGE': 35,
    'SECURED_LOAN': 25,
    # Utility connection intelligence signals
    'UTILITY_CAPACITY_EXPANSION': 30,
    'NEW_SERVICE_APPLICATION': 20,
    # Civil engineering filing signals
    'GRADING_PLAN': 20,
    'DRAINAGE_REPORT': 15,
    'ENGINEERING_REVIEW': 20,
    # Infrastructure planning signals
    'TRAFFIC_IMPACT_STUDY': 20,
    'ROAD_EXPANSION_APPROVAL': 25,
    'INFRASTRUCTURE_EXTENSION': 25,
    # Entity formation signals
    'DEVELOPMENT_ENTITY_FORMATION': 20,
    # Builder pattern signals
    'BUILDER_EXPANSION_PATTERN': 25,
    # Land listing signals
    'DEVELOPMENT_LAND_LISTING': 25,
    # Construction hiring signals
    'CONSTRUCTION_HIRING_SIGNAL': 15,
    # Signal correlation signals
    'SIGNAL_SEQUENCE_MATCH': 30,
}

# Bonus scores for pattern matches and relationships
PATTERN_MATCH_BONUS = 15
RELATIONSHIP_GRAPH_BONUS = 20
MOMENTUM_BONUS = 20


def score_all_parcels():
    """
    Calculate development probability for all parcels by aggregating:
    1. Signal type scores from property_signals
    2. Pattern match bonuses
    3. Relationship graph bonuses
    4. Momentum bonuses
    """
    conn = get_db()
    cur = conn.cursor()

    # Get all parcels
    cur.execute('SELECT parcel_id, city, state FROM parcels WHERE parcel_id IS NOT NULL')
    parcels = cur.fetchall()

    scored = 0
    cutoff_12m = (datetime.utcnow() - timedelta(days=365)).isoformat()

    for parcel_id, city, state in parcels:
        score = 0
        reasoning = []

        # 1. Signal type scores
        cur.execute('''
            SELECT DISTINCT signal_type FROM property_signals
            WHERE parcel_id = ? AND created_at >= ?
        ''', (parcel_id, cutoff_12m))
        signal_types = [r[0] for r in cur.fetchall()]

        for st in signal_types:
            pts = SIGNAL_SCORES.get(st, 5)
            score += pts
            reasoning.append(f"{st}: +{pts}")

        # 2. Also check development_events for this parcel
        try:
            cur.execute('''
                SELECT DISTINCT event_type FROM development_events
                WHERE parcel_id = ? AND created_at >= ?
            ''', (parcel_id, cutoff_12m))
            for (et,) in cur.fetchall():
                mapped = SIGNAL_SCORES.get(et.upper(), 0)
                if mapped and et.upper() not in [s.upper() for s in signal_types]:
                    score += mapped
                    reasoning.append(f"{et}: +{mapped}")
        except Exception:
            pass

        # 3. Pattern match bonus
        try:
            cur.execute('''
                SELECT COUNT(*) FROM pattern_matches WHERE parcel_id = ?
            ''', (parcel_id,))
            pattern_count = cur.fetchone()[0]
            if pattern_count > 0:
                bonus = min(pattern_count * PATTERN_MATCH_BONUS, 30)
                score += bonus
                reasoning.append(f"Pattern matches ({pattern_count}): +{bonus}")
        except Exception:
            pass

        # 4. Relationship graph bonus (includes signal graph engine scoring)
        try:
            cur.execute('''
                SELECT COUNT(*),
                       COALESCE(AVG(relationship_strength), 0),
                       COALESCE(MAX(relationship_strength), 0)
                FROM entity_relationships
                WHERE (entity_b = ? OR entity_a = ?)
                AND COALESCE(relationship_strength, 0) > 0
            ''', (parcel_id, parcel_id))
            row = cur.fetchone()
            rel_count = row[0] if row else 0
            avg_strength = row[1] if row else 0
            if rel_count > 0:
                # Enhanced bonus: factor in relationship strength
                base_bonus = min(rel_count * 5, RELATIONSHIP_GRAPH_BONUS)
                strength_bonus = min(int(avg_strength * 0.1), 5)
                bonus = min(base_bonus + strength_bonus, RELATIONSHIP_GRAPH_BONUS)
                score += bonus
                reasoning.append(f"Relationship graph ({rel_count}, strength {avg_strength:.0f}): +{bonus}")
        except Exception:
            # Fallback to simple count
            try:
                cur.execute('''
                    SELECT COUNT(*) FROM entity_relationships
                    WHERE entity_b = ? OR entity_a = ?
                ''', (parcel_id, parcel_id))
                rel_count = cur.fetchone()[0]
                if rel_count > 0:
                    bonus = min(rel_count * 5, RELATIONSHIP_GRAPH_BONUS)
                    score += bonus
                    reasoning.append(f"Relationship connections ({rel_count}): +{bonus}")
            except Exception:
                pass

        # 5. Signal momentum bonus
        cutoff_60 = (datetime.utcnow() - timedelta(days=60)).isoformat()
        cur.execute('''
            SELECT COUNT(*) FROM property_signals
            WHERE parcel_id = ? AND created_at >= ?
        ''', (parcel_id, cutoff_60))
        recent_count = cur.fetchone()[0]
        if recent_count >= 3:
            score += MOMENTUM_BONUS
            reasoning.append(f"Signal momentum ({recent_count} in 60d): +{MOMENTUM_BONUS}")
        elif recent_count >= 1:
            bonus = recent_count * 5
            score += bonus
            reasoning.append(f"Recent activity ({recent_count} in 60d): +{bonus}")

        # Cap at 100
        final_score = min(score, 100)

        # Store score
        try:
            cur.execute('''
                UPDATE parcels SET development_probability = ?
                WHERE parcel_id = ?
            ''', (final_score, parcel_id))

            # Also update parcel_development_probability table
            cur.execute('''
                SELECT id FROM parcel_development_probability WHERE parcel_id = ?
            ''', (parcel_id,))
            existing = cur.fetchone()
            reasoning_text = '; '.join(reasoning) if reasoning else 'No signals detected'

            if existing:
                cur.execute('''
                    UPDATE parcel_development_probability
                    SET probability_score = ?, reasoning = ?,
                        created_at = CURRENT_TIMESTAMP
                    WHERE parcel_id = ?
                ''', (final_score, reasoning_text, parcel_id))
            else:
                cur.execute('''
                    INSERT INTO parcel_development_probability
                    (id, parcel_id, probability_score, reasoning)
                    VALUES (?, ?, ?, ?)
                ''', (str(uuid.uuid4()), parcel_id, final_score, reasoning_text))

            scored += 1

            # Emit event for high-probability parcels
            if final_score >= 70:
                try:
                    from app import log_intelligence_event
                    log_intelligence_event(
                        event_type='HIGH_PROBABILITY',
                        title=f"High development probability — {city or 'Unknown'}, {state or ''}",
                        description=f"Score: {final_score}/100. {reasoning_text[:200]}",
                        city=city,
                        state=state,
                        related_entity=parcel_id,
                        entity_id=parcel_id,
                    )
                except Exception:
                    pass
        except Exception as e:
            print(f"[ProbEngine] Error scoring {parcel_id}: {e}")

    conn.commit()
    conn.close()
    print(f"[ProbEngine] Scored {scored} parcels")
    return {'parcels_scored': scored}


def run_probability_scoring():
    """Full probability scoring cycle."""
    print(f"[ProbEngine] START — {datetime.utcnow().isoformat()}")
    result = score_all_parcels()
    print(f"[ProbEngine] COMPLETE")
    return result
