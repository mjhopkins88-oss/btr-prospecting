"""
Temporal Pattern Engine

Learns signal sequences from confirmed developments, then scores current
opportunities based on how closely their signal timeline matches proven
patterns. Produces a temporal_boost (0-40) that feeds into convergence scoring.

Two phases:
  1. LEARN  — analyze confirmed predictions to extract signal orderings + timing
  2. MATCH  — score unconfirmed predictions against learned sequences

Example learned pattern:
  Engineering Permit -> Contractor Activity -> Parcel Probability Spike -> Capital Signal
  avg gaps: 12d, 18d, 25d   total window: ~55 days   occurrences: 7   success: 85%

A current prediction that has the first 3 steps in that order within a
similar timeframe gets a strong temporal boost.
"""
import uuid
import json
from datetime import datetime, timedelta
from collections import defaultdict

from shared.database import fetch_all, fetch_one, execute


# ---------------------------------------------------------------------------
# Signal type normalization
# ---------------------------------------------------------------------------

SIGNAL_TYPE_MAP = {
    "LAND_PURCHASE": "Land Purchase",
    "ZONING_CASE": "Zoning Case",
    "SUBDIVISION_PLAT": "Subdivision Plat",
    "PERMIT_APPLICATION": "Engineering Permit",
    "CONTRACTOR_BID": "Contractor Activity",
    "NEWS_MENTION": "News Mention",
}

INTELLIGENCE_SIGNAL_TYPES = [
    "developer_intent_predictions",
    "contractor_activity",
    "capital_predictions",
    "parcel_development_probability",
    "opportunity_clusters",
]

INTELLIGENCE_LABEL_MAP = {
    "developer_intent_predictions": "Developer Intent",
    "contractor_activity": "Contractor Activity",
    "capital_predictions": "Capital Signal",
    "parcel_development_probability": "Parcel Probability Spike",
    "opportunity_clusters": "Opportunity Cluster",
}


# ---------------------------------------------------------------------------
# Phase 1: LEARN — extract sequences from confirmed developments
# ---------------------------------------------------------------------------

def _get_signal_timeline(city, state):
    """
    Build a chronological timeline of all signals for a city/state.
    Combines development_events and intelligence signals.
    Returns sorted list of (signal_label, date_str) tuples.
    """
    timeline = []

    # Development events
    events = fetch_all(
        "SELECT event_type, event_date FROM development_events "
        "WHERE city = ? AND state = ? AND event_date IS NOT NULL "
        "ORDER BY event_date ASC",
        [city, state]
    )
    for e in events:
        label = SIGNAL_TYPE_MAP.get(e.get("event_type"), e.get("event_type", "Unknown"))
        timeline.append((label, e.get("event_date")))

    # Developer intent
    intents = fetch_all(
        "SELECT created_at FROM developer_intent_predictions "
        "WHERE city = ? AND state = ? ORDER BY created_at ASC",
        [city, state]
    )
    for r in intents:
        timeline.append(("Developer Intent", r.get("created_at")))

    # Contractor activity
    contractors = fetch_all(
        "SELECT created_at FROM contractor_activity "
        "WHERE city = ? AND state = ? ORDER BY created_at ASC",
        [city, state]
    )
    for r in contractors:
        timeline.append(("Contractor Activity", r.get("created_at")))

    # Capital predictions
    capital = fetch_all(
        "SELECT created_at FROM capital_predictions "
        "WHERE city = ? AND state = ? ORDER BY created_at ASC",
        [city, state]
    )
    for r in capital:
        timeline.append(("Capital Signal", r.get("created_at")))

    # Parcel probability spikes
    parcels = fetch_all(
        "SELECT created_at FROM parcel_development_probability "
        "WHERE city = ? AND state = ? AND probability_score >= 70 "
        "ORDER BY created_at ASC",
        [city, state]
    )
    for r in parcels:
        timeline.append(("Parcel Probability Spike", r.get("created_at")))

    # Opportunity clusters
    clusters = fetch_all(
        "SELECT created_at FROM opportunity_clusters "
        "WHERE city = ? AND state = ? ORDER BY created_at ASC",
        [city, state]
    )
    for r in clusters:
        timeline.append(("Opportunity Cluster", r.get("created_at")))

    # Sort by date
    def parse_date(d):
        if d is None:
            return datetime.min
        if isinstance(d, datetime):
            return d
        try:
            return datetime.fromisoformat(str(d).replace("Z", "+00:00").replace("+00:00", ""))
        except Exception:
            return datetime.min

    timeline.sort(key=lambda x: parse_date(x[1]))

    # Deduplicate consecutive same-type signals
    deduped = []
    for label, dt in timeline:
        if not deduped or deduped[-1][0] != label:
            deduped.append((label, dt))

    return deduped


def _compute_step_gaps(timeline):
    """Compute day gaps between consecutive steps in a timeline."""
    gaps = []
    for i in range(1, len(timeline)):
        try:
            d1 = _parse_dt(timeline[i - 1][1])
            d2 = _parse_dt(timeline[i][1])
            gaps.append(max(0, (d2 - d1).days))
        except Exception:
            gaps.append(0)
    return gaps


def _parse_dt(d):
    if isinstance(d, datetime):
        return d
    return datetime.fromisoformat(str(d).replace("Z", "+00:00").replace("+00:00", ""))


def learn_temporal_patterns():
    """
    Analyze confirmed predictions to extract recurring signal sequences.
    Groups by sequence signature, counts occurrences, and stores to
    temporal_signal_sequences table.
    """
    print("[TemporalEngine] Phase 1: Learning from confirmed developments...")

    confirmed = fetch_all(
        "SELECT id, city, state, developer FROM predicted_projects WHERE confirmed = 1"
    )
    if not confirmed:
        confirmed = fetch_all(
            "SELECT id, city, state, developer FROM predicted_project_index WHERE confirmed = TRUE"
        )

    if not confirmed:
        print("[TemporalEngine] No confirmed predictions to learn from.")
        return 0

    # Collect sequence signatures
    sequence_stats = defaultdict(lambda: {
        "gaps_list": [],
        "window_list": [],
        "prediction_ids": [],
    })

    for pred in confirmed:
        timeline = _get_signal_timeline(pred["city"], pred["state"])
        if len(timeline) < 2:
            continue

        # Extract the ordered signal labels as the sequence signature
        steps = [t[0] for t in timeline]
        gaps = _compute_step_gaps(timeline)
        total_window = sum(gaps) if gaps else 0

        # Use 3-5 step subsequences as patterns
        for length in range(3, min(len(steps) + 1, 7)):
            sub_steps = steps[:length]
            sub_gaps = gaps[:length - 1]
            key = " -> ".join(sub_steps)

            seq = sequence_stats[key]
            seq["gaps_list"].append(sub_gaps)
            seq["window_list"].append(sum(sub_gaps) if sub_gaps else 0)
            seq["prediction_ids"].append(str(pred["id"]))

    # Store learned sequences
    stored = 0
    total_confirmed = len(confirmed)

    for seq_key, stats in sequence_stats.items():
        occurrences = len(stats["prediction_ids"])
        if occurrences < 1:
            continue

        # Average step gaps
        if stats["gaps_list"]:
            max_len = max(len(g) for g in stats["gaps_list"])
            avg_gaps = []
            for i in range(max_len):
                vals = [g[i] for g in stats["gaps_list"] if i < len(g)]
                avg_gaps.append(int(sum(vals) / len(vals)) if vals else 0)
        else:
            avg_gaps = []

        avg_window = int(sum(stats["window_list"]) / len(stats["window_list"])) if stats["window_list"] else 0
        success_rate = round((occurrences / max(total_confirmed, 1)) * 100, 2)

        # Generate a short name
        steps = seq_key.split(" -> ")
        initials = "".join(w[0].upper() for w in steps)
        seq_name = f"TEMPORAL_{initials}_{occurrences}"

        # Check if this sequence already exists
        existing = fetch_one(
            "SELECT id, occurrences FROM temporal_signal_sequences WHERE signal_steps = ?",
            [seq_key]
        )

        if existing:
            execute(
                """UPDATE temporal_signal_sequences
                   SET occurrences = ?, success_rate = ?, avg_step_gap_days = ?,
                       total_window_days = ?, source_predictions = ?, updated_at = NOW()
                   WHERE id = ?""",
                [occurrences, success_rate, json.dumps(avg_gaps), avg_window,
                 json.dumps(stats["prediction_ids"][:20]), existing["id"]]
            )
        else:
            execute(
                """INSERT INTO temporal_signal_sequences
                   (id, sequence_name, signal_steps, avg_step_gap_days,
                    total_window_days, occurrences, success_rate, source_predictions)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                [str(uuid.uuid4()), seq_name, seq_key, json.dumps(avg_gaps),
                 avg_window, occurrences, success_rate,
                 json.dumps(stats["prediction_ids"][:20])]
            )
        stored += 1

    print(f"[TemporalEngine] Learned {stored} temporal patterns from {len(confirmed)} confirmed predictions.")
    return stored


# ---------------------------------------------------------------------------
# Phase 2: MATCH — score current predictions against learned patterns
# ---------------------------------------------------------------------------

def _load_learned_sequences():
    """Load all learned temporal sequences, sorted by strength."""
    rows = fetch_all(
        "SELECT id, sequence_name, signal_steps, avg_step_gap_days, "
        "total_window_days, occurrences, success_rate "
        "FROM temporal_signal_sequences "
        "ORDER BY occurrences DESC, success_rate DESC"
    )
    for r in rows:
        try:
            r["steps_list"] = r["signal_steps"].split(" -> ")
        except Exception:
            r["steps_list"] = []
        try:
            r["gaps_list"] = json.loads(r.get("avg_step_gap_days") or "[]")
        except Exception:
            r["gaps_list"] = []
    return rows


def _match_prediction_to_sequences(pred, sequences):
    """
    Score a prediction's signal timeline against all learned sequences.
    Returns the best match dict with temporal_boost (0-40), matched
    pattern name, and current stage.
    """
    timeline = _get_signal_timeline(pred.get("city"), pred.get("state"))
    if not timeline:
        return {"temporal_boost": 0, "pattern_match": "", "match_stage": ""}

    current_labels = [t[0] for t in timeline]
    current_gaps = _compute_step_gaps(timeline)

    best_boost = 0
    best_match = ""
    best_stage = ""

    for seq in sequences:
        pattern_steps = seq["steps_list"]
        if not pattern_steps:
            continue

        # How many steps in order does the prediction match?
        matched_steps = 0
        for step in pattern_steps:
            if step in current_labels[matched_steps:]:
                idx = current_labels.index(step, matched_steps)
                matched_steps = idx + 1
            else:
                break

        if matched_steps < 2:
            continue

        # Step coverage ratio
        coverage = matched_steps / len(pattern_steps)

        # Timing similarity (compare gaps to learned averages)
        timing_bonus = 0
        learned_gaps = seq.get("gaps_list") or []
        if learned_gaps and current_gaps:
            gap_diffs = []
            for i in range(min(len(current_gaps), len(learned_gaps), matched_steps - 1)):
                expected = learned_gaps[i]
                actual = current_gaps[i] if i < len(current_gaps) else expected
                if expected > 0:
                    similarity = max(0, 1 - abs(actual - expected) / expected)
                    gap_diffs.append(similarity)
            if gap_diffs:
                timing_bonus = sum(gap_diffs) / len(gap_diffs) * 10  # up to +10

        # Occurrence weight — patterns seen more often are more reliable
        occ_weight = min(seq.get("occurrences", 1) / 5, 1.0)  # caps at 5 occurrences

        # Success rate weight
        sr_weight = min((seq.get("success_rate") or 0) / 100, 1.0)

        # Temporal boost formula (max 40):
        #   coverage * 20  (up to 20 for full sequence match)
        #   timing_bonus   (up to 10 for timing similarity)
        #   occ_weight * 5 (up to 5 for high-occurrence patterns)
        #   sr_weight * 5  (up to 5 for high success rate)
        boost = int(coverage * 20 + timing_bonus + occ_weight * 5 + sr_weight * 5)
        boost = min(boost, 40)

        if boost > best_boost:
            best_boost = boost
            best_match = seq.get("signal_steps", "")
            # Determine current stage
            if matched_steps >= len(pattern_steps):
                best_stage = f"Complete ({matched_steps}/{len(pattern_steps)})"
            else:
                next_step = pattern_steps[matched_steps] if matched_steps < len(pattern_steps) else "?"
                best_stage = f"Step {matched_steps}/{len(pattern_steps)} — next: {next_step}"

    return {
        "temporal_boost": best_boost,
        "pattern_match": best_match,
        "match_stage": best_stage,
    }


def score_temporal_patterns():
    """
    Score all predictions against learned temporal patterns.
    Updates predicted_project_index with temporal_boost, temporal_pattern_match,
    and temporal_match_stage.
    """
    print("[TemporalEngine] Phase 2: Matching predictions to temporal patterns...")

    sequences = _load_learned_sequences()
    if not sequences:
        print("[TemporalEngine] No learned sequences available. Run learn phase first.")
        return 0

    predictions = fetch_all(
        "SELECT id, city, state, developer FROM predicted_project_index"
    )
    if not predictions:
        predictions = fetch_all(
            "SELECT id, city, state, developer FROM predicted_projects"
        )

    scored = 0
    for pred in predictions:
        try:
            result = _match_prediction_to_sequences(pred, sequences)
            execute(
                """UPDATE predicted_project_index
                   SET temporal_boost = ?, temporal_pattern_match = ?,
                       temporal_match_stage = ?
                   WHERE id = ?""",
                [result["temporal_boost"], result["pattern_match"],
                 result["match_stage"], pred["id"]]
            )
            scored += 1
            if result["temporal_boost"] > 0:
                print(f"[TemporalEngine] {pred.get('city')}, {pred.get('state')}: "
                      f"boost={result['temporal_boost']} stage={result['match_stage']}")
        except Exception as e:
            print(f"[TemporalEngine] Error scoring {pred.get('id')}: {e}")

    print(f"[TemporalEngine] Scored {scored} predictions with temporal patterns.")
    return scored


# ---------------------------------------------------------------------------
# Full pipeline
# ---------------------------------------------------------------------------

def run():
    """Execute the full temporal pattern engine: learn then match."""
    print("[TemporalEngine] Starting temporal pattern analysis...")
    learned = learn_temporal_patterns()
    scored = score_temporal_patterns()
    print(f"[TemporalEngine] Complete. {learned} patterns learned, {scored} predictions scored.")
    return {"learned": learned, "scored": scored}


if __name__ == "__main__":
    run()
