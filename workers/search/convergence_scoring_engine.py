"""
Convergence Scoring Engine

Ranks development opportunities based on the number and strength of
overlapping intelligence signals. A high convergence score means multiple
independent signals point to the same opportunity.

Signals evaluated:
- parcel_development_probability
- developer_intent_predictions
- contractor_activity
- capital_predictions
- opportunity_clusters
- predicted_developments (base record)

Scoring model (max 100):
    signal_count * 20         (multi-signal bonus)
    parcel_probability * 0.3  (parcel weight)
    developer_intent          +25
    contractor_activity       +15
    capital_signal            +30
    cluster_detected          +15
    developer_dna_match       +10
"""
from datetime import datetime, timedelta

from shared.database import fetch_all, fetch_one, execute


# ---------------------------------------------------------------------------
# Signal collection per opportunity
# ---------------------------------------------------------------------------

def _collect_signals_for_prediction(pred):
    """
    Gather all related signals for a single predicted project.
    Returns a dict with signal presence flags, counts, and labels.
    """
    city = pred.get("city")
    state = pred.get("state")
    developer = pred.get("developer")
    since = (datetime.utcnow() - timedelta(days=30)).isoformat()

    signals = {
        "signal_types": [],
        "signal_count": 0,
        "parcel_probability": 0,
        "developer_intent_detected": False,
        "contractor_activity_detected": False,
        "capital_signal_detected": False,
        "cluster_detected": bool(pred.get("cluster_detected")),
        "developer_dna_match": bool(pred.get("developer_expansion_signal")),
    }

    # Parcel development probability
    parcel = fetch_one(
        "SELECT MAX(probability_score) as max_prob FROM parcel_development_probability "
        "WHERE city = ? AND state = ? AND created_at >= ?",
        [city, state, since]
    )
    if parcel and parcel.get("max_prob"):
        signals["parcel_probability"] = parcel["max_prob"]
        if parcel["max_prob"] >= 50:
            signals["signal_types"].append("Parcel Probability")

    # Developer intent predictions
    intent = fetch_one(
        "SELECT id FROM developer_intent_predictions "
        "WHERE city = ? AND state = ? AND created_at >= ? LIMIT 1",
        [city, state, since]
    )
    if intent:
        signals["developer_intent_detected"] = True
        signals["signal_types"].append("Developer Intent")

    # Contractor activity
    contractor = fetch_one(
        "SELECT id FROM contractor_activity "
        "WHERE city = ? AND state = ? AND created_at >= ? LIMIT 1",
        [city, state, since]
    )
    if contractor:
        signals["contractor_activity_detected"] = True
        signals["signal_types"].append("Contractor Activity")

    # Capital predictions
    capital = fetch_one(
        "SELECT id FROM capital_predictions "
        "WHERE city = ? AND state = ? AND created_at >= ? LIMIT 1",
        [city, state, since]
    )
    if capital:
        signals["capital_signal_detected"] = True
        signals["signal_types"].append("Capital Deployment")

    # Opportunity clusters
    cluster = fetch_one(
        "SELECT id FROM opportunity_clusters "
        "WHERE city = ? AND state = ? AND created_at >= ? LIMIT 1",
        [city, state, since]
    )
    if cluster:
        signals["cluster_detected"] = True
        if "Opportunity Cluster" not in signals["signal_types"]:
            signals["signal_types"].append("Opportunity Cluster")

    # Developer DNA match from the prediction itself
    if signals["developer_dna_match"]:
        signals["signal_types"].append("Developer DNA Match")

    signals["signal_count"] = len(signals["signal_types"])
    return signals


# ---------------------------------------------------------------------------
# Scoring calculation
# ---------------------------------------------------------------------------

def calculate_convergence_score(signals):
    """
    Calculate the convergence score for a set of signals.

    Scoring:
        signal_count * 20              (multi-signal bonus)
        parcel_probability * 0.3       (parcel weight)
        developer_intent_detected      +25
        contractor_activity_detected   +15
        capital_signal_detected        +30
        cluster_detected               +15
        developer_dna_match            +10

    Capped at 100.
    """
    score = 0

    score += signals["signal_count"] * 20
    score += signals["parcel_probability"] * 0.3

    if signals["developer_intent_detected"]:
        score += 25
    if signals["contractor_activity_detected"]:
        score += 15
    if signals["capital_signal_detected"]:
        score += 30
    if signals["cluster_detected"]:
        score += 15
    if signals["developer_dna_match"]:
        score += 10

    return min(int(score), 100)


# ---------------------------------------------------------------------------
# Store convergence score
# ---------------------------------------------------------------------------

def _store_convergence_score(prediction_id, convergence_score, signal_count, signal_types):
    """Update the predicted project index with convergence score data."""
    signal_types_str = ", ".join(signal_types)
    execute(
        """UPDATE predicted_project_index
           SET convergence_score = ?, convergence_signal_count = ?,
               convergence_signal_types = ?
           WHERE id = ?""",
        [convergence_score, signal_count, signal_types_str, prediction_id]
    )


# ---------------------------------------------------------------------------
# Main scoring run
# ---------------------------------------------------------------------------

def score_all_predictions():
    """Score all predicted projects with convergence scores."""
    predictions = fetch_all(
        "SELECT id, city, state, developer, cluster_detected, "
        "developer_expansion_signal FROM predicted_project_index"
    )

    if not predictions:
        # Fallback to predicted_projects
        predictions = fetch_all(
            "SELECT id, city, state, developer, cluster_detected, "
            "developer_expansion_signal FROM predicted_projects"
        )

    scored = 0
    for pred in predictions:
        try:
            signals = _collect_signals_for_prediction(pred)
            convergence = calculate_convergence_score(signals)
            _store_convergence_score(
                pred["id"],
                convergence,
                signals["signal_count"],
                signals["signal_types"]
            )
            scored += 1
        except Exception as e:
            print(f"[ConvergenceEngine] Error scoring {pred.get('id')}: {e}")

    print(f"[ConvergenceEngine] Scored {scored} predictions.")
    return scored


def run():
    """Execute the convergence scoring engine."""
    print("[ConvergenceEngine] Starting convergence scoring run...")
    count = score_all_predictions()
    print(f"[ConvergenceEngine] Complete. {count} predictions scored.")
    return count


if __name__ == "__main__":
    run()
