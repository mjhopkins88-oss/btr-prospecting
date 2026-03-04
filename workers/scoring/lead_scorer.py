"""
Lead Scoring Engine.
Computes composite lead scores based on signal strength, entity fit,
timing, market conditions, and recency.
"""
import json
from datetime import datetime, timedelta
from shared.config import (
    SCORE_WEIGHT_SIGNAL_STRENGTH,
    SCORE_WEIGHT_ENTITY_FIT,
    SCORE_WEIGHT_TIMING,
    SCORE_WEIGHT_MARKET,
    SCORE_WEIGHT_RECENCY,
)
from shared.database import get_db, fetch_all, fetch_one, new_id


# --- Signal type weights (base) ---
SIGNAL_TYPE_WEIGHTS = {
    'land_acquisition': 0.9,
    'permit_filed': 0.85,
    'construction_start': 0.8,
    'project_announced': 0.7,
    'funding': 0.75,
    'zoning_change': 0.65,
    'news': 0.5,
    'other': 0.3,
}

# --- Project status progression ---
STATUS_SCORES = {
    'rumored': 0.3,
    'planning': 0.5,
    'entitled': 0.65,
    'permitted': 0.75,
    'under_construction': 0.85,
    'leasing': 0.6,
    'completed': 0.2,
}

# --- Grade thresholds ---
GRADE_THRESHOLDS = [
    (90, 'A+'), (80, 'A'), (70, 'B+'), (60, 'B'),
    (50, 'C+'), (40, 'C'), (30, 'D'), (0, 'F'),
]


def _compute_signal_strength(signals):
    """Weighted average of signal strengths, boosted by signal type."""
    if not signals:
        return 0.0
    total = 0.0
    weight_sum = 0.0
    for sig in signals:
        type_weight = SIGNAL_TYPE_WEIGHTS.get(sig.get('signal_type', 'other'), 0.3)
        strength = float(sig.get('strength', 0.5))
        w = type_weight * strength
        total += w
        weight_sum += type_weight
    return (total / weight_sum * 100) if weight_sum > 0 else 0.0


def _compute_entity_fit(project, company):
    """Score how well the project/company fits our ICP."""
    score = 50.0  # base
    if project:
        ptype = (project.get('project_type') or '').lower()
        if ptype in ('btr', 'sfr'):
            score += 30
        elif ptype in ('multifamily', 'mixed_use'):
            score += 15
        unit_count = project.get('unit_count') or 0
        if unit_count >= 200:
            score += 20
        elif unit_count >= 50:
            score += 10
    if company:
        ctype = (company.get('company_type') or '').lower()
        if ctype == 'developer':
            score += 10
        elif ctype == 'builder':
            score += 5
    return min(100.0, score)


def _compute_timing(project):
    """Score based on project status / lifecycle stage."""
    if not project:
        return 50.0
    status = (project.get('status') or 'rumored').lower()
    return STATUS_SCORES.get(status, 0.3) * 100


def _compute_market(project):
    """Score based on market attractiveness (city/state)."""
    hot_markets = {
        'phoenix': 90, 'dallas': 85, 'atlanta': 80, 'charlotte': 75,
        'nashville': 80, 'tampa': 75, 'denver': 70, 'raleigh': 75,
        'austin': 80, 'orlando': 70,
    }
    city = (project.get('city') or '').lower()
    return float(hot_markets.get(city, 50))


def _compute_recency(signals):
    """Score based on how recently signals were created."""
    if not signals:
        return 0.0
    now = datetime.utcnow()
    best = 0.0
    for sig in signals:
        created = sig.get('created_at')
        if not created:
            continue
        try:
            if isinstance(created, str):
                created = datetime.fromisoformat(created.replace('Z', '+00:00').replace('+00:00', ''))
            age_days = (now - created).days
            if age_days <= 1:
                score = 100
            elif age_days <= 7:
                score = 80
            elif age_days <= 30:
                score = 60
            elif age_days <= 90:
                score = 30
            else:
                score = 10
            best = max(best, score)
        except Exception:
            pass
    return best


def _grade(score):
    """Convert numeric score to letter grade."""
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return 'F'


def _load_weight_overrides():
    """Load per-signal-type weight overrides from li_score_weights."""
    rows = fetch_all("SELECT signal_type, weight FROM li_score_weights")
    overrides = {}
    for r in rows:
        overrides[r['signal_type']] = float(r['weight'])
    return overrides


def score_leads(limit=100):
    """
    Score all projects that have signals, creating or updating li_leads entries.
    """
    # Load weight overrides from feedback loop
    overrides = _load_weight_overrides()
    for sig_type, w in overrides.items():
        if sig_type in SIGNAL_TYPE_WEIGHTS:
            SIGNAL_TYPE_WEIGHTS[sig_type] = w

    # Get projects with signals
    projects = fetch_all(
        "SELECT DISTINCT p.id, p.name, p.city, p.state, p.project_type, "
        "p.status, p.unit_count, p.estimated_value "
        "FROM li_projects p "
        "INNER JOIN li_signals s ON s.project_id = p.id "
        "ORDER BY p.created_at DESC LIMIT ?",
        [limit]
    )

    if not projects:
        print("[LeadScorer] No projects with signals to score.")
        return 0

    conn = get_db()
    cur = conn.cursor()
    scored = 0

    for proj in projects:
        # Get signals for this project
        signals = fetch_all(
            "SELECT signal_type, strength, created_at FROM li_signals "
            "WHERE project_id = ? ORDER BY strength DESC",
            [proj['id']]
        )

        # Get associated company (most frequent)
        company = fetch_one(
            "SELECT c.id, c.name, c.company_type "
            "FROM li_companies c "
            "INNER JOIN li_signals s ON s.company_id = c.id "
            "WHERE s.project_id = ? "
            "GROUP BY c.id, c.name, c.company_type "
            "ORDER BY COUNT(*) DESC LIMIT 1",
            [proj['id']]
        )

        # Compute component scores
        sig_score = _compute_signal_strength(signals)
        fit_score = _compute_entity_fit(proj, company)
        timing_score = _compute_timing(proj)
        market_score = _compute_market(proj)
        recency_score = _compute_recency(signals)

        # Weighted composite
        composite = (
            sig_score * SCORE_WEIGHT_SIGNAL_STRENGTH +
            fit_score * SCORE_WEIGHT_ENTITY_FIT +
            timing_score * SCORE_WEIGHT_TIMING +
            market_score * SCORE_WEIGHT_MARKET +
            recency_score * SCORE_WEIGHT_RECENCY
        )

        grade = _grade(composite)
        components = json.dumps({
            'signal_strength': round(sig_score, 1),
            'entity_fit': round(fit_score, 1),
            'timing': round(timing_score, 1),
            'market': round(market_score, 1),
            'recency': round(recency_score, 1),
        })

        company_id = company['id'] if company else None
        lead_id = new_id()

        try:
            # Upsert lead
            cur.execute(
                "SELECT id FROM li_leads WHERE project_id = ? AND company_id IS NOT DISTINCT FROM ?",
                (proj['id'], company_id)
            ) if False else None  # placeholder for postgres IS NOT DISTINCT FROM

            # Use simpler approach: delete + insert
            cur.execute(
                "DELETE FROM li_leads WHERE project_id = ? AND company_id = ?",
                (proj['id'], company_id)
            )
            cur.execute('''
                INSERT INTO li_leads
                (id, project_id, company_id, score, score_components, grade,
                 status, region, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'new', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ''', (
                lead_id, proj['id'], company_id,
                round(composite, 1), components, grade,
                (proj.get('state') or '').upper(),
            ))
            scored += 1
        except Exception as e:
            print(f"[LeadScorer] Error scoring project {proj['name']}: {e}")

    conn.commit()
    conn.close()
    print(f"[LeadScorer] Scored {scored}/{len(projects)} leads.")
    return scored
