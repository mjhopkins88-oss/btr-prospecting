"""
AI Enrichment Worker.
Takes normalized signals and uses Claude to enrich projects and companies
with additional structured data (contacts, deal type, timeline, etc.).
"""
import json
import traceback

try:
    import anthropic
except ImportError:
    anthropic = None

from shared.config import ANTHROPIC_API_KEY, AI_MODEL
from shared.database import get_db, fetch_all, fetch_one, new_id


def _enrich_project_with_ai(project, signals):
    """Use Claude to enrich a project with data extracted from its signals."""
    if not ANTHROPIC_API_KEY or not anthropic:
        return None

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    signals_text = json.dumps(signals[:10], indent=2, default=str)
    prompt = f"""Given this real estate development project and its associated news signals,
provide enriched data.

Project: {project['name']} in {project.get('city', '?')}, {project.get('state', '?')}
Current status: {project.get('status', 'unknown')}
Unit count: {project.get('unit_count', 'unknown')}

Signals:
{signals_text}

Return a JSON object with:
- "status": current project status (one of: "rumored", "planning", "entitled", "permitted", "under_construction", "leasing", "completed")
- "project_type": one of "BTR", "SFR", "multifamily", "mixed_use", "land", "other"
- "estimated_value": dollar amount as number or null
- "unit_count": number or null
- "timeline": estimated completion date or timeline description
- "key_companies": array of {{"name": str, "role": "developer"|"builder"|"investor"|"lender"}}
- "key_contacts": array of {{"name": str, "title": str, "company": str}}
- "summary": 2-3 sentence summary of the opportunity

Return ONLY valid JSON."""

    try:
        resp = client.messages.create(
            model=AI_MODEL,
            max_tokens=1500,
            messages=[{'role': 'user', 'content': prompt}]
        )
        text = resp.content[0].text.strip()
        if text.startswith('```'):
            text = text.split('\n', 1)[1]
            text = text.rsplit('```', 1)[0]
        return json.loads(text)
    except Exception as e:
        print(f"[AIEnricher] Error enriching project {project['name']}: {e}")
        return None


def _apply_enrichment(project_id, enrichment):
    """Write enrichment data back to entity graph tables."""
    if not enrichment:
        return

    conn = get_db()
    cur = conn.cursor()

    # Update project
    try:
        cur.execute('''
            UPDATE li_projects
            SET status = COALESCE(?, status),
                project_type = COALESCE(?, project_type),
                estimated_value = COALESCE(?, estimated_value),
                unit_count = COALESCE(?, unit_count),
                raw_json = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (
            enrichment.get('status'),
            enrichment.get('project_type'),
            enrichment.get('estimated_value'),
            enrichment.get('unit_count'),
            json.dumps(enrichment, default=str),
            project_id,
        ))
    except Exception as e:
        print(f"[AIEnricher] Error updating project: {e}")

    # Upsert companies from enrichment
    for comp in enrichment.get('key_companies', []):
        name = comp.get('name')
        if not name:
            continue
        comp_id = new_id()
        try:
            cur.execute(
                "INSERT OR IGNORE INTO li_companies (id, name, company_type, created_at, updated_at) "
                "VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
                (comp_id, name, comp.get('role', 'developer'))
            )
        except Exception:
            pass

    # Upsert contacts from enrichment
    for contact in enrichment.get('key_contacts', []):
        full_name = contact.get('name')
        if not full_name:
            continue
        # Find or create company
        company_name = contact.get('company')
        company_id = None
        if company_name:
            cur.execute("SELECT id FROM li_companies WHERE name = ?", (company_name,))
            row = cur.fetchone()
            company_id = row[0] if row else None

        contact_id = new_id()
        try:
            cur.execute(
                "INSERT OR IGNORE INTO li_contacts "
                "(id, company_id, full_name, title, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
                (contact_id, company_id, full_name, contact.get('title'))
            )
        except Exception:
            pass

    conn.commit()
    conn.close()


def enrich_projects(limit=20):
    """
    Enrich projects that have signals but haven't been enriched yet.
    Targets projects where raw_json is NULL (not yet enriched).
    """
    projects = fetch_all(
        "SELECT p.id, p.name, p.city, p.state, p.status, p.unit_count "
        "FROM li_projects p "
        "WHERE p.raw_json IS NULL "
        "ORDER BY p.created_at DESC LIMIT ?",
        [limit]
    )

    if not projects:
        print("[AIEnricher] No projects to enrich.")
        return 0

    enriched = 0
    for proj in projects:
        signals = fetch_all(
            "SELECT headline, body, signal_type, strength, url, published_at "
            "FROM li_signals WHERE project_id = ? ORDER BY strength DESC LIMIT 10",
            [proj['id']]
        )
        if not signals:
            continue

        print(f"[AIEnricher] Enriching: {proj['name']}...")
        result = _enrich_project_with_ai(proj, signals)
        if result:
            _apply_enrichment(proj['id'], result)
            enriched += 1

    print(f"[AIEnricher] Enriched {enriched}/{len(projects)} projects.")
    return enriched
