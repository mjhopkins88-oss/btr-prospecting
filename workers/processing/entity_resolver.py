"""
Entity Resolution Worker.
Merges duplicate companies and projects using fuzzy matching,
and links signals to the correct canonical entities.
"""
import json
import re
from shared.database import get_db, fetch_all, execute


def _fuzzy_match(a, b, threshold=0.85):
    """Simple Jaccard similarity on character trigrams."""
    if not a or not b:
        return 0.0
    a, b = a.lower().strip(), b.lower().strip()
    if a == b:
        return 1.0
    tri_a = set(a[i:i+3] for i in range(len(a)-2))
    tri_b = set(b[i:i+3] for i in range(len(b)-2))
    if not tri_a or not tri_b:
        return 0.0
    intersection = len(tri_a & tri_b)
    union = len(tri_a | tri_b)
    return intersection / union if union > 0 else 0.0


def resolve_companies(threshold=0.85):
    """
    Find and merge duplicate companies.
    Keeps the company with the most signals as canonical.
    """
    companies = fetch_all(
        "SELECT c.id, c.name, COUNT(s.id) as sig_count "
        "FROM li_companies c "
        "LEFT JOIN li_signals s ON s.company_id = c.id "
        "GROUP BY c.id, c.name "
        "ORDER BY sig_count DESC"
    )
    if len(companies) < 2:
        return 0

    merged = 0
    seen = set()

    for i, canonical in enumerate(companies):
        if canonical['id'] in seen:
            continue
        for j in range(i + 1, len(companies)):
            dup = companies[j]
            if dup['id'] in seen:
                continue
            score = _fuzzy_match(canonical['name'], dup['name'], threshold)
            if score >= threshold:
                # Merge: move all references from dup to canonical
                conn = get_db()
                cur = conn.cursor()
                try:
                    cur.execute(
                        "UPDATE li_signals SET company_id = ? WHERE company_id = ?",
                        (canonical['id'], dup['id'])
                    )
                    cur.execute(
                        "UPDATE li_leads SET company_id = ? WHERE company_id = ?",
                        (canonical['id'], dup['id'])
                    )
                    cur.execute(
                        "UPDATE li_contacts SET company_id = ? WHERE company_id = ?",
                        (canonical['id'], dup['id'])
                    )
                    cur.execute("DELETE FROM li_companies WHERE id = ?", (dup['id'],))
                    conn.commit()
                    merged += 1
                    seen.add(dup['id'])
                    print(f"[EntityResolver] Merged company '{dup['name']}' → '{canonical['name']}'")
                except Exception as e:
                    conn.rollback()
                    print(f"[EntityResolver] Error merging: {e}")
                finally:
                    conn.close()

    print(f"[EntityResolver] Merged {merged} duplicate companies.")
    return merged


def resolve_projects(threshold=0.80):
    """
    Find and merge duplicate projects (same city/state, similar name).
    """
    projects = fetch_all(
        "SELECT p.id, p.name, p.city, p.state, COUNT(s.id) as sig_count "
        "FROM li_projects p "
        "LEFT JOIN li_signals s ON s.project_id = p.id "
        "GROUP BY p.id, p.name, p.city, p.state "
        "ORDER BY sig_count DESC"
    )
    if len(projects) < 2:
        return 0

    merged = 0
    seen = set()

    for i, canonical in enumerate(projects):
        if canonical['id'] in seen:
            continue
        for j in range(i + 1, len(projects)):
            dup = projects[j]
            if dup['id'] in seen:
                continue
            # Only merge within same city/state
            if (canonical.get('city') or '').lower() != (dup.get('city') or '').lower():
                continue
            if (canonical.get('state') or '').lower() != (dup.get('state') or '').lower():
                continue

            score = _fuzzy_match(canonical['name'], dup['name'])
            if score >= threshold:
                conn = get_db()
                cur = conn.cursor()
                try:
                    cur.execute(
                        "UPDATE li_signals SET project_id = ? WHERE project_id = ?",
                        (canonical['id'], dup['id'])
                    )
                    cur.execute(
                        "UPDATE li_leads SET project_id = ? WHERE project_id = ?",
                        (canonical['id'], dup['id'])
                    )
                    cur.execute("DELETE FROM li_projects WHERE id = ?", (dup['id'],))
                    conn.commit()
                    merged += 1
                    seen.add(dup['id'])
                    print(f"[EntityResolver] Merged project '{dup['name']}' → '{canonical['name']}'")
                except Exception as e:
                    conn.rollback()
                    print(f"[EntityResolver] Error merging project: {e}")
                finally:
                    conn.close()

    print(f"[EntityResolver] Merged {merged} duplicate projects.")
    return merged


def resolve_all():
    """Run all entity resolution passes."""
    c = resolve_companies()
    p = resolve_projects()
    return c + p
