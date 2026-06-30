"""
Industry Playbook loader.

Strategic intelligence layer that selects relevant playbook entries based
on industry, signal types, message intent, and user instruction. The
selected entries are passed to the message generator to:

  * bias angle selection toward what works in this industry
  * surface example phrasings the generator can borrow tone from
  * surface anti-patterns the generator must avoid
  * give the UI a clear "why this angle" trail

Playbook entries are NEVER copy-pasted into messages as if they were
personalization. They shape strategy, not content.
"""
from __future__ import annotations

from typing import Optional

from .. import repo


# Map signal types and instruction keywords to playbook categories that
# carry the most relevant intelligence for that situation.
_SIGNAL_TYPE_TO_CATEGORIES = {
    "company_expansion": ["market_signals", "timing_triggers", "developer_behavior"],
    "hiring_activity":   ["developer_behavior", "outreach_angles"],
    "listing_activity":  ["market_signals", "capital_markets_behavior"],
    "deal_activity":     ["market_signals", "capital_markets_behavior", "timing_triggers"],
    "post_topic":        ["outreach_angles", "messaging_principles"],
    "company_news":      ["timing_triggers", "capital_markets_behavior"],
    "role_change":       ["developer_behavior", "outreach_angles"],
}

_DEFAULT_CATEGORIES = [
    "outreach_angles",
    "messaging_principles",
    "anti_patterns",
    "conversation_openers",
]


def _industry_matches_btr(industry: Optional[str]) -> bool:
    if not industry:
        return False
    s = industry.lower()
    return any(t in s for t in (
        "btr", "build-to-rent", "build to rent", "real estate",
        "cre", "multifamily", "sfr", "single-family rental", "land",
        "development", "homebuild", "construction",
    ))


def select_playbook_for_context(context: dict) -> Optional[dict]:
    """Pick the right playbook for this prospect/company context."""
    prospect = context.get("prospect") or {}
    company = context.get("company") or {}
    industry = prospect.get("industry") or company.get("industry") or ""
    if _industry_matches_btr(industry):
        return repo.get_playbook_by_name("btr_cre")
    # Default for now: BTR is the only playbook. Returning it as a soft
    # default is preferable to no intelligence at all when industry is
    # blank, but a future call site can return None instead.
    return repo.get_playbook_by_name("btr_cre")


def _categories_for(context: dict, instruction: Optional[str]) -> list[str]:
    cats: list[str] = []
    for s in context.get("signals") or []:
        for c in _SIGNAL_TYPE_TO_CATEGORIES.get((s.get("type") or "").lower(), []):
            if c not in cats:
                cats.append(c)
    instr = (instruction or "").lower()
    if any(k in instr for k in ("timing", "window", "quarter")):
        if "timing_triggers" not in cats:
            cats.append("timing_triggers")
    if any(k in instr for k in ("capital", "lp", "fund", "debt", "equity")):
        if "capital_markets_behavior" not in cats:
            cats.append("capital_markets_behavior")
    if any(k in instr for k in ("opener", "first touch", "intro")):
        if "conversation_openers" not in cats:
            cats.append("conversation_openers")
    for c in _DEFAULT_CATEGORIES:
        if c not in cats:
            cats.append(c)
    return cats


def load_relevant_entries(
    context: dict,
    instruction: Optional[str] = None,
    limit_per_category: int = 2,
    total_limit: int = 8,
) -> dict:
    """
    Return {playbook, entries, categories, reasoning} or an empty shell.
    The generator stays usable even when no playbook is found.
    """
    playbook = select_playbook_for_context(context)
    if not playbook:
        return {
            "playbook": None,
            "entries": [],
            "categories": [],
            "reasoning": "No matching industry playbook for this prospect.",
        }

    cats = _categories_for(context, instruction)
    all_entries = repo.list_playbook_entries(
        playbook_id=playbook["id"],
        categories=cats or None,
    )

    # Bucket per category, take top-N by confidence to keep this dense.
    by_cat: dict[str, list] = {}
    for e in sorted(all_entries, key=lambda r: -float(r.get("confidence") or 0)):
        by_cat.setdefault(e["category"], []).append(e)

    chosen: list[dict] = []
    for c in cats:
        for e in (by_cat.get(c) or [])[:limit_per_category]:
            chosen.append(e)
            if len(chosen) >= total_limit:
                break
        if len(chosen) >= total_limit:
            break

    reasoning = (
        f"Loaded {len(chosen)} entries from playbook '{playbook['name']}' "
        f"covering categories: {', '.join(cats[:5]) or 'defaults'}."
    )
    return {
        "playbook": playbook,
        "entries": chosen,
        "categories": cats,
        "reasoning": reasoning,
    }


def collect_anti_patterns(entries: list[dict]) -> list[str]:
    out: list[str] = []
    for e in entries:
        for ap in e.get("anti_patterns") or []:
            if ap and ap not in out:
                out.append(ap)
    return out


def preferred_angles(entries: list[dict]) -> list[str]:
    """Order angles by how often they appear across loaded entries."""
    counts: dict[str, float] = {}
    for e in entries:
        weight = float(e.get("confidence") or 0.5)
        for a in e.get("message_angles") or []:
            counts[a] = counts.get(a, 0) + weight
    return [a for a, _ in sorted(counts.items(), key=lambda x: -x[1])]
