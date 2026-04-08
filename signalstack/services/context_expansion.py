"""
Context Expansion Layer.

This is the FIRST reasoning stage in the pipeline. It takes raw profile
keywords, notes, signals, and prospect facts and produces a small set of
plausible situational HYPOTHESES about what the prospect is likely
dealing with right now.

The motivation: SignalStack used to hard-block generation when the
available context was thin ("no signals, no notes, no profile → no
message"). That made the product feel broken on LinkedIn-only inputs,
which is the most common real-world case. The new behaviour is a
graded, confidence-driven pipeline where we ALWAYS try to produce
thoughtful output — but we label how strong the grounding is and we
lean on intelligent generalization instead of fabricated specifics.

HARD RULES:

  * NEVER fabricate personal facts about the individual. Hypotheses
    are POSSIBILITIES, not claims. They must always be framed as
    "likely", "possibly", "may be", "often sees", "tends to", etc.
  * Hypotheses describe GENERIC market / role / segment patterns,
    NOT specific deals, numbers, dates, relationships, or life
    details.
  * The downstream generator is required to respect this framing —
    hypothesis-based messages must read as curiosity or pattern
    observation, not as claims of knowledge.

Returned shape::

    {
      "hypotheses": [
        {
          "text": "likely involved in BTR development or capital allocation",
          "basis": "title|industry|market|profile_topic|company|default",
          "strength": "strong|moderate|weak",
        },
        ...
      ],
      "confidence_level": "low|medium|high",
      "confidence_score": 0..1,
      "inferred_role_family": "operator|capital|broker|developer|advisor|unknown",
      "inferred_market": "sunbelt|texas|southeast|national|unknown",
      "inferred_activity": "expansion|capital_raising|land_acquisition|ops|unknown",
      "basis_counts": {"signals": N, "notes": N, "profile": N, "prospect": N},
    }
"""
from __future__ import annotations

from typing import Optional

MAX_HYPOTHESES = 5
MIN_HYPOTHESES = 3

# Minimum hypothesis text length we'll accept. Anything shorter is
# probably a stub and gets dropped.
MIN_HYPOTHESIS_CHARS = 20

# Role-family dictionary — very lightweight. We only need enough to
# branch the hypothesis set, not a full taxonomy.
_ROLE_KEYWORDS = {
    "capital": (
        "investor", "investment", "capital", "fund", "lp", "gp",
        "portfolio", "pe ", "private equity", "asset management",
        "acquisitions", "cio", "managing director", "principal",
    ),
    "developer": (
        "developer", "development", "land", "entitlement", "project",
        "construction", "build-to-rent", "btr", "sfr", "townhome",
    ),
    "operator": (
        "operator", "operating", "president", "coo", "ceo", "founder",
        "property management", "asset manager",
    ),
    "broker": (
        "broker", "brokerage", "advisor", "advisory", "capital markets",
        "placement", "debt", "equity placement", "jll", "cbre",
        "newmark", "eastdil", "walker & dunlop",
    ),
}

_MARKET_KEYWORDS = {
    "sunbelt": ("sunbelt", "sun belt"),
    "texas": ("texas", "dallas", "austin", "houston", "san antonio", "ftw", "dfw"),
    "southeast": (
        "southeast", "charlotte", "raleigh", "atlanta", "nashville",
        "tampa", "orlando", "miami", "florida", "north carolina",
        "south carolina", "georgia", "tennessee",
    ),
    "west": ("phoenix", "denver", "boise", "utah", "las vegas", "seattle"),
    "midwest": ("columbus", "indianapolis", "minneapolis", "chicago"),
}

_ACTIVITY_KEYWORDS = {
    "expansion": (
        "expansion", "expanding", "new market", "entering", "launch",
        "grow", "scaling",
    ),
    "capital_raising": (
        "raise", "raising", "fundraise", "close", "closing", "lp",
        "capital raise", "debt facility", "credit facility",
    ),
    "land_acquisition": (
        "land", "site", "entitlement", "zoning", "acquisition", "acquire",
    ),
    "ops": (
        "ops", "operations", "lease-up", "nois", "yield", "expense",
        "efficiency", "cost",
    ),
    "hiring": (
        "hiring", "hire", "recruit", "team build", "head of",
    ),
}


def _lc(s: Optional[str]) -> str:
    return (s or "").strip().lower()


def _any_in(text: str, needles: tuple[str, ...]) -> bool:
    return any(n in text for n in needles)


def _classify_role(corpus: str) -> str:
    for family, kws in _ROLE_KEYWORDS.items():
        if _any_in(corpus, kws):
            return family
    return "unknown"


def _classify_market(corpus: str) -> str:
    for market, kws in _MARKET_KEYWORDS.items():
        if _any_in(corpus, kws):
            return market
    return "unknown"


def _classify_activity(corpus: str) -> str:
    for activity, kws in _ACTIVITY_KEYWORDS.items():
        if _any_in(corpus, kws):
            return activity
    return "unknown"


def _hypothesis(text: str, basis: str, strength: str) -> dict:
    return {
        "text": (text or "").strip(),
        "basis": basis,
        "strength": strength,
    }


def _role_hypotheses(role: str, market: str) -> list[dict]:
    """Return 2-3 generic hypotheses plausible for the role+market mix.

    Every hypothesis is framed as a POSSIBILITY, never a claim. The
    downstream generator must not upgrade these to assertions.
    """
    market_phrase = "expansion-phase markets" if market == "unknown" else f"the {market} market"
    out: list[dict] = []

    if role == "capital":
        out.append(_hypothesis(
            f"likely focused on capital deployment decisions in {market_phrase} right now",
            basis="title", strength="moderate",
        ))
        out.append(_hypothesis(
            "possibly weighing yield expectations against a moving cost-of-capital picture",
            basis="role_pattern", strength="moderate",
        ))
        out.append(_hypothesis(
            "may be seeing slower deal flow but sharper pricing on the deals that do print",
            basis="market_pattern", strength="weak",
        ))
    elif role == "developer":
        out.append(_hypothesis(
            f"likely sourcing land or pipeline in {market_phrase}",
            basis="title", strength="moderate",
        ))
        out.append(_hypothesis(
            "possibly balancing cost pressure vs. absorption assumptions on new product",
            basis="role_pattern", strength="moderate",
        ))
        out.append(_hypothesis(
            "may be navigating a narrower window between entitlement and groundbreaking",
            basis="market_pattern", strength="weak",
        ))
    elif role == "operator":
        out.append(_hypothesis(
            "likely running a portfolio where NOI upside now comes from cost discipline, not rent growth",
            basis="role_pattern", strength="moderate",
        ))
        out.append(_hypothesis(
            f"possibly seeing operating mix shift in {market_phrase} as supply catches up",
            basis="market_pattern", strength="moderate",
        ))
        out.append(_hypothesis(
            "may be rethinking the ops stack now that cheap-rate assumptions are gone",
            basis="market_pattern", strength="weak",
        ))
    elif role == "broker":
        out.append(_hypothesis(
            "likely seeing increased deal flow from sellers with debt maturities coming due",
            basis="role_pattern", strength="moderate",
        ))
        out.append(_hypothesis(
            f"possibly placing more capital into {market_phrase} via non-traditional structures",
            basis="role_pattern", strength="moderate",
        ))
        out.append(_hypothesis(
            "may be spending more time on pricing discovery than on closing right now",
            basis="market_pattern", strength="weak",
        ))
    else:
        # Unknown role — keep it generic BTR/CRE-safe.
        out.append(_hypothesis(
            "likely involved in BTR, multifamily, or adjacent CRE decisions",
            basis="default", strength="weak",
        ))
        out.append(_hypothesis(
            "possibly operating in expansion-phase or secondary markets",
            basis="default", strength="weak",
        ))
        out.append(_hypothesis(
            "may be focused on cost efficiency vs. yield optimization",
            basis="default", strength="weak",
        ))

    return out


def _activity_hypothesis(activity: str, market: str) -> Optional[dict]:
    if activity == "unknown":
        return None
    market_phrase = "secondary markets" if market == "unknown" else f"the {market} market"
    mapping = {
        "expansion": (
            f"the team may be in an expansion-planning window for {market_phrase}",
            "moderate",
        ),
        "capital_raising": (
            "possibly active on the capital-raising side, which usually reshuffles deal priorities",
            "moderate",
        ),
        "land_acquisition": (
            f"likely evaluating land or pipeline opportunities in {market_phrase}",
            "moderate",
        ),
        "ops": (
            "possibly leaning into operating efficiency rather than pure yield optimization",
            "moderate",
        ),
        "hiring": (
            "may be scaling the team, which often signals a shift in focus or coverage",
            "moderate",
        ),
    }
    pair = mapping.get(activity)
    if not pair:
        return None
    return _hypothesis(pair[0], basis="activity_keyword", strength=pair[1])


def _dedupe(hypotheses: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for h in hypotheses:
        key = _lc(h.get("text"))
        if len(key) < MIN_HYPOTHESIS_CHARS or key in seen:
            continue
        seen.add(key)
        out.append(h)
    return out


def _decide_confidence(
    tier1_hits: int,
    tier2_hits: int,
    tier3_hits: int,
) -> tuple[str, float]:
    """
    Graded confidence classifier.

    - HIGH  : at least one Tier 1 signal or note (real situational input)
    - MEDIUM: Tier 2 profile fields (industry, market, function, topics)
    - LOW   : Tier 3 only (name/title/company/location) or nothing at all
    """
    if tier1_hits >= 1:
        score = min(1.0, 0.6 + 0.1 * tier1_hits + 0.05 * tier2_hits)
        return "high", round(score, 3)
    if tier2_hits >= 1:
        score = min(0.75, 0.35 + 0.1 * tier2_hits + 0.05 * tier3_hits)
        return "medium", round(score, 3)
    return "low", round(min(0.3, 0.1 + 0.05 * tier3_hits), 3)


def expand_context(context: dict) -> dict:
    """Run the context expansion layer over a prepared generator context.

    This is side-effect-free: it does NOT mutate ``context``. The caller
    is responsible for stashing the result onto ``context`` so downstream
    stages can read it.
    """
    prospect = context.get("prospect") or {}
    company = context.get("company") or {}
    profile = context.get("profile") or {}
    signals = context.get("signals") or []
    notes = context.get("notes") or []

    # Build a single lowercase corpus for keyword matching. Limit each
    # blob so we don't let one gigantic about_text dominate the classifier.
    parts: list[str] = []
    for field in ("title", "full_name", "company_name", "industry", "location"):
        parts.append(_lc(prospect.get(field))[:160])
    for field in ("name", "industry", "company_type"):
        parts.append(_lc(company.get(field))[:160])
    for field in (
        "headline", "featured_topics", "shared_context",
        "current_role", "function", "market", "industry",
    ):
        parts.append(_lc(profile.get(field))[:160])
    parts.append(_lc(profile.get("about_text"))[:400])
    for s in signals[:6]:
        parts.append(_lc(s.get("text"))[:160])
        parts.append(_lc(s.get("type")))
    for n in notes[:4]:
        parts.append(_lc(n.get("body"))[:200])
    corpus = " ".join(p for p in parts if p)

    role_family = _classify_role(corpus)
    market = _classify_market(corpus)
    activity = _classify_activity(corpus)

    # Basis counts — used by the downstream "message_basis" label.
    basis_counts = {
        "signals": len(signals),
        "notes": len([n for n in notes if (n.get("body") or "").strip()]),
        "profile": sum(
            1 for f in (
                "headline", "about_text", "featured_topics", "shared_context",
                "current_role", "function", "industry", "market",
            ) if profile.get(f)
        ),
        "prospect": sum(
            1 for f in ("title", "company_name", "location", "industry")
            if prospect.get(f)
        ),
    }

    confidence_level, confidence_score = _decide_confidence(
        tier1_hits=basis_counts["signals"] + basis_counts["notes"],
        tier2_hits=basis_counts["profile"],
        tier3_hits=basis_counts["prospect"],
    )

    hypotheses: list[dict] = []
    hypotheses.extend(_role_hypotheses(role_family, market))

    act_h = _activity_hypothesis(activity, market)
    if act_h:
        hypotheses.append(act_h)

    # If the profile names featured topics, we can add a very lightly
    # specific hypothesis that is still framed as a possibility. We
    # never quote the topic verbatim — we paraphrase it.
    topics = _lc(profile.get("featured_topics"))
    if topics:
        hypotheses.append(_hypothesis(
            "likely paying attention to the topics they've been publicly engaging with",
            basis="profile_topic", strength="weak",
        ))

    hypotheses = _dedupe(hypotheses)

    # Trim to our hard bounds. We prefer to return MIN..MAX hypotheses;
    # if we somehow ended up with fewer we still return what we have
    # — the generator treats zero hypotheses as a pure-low path.
    if len(hypotheses) > MAX_HYPOTHESES:
        hypotheses = hypotheses[:MAX_HYPOTHESES]

    return {
        "hypotheses": hypotheses,
        "confidence_level": confidence_level,
        "confidence_score": confidence_score,
        "inferred_role_family": role_family,
        "inferred_market": market,
        "inferred_activity": activity,
        "basis_counts": basis_counts,
    }
