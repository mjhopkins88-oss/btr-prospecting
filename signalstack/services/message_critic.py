"""
Message Critic / Evaluator.

Scores a generated candidate on multiple independent quality axes and
returns a structured verdict. The critic is the final "smart reader"
pass that runs AFTER the pure-heuristic validators (``anti_copy``,
``anti_generic_validator``, ``grounding``) have already been applied.

Scores are emitted for:
    - specificity         0..1  (is this about *this* prospect?)
    - naturalness         0..1  (does this read like a human wrote it?)
    - insightfulness      0..1  (does it carry an actual point of view?)
    - genericity          0..1  (higher = worse — boilerplate content)
    - pressure_level      0..1  (higher = worse — pushy / pitchy)
    - anti_copy           0..1  (higher = better — no raw-source overlap)
    - peer_credibility    0..1  (does it sound like a peer, not a vendor?)
    - grounding           0..1  (pulled from existing grounding verdict)

Aggregate:
    - overall_score       0..1  (weighted composite)
    - verdict             "accept|rewrite|reject"
    - notes               short human-readable reasons

The critic has two execution paths:

  * Deterministic. Always available. Computed from regex/length
    heuristics plus the verdicts produced by ``anti_copy``,
    ``anti_generic_validator``, and ``grounding``.

  * AI-augmented. Used when the provider exposes ``critique_candidate``.
    The AI output is merged into the deterministic scores so the
    critic never regresses into "all 0.5" if the AI path fails.
"""
from __future__ import annotations

import re
from typing import Any, Optional

# Phrase sets used by naturalness / pressure / peer_credibility scoring.
_PUSHY = (
    "quick call", "quick chat", "let's jump on", "let's hop on",
    "free this week", "15 minutes", "when's a good time",
    "open to a conversation", "book a time",
)
_VENDOR = (
    "i help companies like yours", "we help teams", "our platform",
    "our solution", "our product", "our tool", "reach out from",
    "check out our", "love to demo",
)
_TEMPLATE_MARKERS = (
    "hope this finds you well", "saw your profile", "came across your profile",
    "noticed your work as", "would love to connect",
    "congrats on your recent",
)

# A short list of concrete anchor signals that bump specificity. We don't
# need to be exhaustive — ``anti_generic_validator`` also scores this.
_CONCRETE_ANCHORS = (
    "btr", "townhome", "multifamily", "sfr", "capital markets",
    "charlotte", "raleigh", "atlanta", "nashville", "dallas",
    "houston", "austin", "phoenix", "tampa", "denver", "miami",
    "texas", "sunbelt", "expansion", "hiring", "raise",
)

ACCEPT_THRESHOLD = 0.62
REJECT_THRESHOLD = 0.40


def _score_naturalness(
    body: str,
    naturalness_verdict: Optional[dict] = None,
) -> float:
    body = body or ""
    lo = body.lower()
    if not lo.strip():
        return 0.0
    score = 0.85
    if any(t in lo for t in _TEMPLATE_MARKERS):
        score -= 0.4
    if any(t in lo for t in _VENDOR):
        score -= 0.35
    # Excessive punctuation / all-caps is robotic.
    if body.count("!") >= 2:
        score -= 0.1
    if re.search(r"\b[A-Z]{5,}\b", body):
        score -= 0.1
    # Over-long sentences feel more like prose than a DM.
    sentences = re.split(r"[.!?]\s", body)
    if sentences and max(len(s.split()) for s in sentences) > 40:
        score -= 0.15
    # Merge in the naturalness validator verdict if it was attached
    # during candidate_validation. This gives us a single combined
    # score that reflects both the "human DM" heuristics above and
    # the hard signals (comma-stacks, profile-summary prose) the
    # naturalness_validator catches.
    if naturalness_verdict:
        validator_score = float(
            naturalness_verdict.get("naturalness_score") or 0.0
        )
        # Average the two — the validator is the authority on
        # comma-stacks but the critic-side heuristics catch some
        # template-opener patterns the validator ignores.
        score = 0.5 * score + 0.5 * validator_score
        # A single comma-stack violation dominates everything —
        # the message can't be natural if it's literally a keyword
        # list. Clamp the score to reflect that.
        if not naturalness_verdict.get("passes_naturalness", True):
            score = min(score, 0.35)
    return max(0.0, min(1.0, score))


def _score_insightfulness(body: str, insights_available: int) -> float:
    body = body or ""
    lo = body.lower()
    if not lo.strip():
        return 0.0
    score = 0.25
    # POV markers — these hint the message carries an actual claim.
    if re.search(r"\b(my read is|i'd guess|my guess|i think|curious if|tell me i'm wrong)\b", lo):
        score += 0.35
    if re.search(r"\b(pattern|usually|tends to|second[- ]order|trade[- ]off|timing window)\b", lo):
        score += 0.25
    if re.search(r"\b(quarter|cycle|next few|right now|this year)\b", lo):
        score += 0.1
    # Scale by whether we actually produced insights to draw on.
    if insights_available:
        score += 0.1
    return max(0.0, min(1.0, score))


def _score_specificity(
    body: str,
    facts_used: list[str],
    signal_ids: list[str],
    notes_used: list[str],
    profile_fields_used: list[str],
) -> float:
    body_lo = (body or "").lower()
    score = 0.0
    if signal_ids:
        score += 0.4
    if notes_used:
        score += 0.25
    if profile_fields_used:
        score += 0.15
    if any(a in body_lo for a in _CONCRETE_ANCHORS):
        score += 0.15
    # Penalize if it only references weak facts.
    if not (signal_ids or notes_used or profile_fields_used) and facts_used:
        score -= 0.2
    return max(0.0, min(1.0, score))


def _score_pressure(body: str) -> float:
    """Return a *penalty* in [0,1]. Higher = more pressure = worse."""
    lo = (body or "").lower()
    score = 0.0
    for p in _PUSHY:
        if p in lo:
            score += 0.25
    if "book" in lo and "time" in lo:
        score += 0.15
    if "demo" in lo:
        score += 0.2
    if re.search(r"\?\s*$", body or ""):
        # A single trailing question mark is *good* — invites reply.
        score -= 0.05
    return max(0.0, min(1.0, score))


def _score_peer_credibility(body: str, facts_used: list[str]) -> float:
    lo = (body or "").lower()
    score = 0.6
    if any(v in lo for v in _VENDOR):
        score -= 0.4
    if re.search(r"\b(i've spent time|same trade[- ]off|seen this before|happy to compare notes)\b", lo):
        score += 0.25
    if any(a in lo for a in _CONCRETE_ANCHORS):
        score += 0.1
    return max(0.0, min(1.0, score))


def _score_genericity(
    body: str,
    anti_generic_verdict: dict,
    confidence_level: str = "high",
) -> float:
    """Pull from the existing anti-generic verdict so the two layers agree.

    At HIGH confidence we bump genericity if the anti-generic
    specificity signals didn't fire ("could be sent to 200 people"
    penalty). At MEDIUM we bump it less. At LOW confidence we skip
    the bump entirely — a broad pattern-based message is expected
    and shouldn't be double-penalized for not anchoring on a
    specific signal that never existed.
    """
    score = float(anti_generic_verdict.get("genericity_score") or 0.0)
    specificity = float(anti_generic_verdict.get("specificity_score") or 0.0)
    if specificity < 0.4:
        if confidence_level == "high":
            score = min(1.0, score + 0.2)
        elif confidence_level == "medium":
            score = min(1.0, score + 0.1)
        # low: no bump
    return max(0.0, min(1.0, score))


def _verdict_from_scores(
    overall: float,
    hard_fail: bool,
    confidence_level: str = "high",
) -> str:
    if hard_fail:
        return "reject"
    # Slide the accept/reject thresholds for low-confidence runs so
    # thoughtful pattern-based messages don't get rejected purely on
    # their lower baseline specificity score.
    if confidence_level == "low":
        accept = 0.45
        reject_below = 0.25
    elif confidence_level == "medium":
        accept = 0.55
        reject_below = 0.32
    else:
        accept = ACCEPT_THRESHOLD
        reject_below = REJECT_THRESHOLD
    if overall >= accept:
        return "accept"
    if overall >= reject_below:
        return "rewrite"
    return "reject"


def critique_candidate(
    candidate: dict,
    context: dict,
    insights: Optional[list[dict]] = None,
    provider: Optional[Any] = None,
) -> dict:
    """Score a single candidate. Never raises.

    This always runs the deterministic path. If ``provider`` exposes a
    ``critique_candidate`` method, its output is merged into the final
    scores (averaged 50/50 per axis).
    """
    body = candidate.get("body") or ""
    facts_used = candidate.get("facts_used") or []
    signal_ids = candidate.get("signal_ids") or []
    notes_used = candidate.get("notes_used") or []
    profile_fields_used = candidate.get("profile_fields_used") or []
    grounding_verdict = candidate.get("grounding") or {}
    anti_copy_verdict = candidate.get("anti_copy") or {}
    anti_generic_verdict = candidate.get("anti_generic") or {}
    naturalness_verdict = candidate.get("naturalness") or {}

    # Read the confidence level off the anti-generic verdict (which is
    # written by the confidence-aware anti_generic_validator). Fall back
    # to deriving from the candidate's own ``low_context`` flag or the
    # context's ``input_quality`` if the verdict hasn't been attached
    # yet (e.g. rewrite tests).
    confidence_level = (
        (anti_generic_verdict.get("confidence_level") or "").lower()
        or (
            (context.get("input_quality") or {}).get("confidence_level") or ""
        ).lower()
    )
    if not confidence_level:
        confidence_level = "low" if candidate.get("low_context") else "high"

    specificity = _score_specificity(
        body, facts_used, signal_ids, notes_used, profile_fields_used,
    )
    naturalness = _score_naturalness(body, naturalness_verdict)
    insightfulness = _score_insightfulness(body, len(insights or []))
    genericity = _score_genericity(body, anti_generic_verdict, confidence_level)
    pressure = _score_pressure(body)
    peer_cred = _score_peer_credibility(body, facts_used)

    anti_copy = 1.0 if anti_copy_verdict.get("passes_anti_copy_check", True) else 0.0
    grounding = float(grounding_verdict.get("score") or 0.5)

    # Hard-fail conditions — no matter the score, we reject these.
    # The specificity floor moves with the confidence level: on low
    # confidence a broad but thoughtful message is acceptable; on high
    # confidence it isn't, because real signals were available.
    if confidence_level == "high":
        specificity_floor = 0.15
        genericity_ceiling = 0.7
    elif confidence_level == "medium":
        specificity_floor = 0.08
        genericity_ceiling = 0.8
    else:
        # Low confidence: we don't hard-fail on low specificity.
        # ``anti_copy`` + grounding + pressure still apply.
        specificity_floor = 0.0
        genericity_ceiling = 0.9

    # A comma-stack or keyword-stack naturalness violation is always
    # a hard fail, at every confidence level. The generator was told
    # explicitly to write from an internal thought, not from profile
    # keywords — a failure here means the last-mile translation
    # didn't hold and the message needs to be rejected.
    has_comma_stack = any(
        v.startswith("comma_stack:") or v.startswith("keyword_stacking:")
        for v in (naturalness_verdict.get("violations") or [])
    )

    hard_fail = bool(
        (anti_copy_verdict.get("violations") or [])
        or (grounding_verdict.get("violations") or [])
        or genericity >= genericity_ceiling
        or specificity < specificity_floor
        or pressure >= 0.6
        or has_comma_stack
    )

    # Weighted composite. Weights favor specificity + naturalness +
    # insightfulness since those are the axes most correlated with
    # "would a sharp human actually send this".
    overall = (
        0.28 * specificity
        + 0.18 * naturalness
        + 0.20 * insightfulness
        + 0.14 * peer_cred
        + 0.10 * anti_copy
        + 0.10 * grounding
        - 0.15 * genericity
        - 0.10 * pressure
    )
    overall = max(0.0, min(1.0, overall))

    notes: list[str] = []
    if specificity < 0.4:
        notes.append("low_specificity")
    if naturalness < 0.5:
        notes.append("unnatural_phrasing")
    if insightfulness < 0.3:
        notes.append("no_point_of_view")
    if genericity >= 0.5:
        notes.append("generic")
    if pressure >= 0.4:
        notes.append("pushy")
    if peer_cred < 0.4:
        notes.append("vendor_tone")
    if has_comma_stack:
        notes.append("comma_stack_or_keyword_summary")

    deterministic = {
        "scores": {
            "specificity": round(specificity, 3),
            "naturalness": round(naturalness, 3),
            "insightfulness": round(insightfulness, 3),
            "genericity": round(genericity, 3),
            "pressure_level": round(pressure, 3),
            "anti_copy": round(anti_copy, 3),
            "peer_credibility": round(peer_cred, 3),
            "grounding": round(grounding, 3),
        },
        "overall_score": round(overall, 3),
        "verdict": _verdict_from_scores(overall, hard_fail, confidence_level),
        "hard_fail": hard_fail,
        "confidence_level": confidence_level,
        "notes": notes,
        "source": "heuristic",
    }

    # AI-augmented path. The AI provider may return a small dict with
    # the same shape. We only *average* the scores — we never let the
    # AI skip a hard fail.
    if provider is not None and callable(getattr(provider, "critique_candidate", None)):
        try:
            ai_out = provider.critique_candidate(candidate, context, insights)
        except Exception as e:
            print(
                f"[SignalStack] message_critic: provider critique FAILED — "
                f"using deterministic: {type(e).__name__}: {e}"
            )
            ai_out = None
        if isinstance(ai_out, dict) and ai_out.get("scores"):
            ai_scores = ai_out.get("scores") or {}
            merged_scores = {}
            for k, v in deterministic["scores"].items():
                ai_v = ai_scores.get(k)
                if isinstance(ai_v, (int, float)):
                    merged_scores[k] = round(0.5 * v + 0.5 * float(ai_v), 3)
                else:
                    merged_scores[k] = v
            merged_overall = round(
                0.5 * deterministic["overall_score"]
                + 0.5 * float(ai_out.get("overall_score", deterministic["overall_score"])),
                3,
            )
            merged_notes = (
                deterministic["notes"]
                + [n for n in (ai_out.get("notes") or []) if isinstance(n, str)]
            )
            return {
                "scores": merged_scores,
                "overall_score": merged_overall,
                "verdict": _verdict_from_scores(
                    merged_overall, hard_fail, confidence_level,
                ),
                "hard_fail": hard_fail,
                "confidence_level": confidence_level,
                "notes": merged_notes,
                "source": "hybrid",
            }

    return deterministic


def critique_all(
    candidates: list[dict],
    context: dict,
    insights: Optional[list[dict]] = None,
    provider: Optional[Any] = None,
) -> list[dict]:
    """Apply the critic to every candidate. Annotates each in place."""
    out: list[dict] = []
    for c in candidates or []:
        verdict = critique_candidate(c, context, insights=insights, provider=provider)
        c["critique"] = verdict
        out.append(c)
    return out
