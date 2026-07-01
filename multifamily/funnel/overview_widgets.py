"""
Overview funnel widgets (Funnel Phase 7) — pure aggregation for the
Overview's "MULTIFAMILY FUNNEL" section. No DB access, no scoring, no
side effects, same convention as funnel/urgency.py and
sales_intelligence/lead_context_builder.py: callers (api/routes/
multifamily.py) pass in whatever they already computed (the priority-
sorted lead list, the get_source_performance() rollup).
"""
from typing import Any, Dict, List, Optional

from multifamily.types import MultifamilyLead


def best_inbound_handraiser(leads: List[MultifamilyLead]) -> Optional[MultifamilyLead]:
    """The single best real lead who directly raised their hand through
    a public offer-page form submission (any variant — benchmark or any
    of the funnel's other offer pages, since every one of them posts
    with source='benchmark_form'). `leads` is expected to already be
    priority-sorted (pipeline.sort_leads_by_priority), so this is just
    the first match."""
    return next((l for l in leads if l.primary_source == 'benchmark_form' and not l.is_demo), None)


def build_funnel_widgets(
    source_performance: Dict[str, Any], campaign_performance: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Aggregate widgets derived purely from get_source_performance()'s
    existing rollups (Funnel Phase 6): new forms captured per offer
    page, the top-performing offer page, SERP triggers still awaiting
    manual review, and outbound-link conversion counts. Does NOT
    include best_inbound_handraiser — that needs the live lead list,
    not just the aggregate rollup, so callers attach it separately.

    `campaign_performance` (Campaign Phase 5, from
    repository.get_campaign_performance()) is optional and additive —
    a pipeline with zero campaigns yet still returns a complete,
    zero-valued campaign section rather than omitting it."""
    page_variant_counts = {
        k: v for k, v in (source_performance.get('leads_by_page_variant') or {}).items() if k != 'none'
    }
    top_offer_page = max(page_variant_counts.items(), key=lambda kv: kv[1])[0] if page_variant_counts else None
    outbound_stats = source_performance.get('outbound_conversion_stats') or {}
    serp_stats = source_performance.get('serp') or {}
    cp = campaign_performance or {}
    return {
        'new_forms_by_offer': page_variant_counts,
        'top_offer_page': top_offer_page,
        'serp_triggers_needing_review': serp_stats.get('review_candidates_pending', 0),
        'converted_from_outbound': outbound_stats.get('total_links_converted', 0),
        'outbound_links_sent': outbound_stats.get('total_links_sent', 0),
        # Campaign Phase 5 additions — Pilot Campaign Control Center.
        'active_campaigns': cp.get('total_active_campaigns', 0),
        'campaign_conversions': cp.get('total_converted', 0),
        'campaign_targets_needing_followup': cp.get('targets_needing_followup', 0),
        'best_campaign': cp.get('best_campaign'),
        'best_performing_offer_page': cp.get('best_offer_page'),
        'recently_converted_campaign_target': cp.get('recently_converted'),
    }
