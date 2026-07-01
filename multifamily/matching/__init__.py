"""
Lead matching + merge for real multifamily leads.

Public API:
    classify(incoming, existing_leads) -> {'auto': MatchCandidate|None, 'review': [...]}
    merge_incoming_on_intake(survivor, incoming) -> survivor   (auto-merge path)
    merge_existing(survivor_id, loser_id) -> survivor          (confirmed/manual merge)
"""
from multifamily.matching.match_engine import classify, MatchCandidate, FUZZY_COMPANY_THRESHOLD
from multifamily.matching.merge_engine import (
    apply_merge, merge_incoming_on_intake, merge_existing,
)
from multifamily.matching import identity_keys

__all__ = [
    'classify', 'MatchCandidate', 'FUZZY_COMPANY_THRESHOLD',
    'apply_merge', 'merge_incoming_on_intake', 'merge_existing', 'identity_keys',
]
