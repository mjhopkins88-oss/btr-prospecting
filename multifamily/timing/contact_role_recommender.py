"""
Recommend which contact role(s) to target for a lead, based on its
process stage. Pure lookup over process_stage_types.CONTACT_ROLES with a
safe fallback.
"""
from typing import List

from multifamily.timing.process_stage_types import CONTACT_ROLES


def recommend_contact_roles(process_stage: str) -> List[str]:
    return list(CONTACT_ROLES.get(process_stage, ['Owner / Principal', 'Risk Manager']))
