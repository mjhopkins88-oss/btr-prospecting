"""
Multifamily Command — multifamily insurance lead intelligence module.

Kept entirely separate from the BTR (Build-to-Rent) lead intelligence
platform (`li_*` tables, `api/routes/leads.py`, `api/routes/sales_leads.py`).
Multifamily leads must never be merged into the BTR queue.

Scope (v1): California and Texas. Inbound lead delivery first, then
website intent, renewal opportunities, acquisition/financing triggers,
and construction triggers.
"""
