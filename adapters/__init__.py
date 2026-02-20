"""Discovery source adapters — EDGAR, press releases, permits."""
from adapters.base import BaseAdapter
from adapters.edgar import EDGARAdapter
from adapters.press_release import PressReleaseAdapter
from adapters.permit import PermitAdapter

__all__ = ['BaseAdapter', 'EDGARAdapter', 'PressReleaseAdapter', 'PermitAdapter']
