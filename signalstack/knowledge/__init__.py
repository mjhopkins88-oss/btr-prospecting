"""
SignalStack knowledge dataset layer.

A central place for reusable messaging knowledge — videos, articles,
notes, podcasts, playbooks, frameworks, transcripts. Sources hold the
raw material; entries hold the structured strategy/style/angle facts
the generator can consult.

Public surface:
    repo  — CRUD over sources / entries / tags
    extractor — turn raw_text/summary/notes into structured entries
"""
from . import repo  # noqa: F401
from . import extractor  # noqa: F401
