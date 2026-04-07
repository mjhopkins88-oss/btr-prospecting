"""
SignalStack — LinkedIn-specific sales intelligence and messaging engine.

This is a self-contained Flask module that plugs into the existing
btr-prospecting Flask app. All SignalStack-specific code lives here.

Public entry point: `signalstack.routes.bp` (Flask Blueprint).
Call `signalstack.schema.init_schema()` once at app startup to create tables.
"""
from .routes import bp  # noqa: F401
from .schema import init_schema  # noqa: F401
