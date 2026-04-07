"""
SignalStack Flask blueprint — JSON API + a single SPA shell page.

Mounted by app.py via:
    from signalstack import bp as signalstack_bp, init_schema
    app.register_blueprint(signalstack_bp)
    init_schema()

All API endpoints live under /api/signalstack/*. The UI is served at
/signalstack and is a single static HTML file (static/signalstack/index.html)
that calls the JSON API. This keeps the integration zero-impact on the
existing Flask app while still giving us a usable workspace.

NOTE: This module intentionally does NOT depend on app.py's @require_auth
decorator (to keep the module decoupled). If you want auth-protected
routes, wrap the blueprint in app.py at registration time, or import
require_auth here. Comments below mark the integration point.
"""
import os
from flask import Blueprint, request, jsonify, send_from_directory

from . import repo
from .services import generator, analytics
from .types import (
    PROSPECT_STATUS, SIGNAL_TYPES, SIGNAL_SOURCES, MESSAGE_TYPES,
    PRIMARY_TRIGGERS, COMMUNICATION_STYLES, OUTREACH_GOALS,
    MESSAGE_STATUS, MESSAGE_OUTCOMES,
)

bp = Blueprint("signalstack", __name__)

_STATIC_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "static", "signalstack",
)


def _json_body() -> dict:
    return request.get_json(silent=True) or {}


# ===================== UI =====================

@bp.route("/signalstack", strict_slashes=False)
@bp.route("/signalstack/<path:_subpath>")
def signalstack_ui(_subpath: str = ""):
    """Serve the SPA shell. Client-side handles routing."""
    return send_from_directory(_STATIC_DIR, "index.html")


# ===================== Meta =====================

@bp.route("/api/signalstack/meta", methods=["GET"])
def meta():
    return jsonify({
        "prospect_status": PROSPECT_STATUS,
        "signal_types": SIGNAL_TYPES,
        "signal_sources": SIGNAL_SOURCES,
        "message_types": MESSAGE_TYPES,
        "primary_triggers": PRIMARY_TRIGGERS,
        "communication_styles": COMMUNICATION_STYLES,
        "outreach_goals": OUTREACH_GOALS,
        "message_status": MESSAGE_STATUS,
        "message_outcomes": MESSAGE_OUTCOMES,
    })


# ===================== Prospects =====================

@bp.route("/api/signalstack/prospects", methods=["GET"])
def list_prospects():
    return jsonify(repo.list_prospects(
        q=request.args.get("q", ""),
        status=request.args.get("status", ""),
    ))


@bp.route("/api/signalstack/prospects", methods=["POST"])
def create_prospect():
    data = _json_body()
    if not data.get("full_name"):
        return jsonify({"error": "full_name required"}), 400
    try:
        return jsonify(repo.create_prospect(data)), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@bp.route("/api/signalstack/prospects/<pid>", methods=["GET"])
def get_prospect(pid):
    p = repo.get_prospect(pid)
    if not p:
        return jsonify({"error": "not_found"}), 404
    p["signals"] = repo.list_signals_for_prospect(pid)
    p["messages"] = repo.list_messages(prospect_id=pid)
    if p.get("company_id"):
        p["company"] = repo.get_company(p["company_id"])
    return jsonify(p)


@bp.route("/api/signalstack/prospects/<pid>", methods=["PATCH"])
def patch_prospect(pid):
    try:
        return jsonify(repo.update_prospect(pid, _json_body()))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


# ===================== Companies =====================

@bp.route("/api/signalstack/companies", methods=["GET"])
def list_companies():
    return jsonify(repo.list_companies(q=request.args.get("q", "")))


@bp.route("/api/signalstack/companies", methods=["POST"])
def create_company():
    data = _json_body()
    if not data.get("name"):
        return jsonify({"error": "name required"}), 400
    return jsonify(repo.create_company(data)), 201


@bp.route("/api/signalstack/companies/<cid>", methods=["GET"])
def get_company(cid):
    c = repo.get_company(cid)
    if not c:
        return jsonify({"error": "not_found"}), 404
    c["signals"] = repo.list_signals_for_company(cid)
    c["prospects"] = repo.list_prospects_for_company(cid)
    return jsonify(c)


@bp.route("/api/signalstack/companies/<cid>", methods=["PATCH"])
def patch_company(cid):
    return jsonify(repo.update_company(cid, _json_body()))


# ===================== Signals =====================

@bp.route("/api/signalstack/signals", methods=["POST"])
def create_signal():
    data = _json_body()
    if not data.get("text") or not data.get("type") or not data.get("source"):
        return jsonify({"error": "type, source, text required"}), 400
    if not data.get("prospect_id") and not data.get("company_id"):
        return jsonify({"error": "prospect_id or company_id required"}), 400
    try:
        return jsonify(repo.create_signal(data)), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


# ===================== Generation =====================

@bp.route("/api/signalstack/generate", methods=["POST"])
def generate_messages():
    data = _json_body()
    pid = data.get("prospect_id")
    if not pid:
        return jsonify({"error": "prospect_id required"}), 400
    try:
        n = int(data.get("n", 4))
    except (TypeError, ValueError):
        n = 4
    try:
        result = generator.generate(
            pid,
            n=n,
            instruction=data.get("instruction"),
            strategy_override=data.get("strategy"),
            profile_override=data.get("profile"),
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "error": "generator_crashed",
            "message": f"Generator crashed: {e}",
            "candidates": [],
            "rejected": [],
        }), 200
    try:
        return jsonify(result)
    except Exception as e:
        # Last-ditch: strip non-serializable context and try again.
        import traceback
        traceback.print_exc()
        safe = {
            "error": "serialization_failed",
            "message": f"Could not serialize generator result: {e}",
            "candidates": result.get("candidates", []) if isinstance(result, dict) else [],
            "rejected": result.get("rejected", []) if isinstance(result, dict) else [],
        }
        return jsonify(safe), 200


# ===================== Profile Context =====================

@bp.route("/api/signalstack/prospects/<pid>/profile", methods=["GET"])
def get_profile(pid):
    return jsonify(repo.get_profile_context(pid) or {})


@bp.route("/api/signalstack/prospects/<pid>/profile", methods=["PUT"])
def upsert_profile(pid):
    data = _json_body()
    return jsonify(repo.upsert_profile_context(pid, data))


# ===================== Notes =====================

@bp.route("/api/signalstack/notes", methods=["POST"])
def create_note():
    data = _json_body()
    if not data.get("body"):
        return jsonify({"error": "body required"}), 400
    if not data.get("prospect_id") and not data.get("company_id"):
        return jsonify({"error": "prospect_id or company_id required"}), 400
    return jsonify(repo.create_note(data)), 201


# ===================== Social-selling principles =====================

@bp.route("/api/signalstack/principles", methods=["GET"])
def list_principles():
    return jsonify(repo.list_principles(active_only=True))


@bp.route("/api/signalstack/principles", methods=["POST"])
def create_principle():
    data = _json_body()
    for f in ("category", "principle_name", "description"):
        if not data.get(f):
            return jsonify({"error": f"{f} required"}), 400
    return jsonify(repo.create_principle(data)), 201


# ===================== Demo seed =====================

@bp.route("/api/signalstack/seed-demo", methods=["POST"])
def seed_demo():
    from .seed import seed_demo as _seed
    return jsonify(_seed())


@bp.route("/api/signalstack/messages", methods=["GET"])
def list_messages():
    return jsonify(repo.list_messages(
        prospect_id=request.args.get("prospect_id", ""),
        status=request.args.get("status", ""),
    ))


@bp.route("/api/signalstack/messages", methods=["POST"])
def save_message():
    data = _json_body()
    pid = data.get("prospect_id")
    if not pid:
        return jsonify({"error": "prospect_id required"}), 400
    return jsonify(generator.save_draft(pid, data)), 201


@bp.route("/api/signalstack/messages/<mid>", methods=["PATCH"])
def patch_message(mid):
    try:
        return jsonify(repo.update_message(mid, _json_body()))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@bp.route("/api/signalstack/messages/<mid>/outcome", methods=["POST"])
def add_outcome(mid):
    data = _json_body()
    try:
        return jsonify(repo.record_outcome(mid, data["outcome"], data.get("notes", ""))), 201
    except (KeyError, ValueError) as e:
        return jsonify({"error": str(e)}), 400


# ===================== Analytics =====================

@bp.route("/api/signalstack/analytics", methods=["GET"])
def get_analytics():
    return jsonify(analytics.overview())
