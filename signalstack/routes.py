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
from .knowledge import repo as knowledge_repo, extractor as knowledge_extractor
from .serialization import to_json_safe, describe_unsafe
from .types import (
    PROSPECT_STATUS, SIGNAL_TYPES, SIGNAL_SOURCES, MESSAGE_TYPES,
    PRIMARY_TRIGGERS, COMMUNICATION_STYLES, OUTREACH_GOALS,
    MESSAGE_STATUS, MESSAGE_OUTCOMES,
    KNOWLEDGE_SOURCE_TYPES, KNOWLEDGE_EXTRACTION_STATUS,
    KNOWLEDGE_ENTRY_CATEGORIES,
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
        "knowledge_source_types": KNOWLEDGE_SOURCE_TYPES,
        "knowledge_extraction_status": KNOWLEDGE_EXTRACTION_STATUS,
        "knowledge_entry_categories": KNOWLEDGE_ENTRY_CATEGORIES,
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
        return jsonify(to_json_safe({
            "ok": False,
            "error": "generator_crashed",
            "message": f"Generator crashed: {e}",
            "stage": "generator",
            "candidates": [],
            "rejected": [],
        })), 200

    # Primary path: sanitize the full result before handing it to Flask.
    # ``to_json_safe`` walks the response recursively and converts any
    # Postgres-derived datetime/Decimal/memoryview/etc values into JSON
    # primitives, so ``jsonify`` cannot explode on nested candidate
    # metadata (playbook_entries_used, knowledge_entries_used, grounding,
    # anti_copy, anti_generic, strongest_observation_used, ...).
    try:
        safe_result = to_json_safe(result)
        return jsonify(safe_result)
    except Exception as e:
        import traceback
        traceback.print_exc()
        try:
            offenders = describe_unsafe(result)[:20]
            print(f"[SignalStack] unsafe fields in generator result: {offenders}")
        except Exception:
            pass
        # Fallback path: build a minimal, independently-sanitized error
        # payload. We deliberately do NOT carry over the original
        # candidates — they are the most likely source of the original
        # failure and would re-poison the fallback response.
        minimal = {
            "ok": False,
            "error": "serialization_failed",
            "message": f"Could not serialize generator result: {e}",
            "stage": "response_serialization",
            "candidates": [],
            "rejected": [],
        }
        try:
            return jsonify(to_json_safe(minimal)), 200
        except Exception as final_err:
            # Absolute last resort: hand-built dict of strings only. This
            # cannot fail because every value is already a str/bool.
            traceback.print_exc()
            return jsonify({
                "ok": False,
                "error": "serialization_failed",
                "message": str(final_err),
                "stage": "response_serialization_fallback",
                "candidates": [],
                "rejected": [],
            }), 200


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


# ===================== Knowledge dataset =====================

def _parse_tags(value) -> list:
    """Accept tags as list or comma-separated string."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(t).strip() for t in value if str(t).strip()]
    if isinstance(value, str):
        return [t.strip() for t in value.split(",") if t.strip()]
    return []


def _parse_active(value):
    if value in (None, "", "all"):
        return None
    if isinstance(value, bool):
        return value
    return str(value).lower() in ("1", "true", "yes", "on", "active")


@bp.route("/api/signalstack/knowledge/stats", methods=["GET"])
def knowledge_stats():
    return jsonify(knowledge_repo.overview_stats())


@bp.route("/api/signalstack/knowledge/sources", methods=["GET"])
def list_knowledge_sources():
    return jsonify(knowledge_repo.list_sources(
        q=request.args.get("q", ""),
        source_type=request.args.get("source_type", ""),
        active=_parse_active(request.args.get("active")),
        extraction_status=request.args.get("extraction_status", ""),
        tag=request.args.get("tag", ""),
    ))


@bp.route("/api/signalstack/knowledge/sources", methods=["POST"])
def create_knowledge_source():
    data = _json_body()
    if not data.get("title"):
        return jsonify({"error": "title required"}), 400
    if not data.get("source_type"):
        data["source_type"] = "manual_entry"
    data["tags"] = _parse_tags(data.get("tags"))
    extract = bool(data.pop("extract_after_save", False))
    try:
        source = knowledge_repo.create_source(data)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if extract:
        try:
            result = knowledge_extractor.extract_for_source(source["id"])
            source = knowledge_repo.get_source(source["id"]) or source
            source["extraction_result"] = result
        except Exception as e:
            print(f"[SignalStack] knowledge extract on create failed: {e}")
            source["extraction_result"] = {"error": "extract_failed", "message": str(e)}
    return jsonify(source), 201


@bp.route("/api/signalstack/knowledge/sources/<sid>", methods=["GET"])
def get_knowledge_source(sid):
    source = knowledge_repo.get_source(sid)
    if not source:
        return jsonify({"error": "not_found"}), 404
    source["entries"] = knowledge_repo.list_entries(source_id=sid)
    return jsonify(source)


@bp.route("/api/signalstack/knowledge/sources/<sid>", methods=["PATCH"])
def update_knowledge_source(sid):
    data = _json_body()
    if "tags" in data:
        data["tags"] = _parse_tags(data.get("tags"))
    try:
        source = knowledge_repo.update_source(sid, data)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if not source:
        return jsonify({"error": "not_found"}), 404
    return jsonify(source)


@bp.route("/api/signalstack/knowledge/sources/<sid>/archive", methods=["POST"])
def archive_knowledge_source(sid):
    source = knowledge_repo.archive_source(sid)
    if not source:
        return jsonify({"error": "not_found"}), 404
    return jsonify(source)


@bp.route("/api/signalstack/knowledge/sources/<sid>/extract", methods=["POST"])
def extract_knowledge_source(sid):
    try:
        result = knowledge_extractor.extract_for_source(sid)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": "extract_failed", "message": str(e)}), 200
    if result.get("error"):
        return jsonify(result), 404 if result["error"] == "source_not_found" else 200
    return jsonify(result)


@bp.route("/api/signalstack/knowledge/sources/<sid>/entries", methods=["GET"])
def list_knowledge_entries_for_source(sid):
    return jsonify(knowledge_repo.list_entries(source_id=sid))


@bp.route("/api/signalstack/knowledge/entries", methods=["GET"])
def list_knowledge_entries():
    return jsonify(knowledge_repo.list_entries(
        source_id=request.args.get("source_id", ""),
        active=_parse_active(request.args.get("active")),
        category=request.args.get("category", ""),
    ))


@bp.route("/api/signalstack/knowledge/entries", methods=["POST"])
def create_knowledge_entry():
    data = _json_body()
    for f in ("source_id", "category", "principle_name", "description"):
        if not data.get(f):
            return jsonify({"error": f"{f} required"}), 400
    if "tags" in data:
        data["tags"] = _parse_tags(data.get("tags"))
    return jsonify(knowledge_repo.create_entry(data)), 201


@bp.route("/api/signalstack/knowledge/entries/<eid>", methods=["PATCH"])
def update_knowledge_entry(eid):
    data = _json_body()
    if "tags" in data:
        data["tags"] = _parse_tags(data.get("tags"))
    entry = knowledge_repo.update_entry(eid, data)
    if not entry:
        return jsonify({"error": "not_found"}), 404
    return jsonify(entry)


@bp.route("/api/signalstack/knowledge/entries/<eid>", methods=["DELETE"])
def delete_knowledge_entry(eid):
    ok = knowledge_repo.delete_entry(eid)
    return jsonify({"ok": ok}), (200 if ok else 404)


@bp.route("/api/signalstack/knowledge/tags", methods=["GET"])
def list_knowledge_tags():
    return jsonify(knowledge_repo.list_tags())


@bp.route("/api/signalstack/knowledge/playbooks", methods=["GET"])
def list_knowledge_playbooks():
    """List all industry playbooks with entry counts and categories."""
    try:
        books = repo.list_playbooks()
    except Exception as e:
        print(f"[SignalStack] list_playbooks failed: {e}")
        return jsonify([])
    out = []
    for pb in books:
        try:
            entries = repo.list_playbook_entries(playbook_id=pb["id"])
        except Exception:
            entries = []
        cats = sorted({e.get("category") for e in entries if e.get("category")})
        out.append({
            **pb,
            "entry_count": len(entries),
            "categories": cats,
        })
    return jsonify(out)


@bp.route("/api/signalstack/knowledge/playbooks/<pid>", methods=["GET"])
def get_knowledge_playbook(pid):
    """Return a single playbook with its full entry list."""
    try:
        books = repo.list_playbooks()
    except Exception as e:
        return jsonify({"error": "load_failed", "message": str(e)}), 500
    pb = next((b for b in books if b.get("id") == pid), None)
    if not pb:
        return jsonify({"error": "not_found"}), 404
    try:
        entries = repo.list_playbook_entries(playbook_id=pid)
    except Exception:
        entries = []
    pb["entries"] = entries
    pb["entry_count"] = len(entries)
    pb["categories"] = sorted({e.get("category") for e in entries if e.get("category")})
    return jsonify(pb)
