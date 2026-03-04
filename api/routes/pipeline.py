"""
API Routes: Pipeline Control
Flask Blueprint for triggering and monitoring the lead intelligence pipeline.
"""
from flask import Blueprint, request, jsonify
import threading

from shared.database import fetch_all, fetch_one
from shared.queue import enqueue

pipeline_bp = Blueprint('pipeline', __name__, url_prefix='/api/li')

_pipeline_running = False


@pipeline_bp.route('/pipeline/run', methods=['POST'])
def trigger_pipeline():
    """Trigger a full pipeline run (async)."""
    global _pipeline_running
    if _pipeline_running:
        return jsonify({'error': 'Pipeline already running'}), 409

    from workers.pipeline import run_full_pipeline

    def _run():
        global _pipeline_running
        _pipeline_running = True
        try:
            run_full_pipeline()
        finally:
            _pipeline_running = False

    enqueue(_run, job_timeout=1800)
    return jsonify({'ok': True, 'message': 'Pipeline started'})


@pipeline_bp.route('/pipeline/stage/<stage>', methods=['POST'])
def trigger_stage(stage):
    """Trigger a specific pipeline stage."""
    from workers import pipeline

    stage_map = {
        'collect': pipeline.run_collection,
        'normalize': pipeline.run_normalization,
        'resolve': pipeline.run_entity_resolution,
        'enrich': pipeline.run_enrichment,
        'score': pipeline.run_scoring,
        'route': pipeline.run_routing,
        'brief': pipeline.run_brief,
        'learn': pipeline.run_learning,
    }

    func = stage_map.get(stage)
    if not func:
        return jsonify({'error': f'Unknown stage: {stage}', 'valid_stages': list(stage_map.keys())}), 400

    enqueue(func, job_timeout=900)
    return jsonify({'ok': True, 'stage': stage, 'message': f'Stage {stage} started'})


@pipeline_bp.route('/pipeline/status', methods=['GET'])
def pipeline_status():
    """Get pipeline status overview."""
    status = {
        'running': _pipeline_running,
        'entities': {
            'projects': fetch_one("SELECT COUNT(*) as count FROM li_projects"),
            'companies': fetch_one("SELECT COUNT(*) as count FROM li_companies"),
            'contacts': fetch_one("SELECT COUNT(*) as count FROM li_contacts"),
            'signals': fetch_one("SELECT COUNT(*) as count FROM li_signals"),
            'signals_normalized': fetch_one("SELECT COUNT(*) as count FROM li_signals WHERE normalized = 1"),
            'leads': fetch_one("SELECT COUNT(*) as count FROM li_leads"),
            'outcomes': fetch_one("SELECT COUNT(*) as count FROM li_outcomes"),
        },
    }
    return jsonify(status)


@pipeline_bp.route('/brief/latest', methods=['GET'])
def latest_brief():
    """Get the most recent daily brief."""
    row = fetch_one(
        "SELECT body FROM li_signals WHERE source_type = 'system' AND signal_type = 'brief' "
        "ORDER BY created_at DESC LIMIT 1"
    )
    if not row or not row.get('body'):
        return jsonify({'error': 'No brief available'}), 404

    import json
    try:
        brief = json.loads(row['body'])
        return jsonify(brief)
    except Exception:
        return jsonify({'error': 'Brief data corrupted'}), 500
