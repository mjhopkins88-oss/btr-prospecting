"""
API Routes: Daily BTR Intelligence Brief — PDF generation + download.
"""
from flask import Blueprint, request, jsonify, send_file
from shared.database import fetch_all, fetch_one
from datetime import datetime, timedelta
import io
import json
import logging
import os

logger = logging.getLogger('leo.pdf')

daily_brief_bp = Blueprint('daily_brief', __name__, url_prefix='/api/brief')

# ---------------------------------------------------------------------------
# Unicode font setup — DejaVu Sans for full Unicode support in PDFs
# ---------------------------------------------------------------------------

_PROJECT_FONT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'fonts'
)
_SYSTEM_FONT_DIR = '/usr/share/fonts/truetype/dejavu'

_FONT_REGULAR = None
_FONT_BOLD = None

for _dir in (_PROJECT_FONT_DIR, _SYSTEM_FONT_DIR):
    _r = os.path.join(_dir, 'DejaVuSans.ttf')
    _b = os.path.join(_dir, 'DejaVuSans-Bold.ttf')
    if os.path.exists(_r) and os.path.exists(_b):
        _FONT_REGULAR = _r
        _FONT_BOLD = _b
        break

UNICODE_FONTS_AVAILABLE = _FONT_REGULAR is not None


def _register_unicode_fonts(pdf):
    """Register DejaVu Unicode fonts on an FPDF instance. Returns font family name."""
    if UNICODE_FONTS_AVAILABLE:
        pdf.add_font('DejaVu', '', _FONT_REGULAR)
        pdf.add_font('DejaVu', 'B', _FONT_BOLD)
        pdf.add_font('DejaVu', 'I', _FONT_REGULAR)
        pdf.add_font('DejaVu', 'BI', _FONT_BOLD)
        return 'DejaVu'
    logger.warning("[PDF] DejaVu fonts not found, falling back to Helvetica (Latin-1 only)")
    return 'Helvetica'


def sanitize_text(text):
    """Normalize Unicode text for maximum PDF compatibility. Fallback sanitizer."""
    text = str(text)
    text = text.replace('—', ' - ').replace('–', '-')
    text = text.replace('‘', "'").replace('’', "'")
    text = text.replace('“', '"').replace('”', '"')
    text = text.replace('…', '...')
    text = text.replace(' ', ' ').replace('​', '')
    text = text.replace('•', '-')
    text = text.replace('→', '->').replace('←', '<-')
    text = text.replace('✓', '[x]').replace('✗', '[ ]')
    text = text.replace('·', '-')
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    return text


# ---------------------------------------------------------------------------
# Brief content generator
# ---------------------------------------------------------------------------

def _generate_brief_content():
    """
    Generate the full daily brief content with personalization from app data.
    Returns dict with all sections.
    """
    today = datetime.utcnow()
    date_str = today.strftime('%A, %B %d, %Y')

    brief = {
        'title': f'BTR Daily Brief — {date_str}',
        'date': date_str,
        'generated_at': today.isoformat(),
    }

    # --- Section 1: Market Snapshot (from real signals) ---
    market_points = []
    try:
        signals = fetch_all(
            "SELECT title, summary, importance FROM prospecting_signals "
            "ORDER BY detected_at DESC LIMIT 5", []
        )
        for s in (signals or []):
            point = f"[Signal {s.get('importance', '?')}/10] {s['title']}"
            if s.get('summary'):
                point += f" — {s['summary'][:120]}"
            market_points.append(point)
    except Exception as e:
        logger.warning(f"[Brief] Market snapshot query failed: {e}")
    if not market_points:
        market_points.append('No recent signals — run signal scan to populate market intelligence.')
    brief['market_snapshot'] = market_points

    # --- Section 2: BTR Intelligence (from pipeline data) ---
    btr_intel = []
    try:
        pipeline = fetch_all(
            """SELECT relationship_status, COUNT(*) as cnt, AVG(warmth_score) as avg_warmth
               FROM capital_groups
               WHERE relationship_status NOT IN ('dormant', 'lost', 'dead')
               GROUP BY relationship_status ORDER BY cnt DESC LIMIT 5""", []
        )
        for p in (pipeline or []):
            avg_w = round(p.get('avg_warmth', 0) or 0, 1)
            btr_intel.append(
                f"{p['relationship_status'].title()}: {p['cnt']} groups, avg warmth {avg_w}/10"
            )
    except Exception as e:
        logger.warning(f"[Brief] Pipeline query failed: {e}")
    if not btr_intel:
        btr_intel.append('Pipeline data not yet populated — add capital groups to see intelligence.')
    brief['btr_intelligence'] = btr_intel

    # --- Section 3: What This Means (dynamic from data) ---
    try:
        _pipe_rows = fetch_all(
            """SELECT COUNT(*) as cnt FROM capital_groups
               WHERE relationship_status NOT IN ('dormant', 'lost', 'dead')""", []
        )
        total_groups = _pipe_rows[0]['cnt'] if _pipe_rows else 0
    except Exception:
        total_groups = 0
    if total_groups > 0:
        interpretation = (
            f'Your pipeline has {total_groups} active groups. '
            f'Focus on advancing the highest-warmth relationships while maintaining '
            f'consistent touchpoints across the funnel. Check signals daily for outreach angles.'
        )
    else:
        interpretation = (
            'Build your pipeline by adding capital groups and contacts. '
            'Once populated, this section will surface data-driven market intelligence.'
        )
    brief['interpretation'] = interpretation

    # --- Section 4: Action Items (personalized if data available) ---
    actions = _build_action_items()
    brief['action_items'] = actions

    # --- Section 5: Daily Success Targets ---
    targets = _build_daily_targets()
    brief['daily_targets'] = targets

    # --- Section: What Changed (from Leo actions in last 24h) ---
    changes = []
    try:
        recent_actions = fetch_all(
            """SELECT action_type, description, created_at
               FROM leo_action_log
               WHERE created_at > datetime('now', '-24 hours')
               ORDER BY created_at DESC LIMIT 5""", []
        )
        for a in (recent_actions or []):
            changes.append(f"{a['action_type']}: {a['description']}")
    except Exception:
        logger.debug("What changed query failed", exc_info=True)
    if not changes:
        changes.append('No recent actions logged.')
    brief['what_changed'] = changes

    # --- Section 6: Learning Insight ---
    brief['learning_insight'] = {
        'title': 'The 3-Touch Rule',
        'content': (
            'Research shows that most B2B deals require at least 3 meaningful touchpoints before a prospect '
            'engages seriously. The key word is meaningful — a generic check-in does not count. '
            'Each touch should reference something specific: a signal, a deal, a market shift, or a prior conversation. '
            'If your outreach is not referencing something they care about, it is noise. '
            'Track your touchpoint count per contact and aim for 3 before evaluating whether a lead is truly cold.'
        ),
    }

    # --- Section 7: Fun Fact ---
    brief['fun_fact'] = (
        'The first purpose-built rental community in the U.S. dates back to Stuyvesant Town in Manhattan (1947), '
        'built to house returning WWII veterans. It remains one of the largest residential developments in the country '
        'with over 11,200 apartments on 80 acres — essentially the original build-to-rent at institutional scale.'
    )

    return brief


def _build_action_items():
    """Build personalized action items from CRM data, with generic fallbacks."""
    actions = []

    # Include user's daily focus if set
    try:
        today_str = datetime.utcnow().strftime('%Y-%m-%d')
        focus_row = fetch_one(
            "SELECT daily_focus FROM performance_daily WHERE date_str = ?",
            [today_str]
        )
        if focus_row and focus_row.get('daily_focus'):
            actions.append(f"TODAY'S FOCUS: {focus_row['daily_focus']}")
    except Exception:
        pass

    # Try to pull real data
    try:
        today = datetime.utcnow().strftime('%Y-%m-%d')

        # Overdue follow-ups
        overdue = fetch_all(
            """SELECT t.title, g.name as group_name
               FROM prospecting_tasks t
               LEFT JOIN capital_groups g ON t.capital_group_id = g.id
               WHERE t.status = 'pending' AND t.due_at < ?
               ORDER BY t.due_at ASC LIMIT 2""",
            [today]
        )
        for task in (overdue or []):
            target = task.get('group_name', '')
            actions.append(f"Complete overdue follow-up: {task['title']}" + (f" ({target})" if target else ''))

        # High-warmth contacts going cold
        cooling = fetch_all(
            """SELECT name, warmth_score, last_contacted_at
               FROM capital_groups
               WHERE warmth_score >= 6
                 AND (last_contacted_at IS NULL OR last_contacted_at < ?)
                 AND relationship_status NOT IN ('dormant', 'lost', 'dead')
               ORDER BY warmth_score DESC LIMIT 2""",
            [(datetime.utcnow() - timedelta(days=10)).isoformat()]
        )
        for g in (cooling or []):
            actions.append(f"Re-engage {g['name']} (warmth {g['warmth_score']}/10, going cold)")

        # Unactioned signals
        week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
        signals = fetch_all(
            """SELECT s.title, g.name as group_name
               FROM prospecting_signals s
               LEFT JOIN capital_groups g ON s.group_id = g.id
               WHERE s.detected_at > ?
                 AND NOT EXISTS (
                   SELECT 1 FROM prospecting_touchpoints t
                   WHERE t.group_id = s.group_id AND t.occurred_at > s.detected_at
                 )
               ORDER BY s.importance DESC NULLS LAST LIMIT 2""",
            [week_ago]
        )
        for s in (signals or []):
            actions.append(f"Act on signal: {s['title'][:50]}" + (f" ({s.get('group_name', '')})" if s.get('group_name') else ''))

    except Exception as e:
        logger.warning(f"[Brief] Action items query failed: {e}")

    # Fill with generic actions if not enough personalized ones
    generic = [
        'Identify and reach out to 2 new capital partners with active BTR mandates.',
        'Review SignalStack for unactioned signals and draft outreach for the highest-priority one.',
        'Follow up on any conversations from the past 7 days — reference something specific from the last exchange.',
        'Log all touchpoints from today to keep your CRM current.',
        'Review your pipeline stages and advance any contacts that have been static for 14+ days.',
    ]
    while len(actions) < 5:
        idx = len(actions)
        if idx < len(generic):
            actions.append(generic[idx])
        else:
            break

    return actions[:5]


def _build_daily_targets():
    """Build daily success targets, personalized when possible."""
    targets = []

    try:
        week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
        tp_week = fetch_one(
            "SELECT COUNT(*) as cnt FROM prospecting_touchpoints WHERE occurred_at > ?",
            [week_ago]
        )
        weekly_tp = tp_week['cnt'] if tp_week else 0
        daily_avg = round(weekly_tp / 7, 1) if weekly_tp else 0

        suggested_tp = max(5, int(daily_avg * 1.2))
        targets.append(f'{suggested_tp} touchpoints (your daily avg: {daily_avg})')
    except Exception:
        targets.append('5 touchpoints logged')

    try:
        pending = fetch_one(
            "SELECT COUNT(*) as cnt FROM prospecting_tasks WHERE status = 'pending' AND type = 'follow_up'"
        )
        fu_count = pending['cnt'] if pending else 0
        fu_target = min(max(2, fu_count), 5)
        targets.append(f'{fu_target} follow-ups completed ({fu_count} pending)')
    except Exception:
        targets.append('2 follow-ups completed')

    targets.append('1 meaningful conversation (not a check-in — a real exchange)')
    targets.append('1 new signal acted on within 24 hours of detection')

    try:
        week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
        sig_count = fetch_one(
            "SELECT COUNT(*) as cnt FROM prospecting_signals WHERE detected_at > ?",
            [week_ago]
        )
        if sig_count and sig_count['cnt'] > 0:
            targets.append(f'Review {min(sig_count["cnt"], 5)} signals from SignalStack')
    except Exception:
        pass

    return targets[:5]


# ---------------------------------------------------------------------------
# PDF builder
# ---------------------------------------------------------------------------

def _build_pdf(brief):
    """Generate a clean, professional PDF from brief content. Returns bytes."""
    from fpdf import FPDF

    s = sanitize_text
    F = 'DejaVu' if UNICODE_FONTS_AVAILABLE else 'Helvetica'

    class BriefPDF(FPDF):
        def header(self):
            self.set_font(F, 'B', 10)
            self.set_text_color(100, 116, 139)
            self.cell(0, 8, 'BTR PROSPECTING ENGINE', align='R')
            self.ln(12)

        def footer(self):
            self.set_y(-15)
            self.set_font(F, 'I', 7)
            self.set_text_color(148, 163, 184)
            self.cell(0, 10, s(f'Generated {brief["date"]} | Confidential'), align='C')

        def section_header(self, text):
            self.set_font(F, 'B', 11)
            self.set_text_color(15, 23, 42)
            self.set_fill_color(241, 245, 249)
            self.cell(0, 8, s(f'  {text}'), fill=True, new_x='LMARGIN', new_y='NEXT')
            self.ln(3)

        def body_text(self, text):
            self.set_font(F, '', 9)
            self.set_text_color(51, 65, 85)
            self.multi_cell(0, 5, s(text))
            self.ln(2)

        def bullet(self, text):
            self.set_font(F, '', 9)
            self.set_text_color(51, 65, 85)
            x = self.get_x()
            self.set_x(x + 4)
            self.cell(4, 5, chr(8226) if UNICODE_FONTS_AVAILABLE else '-')
            self.multi_cell(0, 5, s(f' {text}'))
            self.ln(1)

        def numbered(self, num, text):
            self.set_font(F, 'B', 9)
            self.set_text_color(20, 184, 166)
            x = self.get_x()
            self.set_x(x + 4)
            self.cell(6, 5, f'{num}.')
            self.set_font(F, '', 9)
            self.set_text_color(51, 65, 85)
            self.multi_cell(0, 5, s(f' {text}'))
            self.ln(1)

    pdf = BriefPDF('P', 'mm', 'Letter')
    F = _register_unicode_fonts(pdf)
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # Title
    pdf.set_font(F, 'B', 18)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 12, 'BTR Daily Brief', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font(F, '', 10)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(0, 6, s(brief['date']), new_x='LMARGIN', new_y='NEXT')
    pdf.ln(6)

    # Divider
    pdf.set_draw_color(226, 232, 240)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(6)

    # Market Snapshot
    pdf.section_header('MARKET SNAPSHOT')
    for point in brief.get('market_snapshot', []):
        pdf.bullet(point)
    pdf.ln(3)

    # BTR Intelligence
    pdf.section_header('BUILD-TO-RENT INTELLIGENCE')
    for point in brief.get('btr_intelligence', []):
        pdf.bullet(point)
    pdf.ln(3)

    # What This Means
    pdf.section_header('WHAT THIS MEANS')
    pdf.body_text(brief.get('interpretation', ''))
    pdf.ln(2)

    # Action Items
    pdf.section_header('ACTION ITEMS')
    for i, action in enumerate(brief.get('action_items', []), 1):
        pdf.numbered(i, action)
    pdf.ln(3)

    # Daily Targets
    pdf.section_header('DAILY SUCCESS TARGETS')
    for target in brief.get('daily_targets', []):
        pdf.bullet(target)
    pdf.ln(3)

    # What Changed section
    if brief.get('what_changed'):
        pdf.section_header('WHAT CHANGED (LAST 24H)')
        for item in brief['what_changed'][:5]:
            pdf.bullet(item)
        pdf.ln(3)

    # Learning Insight
    learning = brief.get('learning_insight', {})
    if learning:
        pdf.section_header('LEARNING INSIGHT')
        pdf.set_font(F, 'B', 9)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 6, s(learning.get('title', '')), new_x='LMARGIN', new_y='NEXT')
        pdf.body_text(learning.get('content', ''))
        pdf.ln(2)

    # Fun Fact
    pdf.section_header('FUN FACT')
    pdf.body_text(brief.get('fun_fact', ''))

    # Output
    return pdf.output()


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@daily_brief_bp.route('/generate', methods=['GET'])
def generate_brief():
    """Generate the daily brief content as JSON."""
    try:
        brief = _generate_brief_content()
        return jsonify(brief)
    except Exception as e:
        logger.error(f"[Brief] Generate failed: {e}")
        return jsonify({'success': False, 'error': 'Brief generation failed'}), 500


@daily_brief_bp.route('/download', methods=['GET'])
def download_brief():
    """Generate and return the daily brief as a downloadable PDF."""
    try:
        brief = _generate_brief_content()
        pdf_bytes = _build_pdf(brief)
        if not validate_pdf(pdf_bytes):
            logger.error("[PDF] Daily brief generated invalid PDF")
            return jsonify({'success': False, 'error': 'PDF generation failed'}), 500
        now = datetime.utcnow()
        filename = f'BTR_Brief_{now.strftime("%Y-%m-%d_%H%M%S")}.pdf'
        logger.info(f"[PDF] Daily brief generated: {filename} ({len(pdf_bytes)} bytes)")
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename,
        )
    except Exception as e:
        logger.error(f"[PDF] Daily brief generation failed: {e}")
        return jsonify({'success': False, 'error': 'PDF generation failed'}), 500


@daily_brief_bp.route('/preview', methods=['GET'])
def preview_brief():
    """Generate and return the daily brief as an inline PDF (for browser preview)."""
    try:
        brief = _generate_brief_content()
        pdf_bytes = _build_pdf(brief)
        if not validate_pdf(pdf_bytes):
            return jsonify({'success': False, 'error': 'PDF generation failed'}), 500
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=False,
        )
    except Exception as e:
        logger.error(f"[PDF] Preview generation failed: {e}")
        return jsonify({'success': False, 'error': 'PDF generation failed'}), 500


# ---------------------------------------------------------------------------
# General-purpose PDF generator for Leo documents
# ---------------------------------------------------------------------------

PDF_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'pdf_cache')
os.makedirs(PDF_DIR, exist_ok=True)


def build_doc_pdf(doc):
    """Build a premium PDF from a structured document dict.

    Supports section types:
      priority_snapshot, action_queue, schedule, intel,
      insight, metrics, quote, outreach, standard (default).
    Returns PDF bytes.
    """
    from fpdf import FPDF

    S900 = (15, 23, 42)
    S700 = (51, 65, 85)
    S500 = (100, 116, 139)
    S400 = (148, 163, 184)
    S200 = (226, 232, 240)
    S100 = (241, 245, 249)
    TEAL = (13, 148, 136)
    TEAL_LT = (20, 184, 166)
    TEAL_BG = (240, 253, 250)
    RED = (220, 38, 38)
    AMBER = (217, 119, 6)
    BLUE = (37, 99, 235)
    PRIO_CLR = {'critical': RED, 'high': AMBER, 'medium': BLUE, 'low': S500}

    s = sanitize_text

    class PremiumPDF(FPDF):
        def header(self):
            self.set_fill_color(*TEAL)
            self.rect(0, 0, self.w, 2.5, 'F')
            self.set_y(7)
            self.set_font(F, 'B', 8)
            self.set_text_color(*TEAL)
            self.cell(0, 5, 'BTR PROSPECTING ENGINE', align='L')
            self.set_font(F, '', 8)
            self.set_text_color(*S400)
            self.cell(0, 5, s(doc.get('date', '')), align='R')
            self.ln(10)

        def footer(self):
            self.set_y(-12)
            self.set_draw_color(*S200)
            self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
            self.set_y(-10)
            self.set_font(F, '', 7)
            self.set_text_color(*S400)
            self.cell(0, 5, s(f'Confidential  |  {doc.get("date", "")}  |  Page {self.page_no()}'), align='C')

        def section_head(self, text):
            self.ln(2)
            y = self.get_y()
            self.set_fill_color(*TEAL)
            self.rect(self.l_margin, y, 3, 7, 'F')
            self.set_x(self.l_margin + 6)
            self.set_font(F, 'B', 11)
            self.set_text_color(*S900)
            self.cell(0, 7, s(text), new_x='LMARGIN', new_y='NEXT')
            self.ln(3)

        def divider(self):
            self.set_draw_color(*S200)
            self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
            self.ln(4)

        def indented_text(self, indent, w, h, text, **kw):
            orig = self.l_margin
            self.set_left_margin(orig + indent)
            self.set_x(orig + indent)
            self.multi_cell(w, h, text, **kw)
            self.set_left_margin(orig)

    pdf = PremiumPDF('P', 'mm', 'Letter')
    F = _register_unicode_fonts(pdf)
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_left_margin(15)
    pdf.set_right_margin(15)
    pdf.add_page()

    # ---- Title block ----
    pdf.set_font(F, 'B', 22)
    pdf.set_text_color(*S900)
    pdf.cell(0, 12, s(doc.get('title', 'Execution Brief')), new_x='LMARGIN', new_y='NEXT')
    if doc.get('subtitle'):
        pdf.set_font(F, '', 11)
        pdf.set_text_color(*S500)
        pdf.cell(0, 6, s(doc['subtitle']), new_x='LMARGIN', new_y='NEXT')
    pdf.ln(2)
    pdf.divider()
    pdf.ln(1)

    usable_w = pdf.w - pdf.l_margin - pdf.r_margin

    for section in doc.get('sections', []):
        sec_type = section.get('type', 'standard')
        heading = section.get('heading', '')
        if heading:
            pdf.section_head(heading)

        # ---------- priority_snapshot ----------
        if sec_type == 'priority_snapshot':
            for item in section.get('items', []):
                prio = item.get('priority', 'medium')
                clr = PRIO_CLR.get(prio, S500)
                y = pdf.get_y()
                pdf.set_fill_color(*clr)
                pdf.rect(pdf.l_margin + 2, y, 2, 10, 'F')
                pdf.set_x(pdf.l_margin + 8)
                pdf.set_font(F, 'B', 9)
                pdf.set_text_color(*clr)
                pdf.cell(22, 5, s(item.get('label', prio.upper())))
                pdf.set_font(F, '', 9)
                pdf.set_text_color(*S700)
                pdf.indented_text(30, usable_w - 32, 5, s(item.get('text', '')))
                pdf.ln(2)
            pdf.ln(2)

        # ---------- action_queue ----------
        elif sec_type == 'action_queue':
            for group in section.get('groups', []):
                label = group.get('label', '')
                clr = PRIO_CLR.get(label.lower(), S500)
                pdf.set_font(F, 'B', 9)
                pdf.set_text_color(*clr)
                pdf.set_x(pdf.l_margin + 3)
                pdf.cell(0, 5, s(label), new_x='LMARGIN', new_y='NEXT')
                pdf.ln(1)
                for it in group.get('items', []):
                    y = pdf.get_y()
                    pdf.set_fill_color(*clr)
                    pdf.rect(pdf.l_margin + 5, y + 1.5, 1.5, 1.5, 'F')
                    pdf.set_font(F, '', 9)
                    pdf.set_text_color(*S700)
                    pdf.indented_text(10, usable_w - 12, 5, s(it))
                    pdf.ln(1.5)
                pdf.ln(2)
            pdf.ln(1)

        # ---------- schedule ----------
        elif sec_type == 'schedule':
            # Light header row
            pdf.set_fill_color(*S100)
            pdf.set_font(F, 'B', 8)
            pdf.set_text_color(*S500)
            y = pdf.get_y()
            pdf.rect(pdf.l_margin, y, usable_w, 5.5, 'F')
            pdf.set_x(pdf.l_margin + 4)
            pdf.cell(34, 5.5, 'TIME')
            pdf.cell(0, 5.5, 'BLOCK', new_x='LMARGIN', new_y='NEXT')
            pdf.ln(1)
            for blk in section.get('blocks', []):
                is_ex = blk.get('is_existing', False)
                pdf.set_x(pdf.l_margin + 4)
                pdf.set_font(F, 'B', 9)
                pdf.set_text_color(*(S400 if is_ex else TEAL))
                pdf.cell(34, 5, s(blk.get('time', '')))
                style = '' if is_ex else 'B'
                pdf.set_font(F, style, 9)
                pdf.set_text_color(*(S400 if is_ex else S700))
                title_txt = blk.get('title', '')
                if is_ex:
                    title_txt += '  [existing]'
                dur = blk.get('duration', '')
                if dur:
                    title_txt += f'  ({dur})'
                pdf.cell(0, 5, s(title_txt), new_x='LMARGIN', new_y='NEXT')
                desc = blk.get('description', '')
                if desc and not is_ex:
                    pdf.set_x(pdf.l_margin + 38)
                    pdf.set_font(F, 'I', 8)
                    pdf.set_text_color(*S500)
                    pdf.indented_text(38, usable_w - 40, 4, s(desc))
                pdf.ln(1)
            pdf.ln(2)

        # ---------- intel (bullets with impact) ----------
        elif sec_type == 'intel':
            for item in section.get('items', []):
                y = pdf.get_y()
                pdf.set_fill_color(*TEAL_LT)
                pdf.rect(pdf.l_margin + 3, y + 1.8, 1.8, 1.8, 'F')
                pdf.set_font(F, '', 9)
                pdf.set_text_color(*S700)
                pdf.indented_text(8, usable_w - 10, 5, s(item.get('text', '')))
                if item.get('impact'):
                    pdf.set_x(pdf.l_margin + 8)
                    pdf.set_font(F, 'B', 8)
                    pdf.set_text_color(*TEAL)
                    pdf.cell(16, 4, 'Impact: ')
                    pdf.set_font(F, 'I', 8)
                    pdf.set_text_color(*S500)
                    pdf.indented_text(24, usable_w - 26, 4, s(item['impact']))
                pdf.ln(2)
            pdf.ln(1)

        # ---------- insight (Leo blockquote) ----------
        elif sec_type == 'insight':
            text = section.get('text', '')
            if text:
                y_start = pdf.get_y()
                pdf.set_font(F, 'I', 9.5)
                pdf.set_text_color(*S700)
                pdf.indented_text(8, usable_w - 12, 5.5, s(text))
                y_end = pdf.get_y()
                bar_h = max(y_end - y_start, 5)
                pdf.set_fill_color(*TEAL_LT)
                pdf.rect(pdf.l_margin + 3, y_start, 2.5, bar_h, 'F')
                pdf.ln(4)

        # ---------- metrics (checkbox list) ----------
        elif sec_type == 'metrics':
            for item in section.get('items', []):
                y = pdf.get_y()
                pdf.set_draw_color(*TEAL)
                pdf.rect(pdf.l_margin + 4, y + 0.5, 3.5, 3.5)
                pdf.set_font(F, '', 9)
                pdf.set_text_color(*S700)
                pdf.indented_text(11, usable_w - 13, 5, s(item))
                pdf.ln(1.5)
            pdf.ln(2)

        # ---------- outreach example ----------
        elif sec_type == 'outreach':
            target = section.get('target', '')
            subject = section.get('subject', '')
            body = section.get('body', '')
            if target:
                pdf.set_font(F, '', 8)
                pdf.set_text_color(*S500)
                pdf.cell(0, 4, s(f'Target: {target}'), new_x='LMARGIN', new_y='NEXT')
                pdf.ln(1)
            if subject:
                y = pdf.get_y()
                pdf.set_fill_color(*S100)
                pdf.rect(pdf.l_margin + 2, y, usable_w - 4, 6, 'F')
                pdf.set_x(pdf.l_margin + 5)
                pdf.set_font(F, 'B', 9)
                pdf.set_text_color(*S900)
                pdf.cell(0, 6, s(f'Subject: {subject}'), new_x='LMARGIN', new_y='NEXT')
                pdf.ln(1)
                pdf.set_font(F, '', 9)
                pdf.set_text_color(*S700)
                pdf.indented_text(5, usable_w - 10, 5, s(body))
                pdf.ln(3)

        # ---------- quote ----------
        elif sec_type == 'quote':
            pdf.ln(3)
            pdf.divider()
            pdf.ln(2)
            text = section.get('text', '')
            author = section.get('author', '')
            pdf.set_font(F, 'I', 10)
            pdf.set_text_color(*S500)
            pdf.multi_cell(0, 6, s(f'"{text}"'), align='C')
            if author:
                pdf.set_font(F, '', 8)
                pdf.set_text_color(*S400)
                pdf.cell(0, 5, s(f'-- {author}'), align='C', new_x='LMARGIN', new_y='NEXT')
            pdf.ln(4)

        # ---------- standard (backward compat) ----------
        else:
            if section.get('body'):
                pdf.set_font(F, '', 9.5)
                pdf.set_text_color(*S700)
                pdf.multi_cell(0, 5, s(section['body']))
                pdf.ln(2)
            for i, item in enumerate(section.get('items', []), 1):
                pdf.set_font(F, 'B', 9)
                pdf.set_text_color(*TEAL_LT)
                pdf.set_x(pdf.l_margin + 4)
                pdf.cell(6, 5, f'{i}.')
                pdf.set_font(F, '', 9)
                pdf.set_text_color(*S700)
                pdf.multi_cell(0, 5, s(item))
                pdf.ln(1)
            pdf.ln(2)

    return pdf.output()




def validate_pdf(pdf_bytes):
    """Check that pdf_bytes is a valid, non-empty PDF."""
    if not pdf_bytes or len(pdf_bytes) < 100:
        return False
    if not pdf_bytes[:5] == b'%PDF-':
        return False
    return True


def store_pdf(pdf_bytes, filename, report_type='unknown'):
    """Store PDF bytes to disk, return download ID."""
    import uuid
    if not validate_pdf(pdf_bytes):
        logger.error(f"[PDF] Invalid PDF bytes for {filename}: size={len(pdf_bytes) if pdf_bytes else 0}")
        raise ValueError("Generated PDF is invalid or empty")
    pdf_id = str(uuid.uuid4())
    path = os.path.join(PDF_DIR, f"{pdf_id}.pdf")
    meta_path = os.path.join(PDF_DIR, f"{pdf_id}.json")
    with open(path, 'wb') as f:
        f.write(pdf_bytes)
    with open(meta_path, 'w') as f:
        json.dump({
            'filename': filename, 'created': datetime.utcnow().isoformat(),
            'size': len(pdf_bytes), 'report_type': report_type,
            'pdf_id': pdf_id, 'path': path,
        }, f)
    logger.info(
        f"[PDF] Stored report_type={report_type} filename={filename} "
        f"size={len(pdf_bytes)}b pdf_id={pdf_id[:12]} path={path}"
    )
    _evict_old_pdfs()
    return pdf_id


def _evict_old_pdfs():
    """Keep only the 50 most recent PDFs on disk."""
    try:
        meta_files = sorted(
            [f for f in os.listdir(PDF_DIR) if f.endswith('.json')],
            key=lambda f: os.path.getmtime(os.path.join(PDF_DIR, f))
        )
        if len(meta_files) > 50:
            for mf in meta_files[:len(meta_files) - 50]:
                pdf_id = mf.replace('.json', '')
                for ext in ('.pdf', '.json'):
                    p = os.path.join(PDF_DIR, pdf_id + ext)
                    if os.path.exists(p):
                        os.remove(p)
    except Exception as e:
        logger.warning(f"[PDF] Eviction error: {e}")


def _resolve_pdf(pdf_id):
    """Validate pdf_id and return (path, filename, meta) or raise ValueError."""
    import re
    if not re.match(r'^[a-f0-9\-]{36}$', pdf_id):
        raise ValueError('Invalid PDF ID')
    path = os.path.join(PDF_DIR, f"{pdf_id}.pdf")
    if not os.path.exists(path):
        raise FileNotFoundError(f'PDF {pdf_id} not found or expired')
    size = os.path.getsize(path)
    if size < 100:
        raise ValueError(f'PDF {pdf_id} is corrupt (size={size})')
    meta = {}
    meta_path = os.path.join(PDF_DIR, f"{pdf_id}.json")
    if os.path.exists(meta_path):
        try:
            with open(meta_path) as f:
                meta = json.load(f)
        except Exception:
            pass
    filename = meta.get('filename', f"BTR_Document_{pdf_id[:8]}.pdf")
    return path, filename, meta, size


@daily_brief_bp.route('/doc/<pdf_id>/verify', methods=['GET'])
def verify_doc(pdf_id):
    """Verify a PDF exists and is valid before download."""
    try:
        path, filename, meta, size = _resolve_pdf(pdf_id)
        with open(path, 'rb') as f:
            header_bytes = f.read(100)
        if not validate_pdf(header_bytes):
            return jsonify({'valid': False, 'error': 'File is not a valid PDF'}), 500
        return jsonify({
            'valid': True, 'filename': filename, 'size': size,
            'created': meta.get('created', ''), 'content_type': 'application/pdf',
        })
    except (ValueError, FileNotFoundError) as e:
        return jsonify({'valid': False, 'error': str(e)}), 404


@daily_brief_bp.route('/doc/<pdf_id>', methods=['GET'])
def download_doc(pdf_id):
    """Download a generated PDF by ID."""
    try:
        path, filename, meta, size = _resolve_pdf(pdf_id)
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid PDF ID'}), 400
    except FileNotFoundError:
        logger.warning(f"[PDF] Download requested for missing PDF: {pdf_id}")
        return jsonify({'success': False, 'error': 'PDF not found or expired'}), 404
    logger.info(
        f"[PDF] Serving pdf_id={pdf_id[:12]} filename={filename} "
        f"path={path} size={size}b type={meta.get('report_type', '?')}"
    )
    return send_file(
        path,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=filename,
    )
