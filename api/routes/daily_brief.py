"""
API Routes: Daily BTR Intelligence Brief — PDF generation + download.
"""
from flask import Blueprint, request, jsonify, send_file
from shared.database import fetch_all, fetch_one
from datetime import datetime, timedelta
import io
import json
import os

daily_brief_bp = Blueprint('daily_brief', __name__, url_prefix='/api/brief')


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

    # --- Section 1: Market Snapshot ---
    market_points = [
        'Multifamily construction starts declined 8% YoY nationally, tightening future supply and favoring BTR absorption.',
        'Institutional capital continues rotating from office to residential, with BTR capturing an increasing share of LP allocations.',
        'Sun Belt metros (DFW, Phoenix, Nashville, Charlotte) lead in BTR permit activity, though land costs are compressing yields.',
        'Interest rate stabilization is improving deal underwriting certainty — more projects penciling than in late 2024.',
        'Single-family rental REITs are expanding build-to-rent pipelines, signaling sustained institutional demand.',
    ]
    brief['market_snapshot'] = market_points

    # --- Section 2: BTR Intelligence ---
    btr_intel = [
        'Horizontal BTR communities (detached single-family rental) outperforming vertical mid-rise in lease-up velocity across secondary markets.',
        'Developer-operator partnerships increasing as capital partners seek stabilized yield without development risk.',
        'Land sellers in growth corridors are increasingly pricing BTR use into asks — early movers have a cost advantage.',
        'Amenity packages trending toward remote-work infrastructure: fiber, co-working lounges, and soundproof pods.',
    ]
    brief['btr_intelligence'] = btr_intel

    # --- Section 3: What This Means ---
    interpretation = (
        'The supply squeeze combined with stable rates creates a window for well-capitalized operators. '
        'BTR is no longer a niche — institutional demand is pulling it into mainstream CRE allocation. '
        'For prospectors, this means capital partners are actively looking for deal flow. '
        'The competitive advantage is speed: getting in front of LPs before their allocation windows close, '
        'and sourcing land before BTR-specific pricing becomes standard.'
    )
    brief['interpretation'] = interpretation

    # --- Section 4: Action Items (personalized if data available) ---
    actions = _build_action_items()
    brief['action_items'] = actions

    # --- Section 5: Daily Success Targets ---
    targets = _build_daily_targets()
    brief['daily_targets'] = targets

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

    except Exception:
        pass

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

    class BriefPDF(FPDF):
        def header(self):
            self.set_font('Helvetica', 'B', 10)
            self.set_text_color(100, 116, 139)
            self.cell(0, 8, 'BTR PROSPECTING ENGINE', align='R')
            self.ln(12)

        def footer(self):
            self.set_y(-15)
            self.set_font('Helvetica', 'I', 7)
            self.set_text_color(148, 163, 184)
            self.cell(0, 10, f'Generated {brief["date"]} | Confidential', align='C')

        def section_header(self, text):
            self.set_font('Helvetica', 'B', 11)
            self.set_text_color(15, 23, 42)
            self.set_fill_color(241, 245, 249)
            self.cell(0, 8, f'  {text}', fill=True, new_x='LMARGIN', new_y='NEXT')
            self.ln(3)

        def body_text(self, text):
            self.set_font('Helvetica', '', 9)
            self.set_text_color(51, 65, 85)
            self.multi_cell(0, 5, text)
            self.ln(2)

        def bullet(self, text):
            self.set_font('Helvetica', '', 9)
            self.set_text_color(51, 65, 85)
            x = self.get_x()
            self.set_x(x + 4)
            self.cell(4, 5, chr(8226))
            self.multi_cell(0, 5, f' {text}')
            self.ln(1)

        def numbered(self, num, text):
            self.set_font('Helvetica', 'B', 9)
            self.set_text_color(20, 184, 166)
            x = self.get_x()
            self.set_x(x + 4)
            self.cell(6, 5, f'{num}.')
            self.set_font('Helvetica', '', 9)
            self.set_text_color(51, 65, 85)
            self.multi_cell(0, 5, f' {text}')
            self.ln(1)

    pdf = BriefPDF('P', 'mm', 'Letter')
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # Title
    pdf.set_font('Helvetica', 'B', 18)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 12, 'BTR Daily Brief', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(0, 6, brief['date'], new_x='LMARGIN', new_y='NEXT')
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

    # Learning Insight
    learning = brief.get('learning_insight', {})
    if learning:
        pdf.section_header('LEARNING INSIGHT')
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 6, learning.get('title', ''), new_x='LMARGIN', new_y='NEXT')
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
    brief = _generate_brief_content()
    return jsonify(brief)


@daily_brief_bp.route('/download', methods=['GET'])
def download_brief():
    """Generate and return the daily brief as a downloadable PDF."""
    brief = _generate_brief_content()
    pdf_bytes = _build_pdf(brief)

    date_slug = datetime.utcnow().strftime('%Y-%m-%d')
    filename = f'BTR-Daily-Brief-{date_slug}.pdf'

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=filename,
    )


@daily_brief_bp.route('/preview', methods=['GET'])
def preview_brief():
    """Generate and return the daily brief as an inline PDF (for browser preview)."""
    brief = _generate_brief_content()
    pdf_bytes = _build_pdf(brief)

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype='application/pdf',
        as_attachment=False,
    )
