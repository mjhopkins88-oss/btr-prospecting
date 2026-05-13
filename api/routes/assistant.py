"""
API Routes: AI Assistant — Operator Intelligence System.

Core intelligence layer: strategic advisor, CRM operator, analyst,
system optimizer. Multi-mode intent routing, proactive insights,
interaction tracking, structured cards, and session memory.
"""
from flask import Blueprint, request, jsonify
from shared.database import fetch_all, fetch_one, execute, new_id
from datetime import datetime, timedelta
import os
import anthropic
import json
import re

try:
    from services.proactive_suggestions import get_proactive_suggestions
except ImportError:
    def get_proactive_suggestions():
        return None

assistant_bp = Blueprint('assistant', __name__, url_prefix='/api/assistant')

# ---------------------------------------------------------------------------
# Intent classification — expanded
# ---------------------------------------------------------------------------

INTENT_KEYWORDS = {
    'brainstorm':       ['idea', 'brainstorm', 'strategy', 'approach', 'think about', 'what if',
                         'how could', 'improve', 'optimize', 'better', 'creative', 'explore',
                         'options', 'leverage', 'opportunity', 'growth'],
    'diagnose':         ['why', 'not closing', 'not working', 'failing', 'dropping', 'declining',
                         'low', 'behind', 'stuck', 'bottleneck', 'what went wrong'],
    'build_prompt':     ['build prompt', 'write prompt', 'create prompt', 'prompt for',
                         'claude prompt', 'ai prompt', 'system design', 'architect'],
    'draft_outreach':   ['draft', 'write email', 'outreach', 'message to', 'reach out',
                         'cold email', 'linkedin message', 'write to'],
    'explain_metrics':  ['explain', 'what does', 'what is', 'how does', 'mean by',
                         'metric', 'score', 'warmth', 'define'],
    'analyze_contact':  ['about this contact', 'tell me about', 'who is', 'contact info',
                         'relationship with', 'history with', 'brief me on'],
    'analyze_company':  ['company', 'capital group', 'firm', 'fund', 'partner',
                         'organization', 'group analysis'],
    'recommend_action': ['what should', 'next step', 'priority', 'recommend', 'suggest',
                         'what now', 'top action', 'focus on', 'do next'],
    'log_update_crm':   ['log', 'record', 'update stage', 'mark as', 'change status',
                         'touchpoint', 'note that'],
    'crm_update':       ['called', 'emailed', 'met with', 'texted', 'spoke with',
                         'had a call', 'log a call', 'add touchpoint', 'move to',
                         'follow up with', 'follow-up', 'check back', 'create task',
                         'action item', 'send deck', 'add note to', 'had a meeting',
                         'sent an email', 'reached out', 'connected with', 'set up',
                         'scheduled', 'move them to', 'change to', 'update to'],
    'export_report':    ['export', 'download', 'csv', 'report', 'spreadsheet', 'pull data'],
    'troubleshoot':     ['error', 'broken', 'not working', 'bug', 'issue', 'wrong',
                         'fix', 'help with app', 'problem'],
    'coach':            ['how am i doing', 'performance', 'momentum', 'cadence', 'habit',
                         'consistency', 'streak', 'pace', 'on track', 'falling behind',
                         'recovery', 'burnout', 'motivat'],
}

INTENT_TO_MODE = {
    'brainstorm':       'strategic',
    'diagnose':         'analyst',
    'build_prompt':     'builder',
    'draft_outreach':   'execution',
    'explain_metrics':  'analyst',
    'analyze_contact':  'analyst',
    'analyze_company':  'analyst',
    'recommend_action': 'execution',
    'log_update_crm':   'execution',
    'crm_update':       'execution',
    'export_report':    'execution',
    'troubleshoot':     'execution',
    'coach':            'coach',
}

MODE_MAX_TOKENS = {
    'strategic': 3000,
    'execution': 1500,
    'analyst':   2500,
    'builder':   2500,
    'coach':     2000,
}


def _classify_intent(text):
    text_lower = text.lower()

    if text_lower.startswith('/'):
        cmd = text_lower.split()[0]
        slash_map = {
            '/draft': 'draft_outreach', '/log': 'log_update_crm',
            '/next': 'recommend_action', '/brief': 'coach',
            '/export': 'export_report', '/signal': 'analyze_company',
            '/sprint': 'recommend_action', '/fix': 'troubleshoot',
            '/plan': 'brainstorm',
        }
        return slash_map.get(cmd, 'recommend_action')

    best_intent = 'brainstorm'
    best_score = 0
    for intent, keywords in INTENT_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in text_lower)
        if score > best_score:
            best_score = score
            best_intent = intent
    return best_intent


# ---------------------------------------------------------------------------
# System prompt — Operator Intelligence
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are BTR Command Operator — the core intelligence layer of a commercial real estate prospecting platform.

You are NOT a chatbot. You are the system's brain: strategist, operator, analyst, and optimizer.

INTERNAL PROCESS (never expose this):
For every message, silently: classify intent → gather context → select mode → reason → output refined answer.
Never show chain-of-thought. Only output polished, actionable responses.

═══════════════════════════════
RESPONSE STRUCTURE (every response)
═══════════════════════════════
1. Direct answer (1-2 lines — what they need NOW)
2. Insight (what's really going on beneath the surface)
3. Recommendation (specific, with names from CRM)
4. Action options (cards/buttons when executable)

Keep it tight. No walls of text. No filler.

═══════════════════════════════
RESPONSE MODES (auto-selected)
═══════════════════════════════

STRATEGIC — ideas, optimization, product decisions
→ diagnosis, leverage points, prioritized actions, tradeoffs
→ Use StrategyCard

EXECUTION — doing things (logging, drafting, exporting, next actions)
→ action cards, minimal text, clear buttons
→ Use DraftCard, TouchpointLogCard, ExportCard, NextActionCard, ConfirmationCard

ANALYST — interpreting CRM data, analyzing contacts/companies, diagnosing problems
→ patterns, inefficiencies, opportunities
→ Multi-step for "why" questions: check data → identify bottleneck → recommend fix → offer to execute
→ Use ContactInsightCard, SignalInsightCard, PerformanceInsightCard

BUILDER — Claude prompts, system design, workflow architecture
→ exact prompts, constraints, output format, safety rules
→ Use ClaudePromptCard

COACH — performance, behavior, momentum, recovery
→ what to do now, how to recover, cadence guidance
→ Reference Performance dashboard and weekly patterns
→ Use PerformanceInsightCard or NextActionCard

═══════════════════════════════
PRODUCT AWARENESS
═══════════════════════════════
- SignalStack = timing intelligence (when to act on market signals)
- Performance = behavior engine (daily execution metrics, streaks, habits)
- Prospecting = relationship engine (contacts, companies, touchpoints)
- Command Center = execution layer (this chat, action cards, CRM operations)
- Operator Mode = this chat interface

Use these names naturally. They are the product language.

═══════════════════════════════
MULTI-STEP REASONING
═══════════════════════════════
For "why" questions (e.g., "why am I not closing deals?"):
1. Analyze the data (activity volume, follow-up timing, signal utilization)
2. Identify the bottleneck (low replies? weak follow-ups? bad timing?)
3. Recommend the fix (specific, with names)
4. Suggest executable actions
5. Offer to execute via action cards

For improvement questions (e.g., "how can I improve X?"):
1. Diagnosis (what's actually happening)
2. Highest-ROI improvements (ranked by effort vs impact)
3. Implementation order
4. Exact Claude prompt for deeper work (if relevant)
5. Risks / what not to do

═══════════════════════════════
PROACTIVE INSIGHTS
═══════════════════════════════
When context data reveals patterns, surface them naturally in your response:
- Under-following high-value contacts
- Signals detected but not acted on
- Activity trending down vs prior week
- Contacts going cold that were previously warm
- Stage bottlenecks (too many stuck at same stage)
- Overdue tasks piling up

Weave these into your answer like a smart colleague would. Not as alerts — as observations.

═══════════════════════════════
CARD TYPES
═══════════════════════════════

TextCard: data: {}
StrategyCard: data: {"diagnosis":"...","recommendations":[{"title":"...","detail":"...","effort":"low|medium|high","impact":"low|medium|high"}],"implementation_order":["..."],"risks":["..."],"claude_prompt":"..." or null}
ClaudePromptCard: data: {"prompt_title":"...","prompt_body":"...","constraints":["..."],"output_format":"..."}
DraftCard: data: {"channel":"email|linkedin|call","target_name":"...","target_id":"...","subject":"...","body":"...","signal_ref":"..."}
NextActionCard: data: {"recommendations":[{"priority":"high|medium|low","action":"...","target":"...","reason":"..."}]}
ContactInsightCard: data: {"name":"...","id":"...","title":"...","company":"...","stage":"...","warmth":N,"last_touch":"...","touchpoint_count":N,"engagement_trend":"rising|stable|declining","key_insights":["..."],"next_move":"..."}
SignalInsightCard: data: {"company_name":"...","company_id":"...","signals":[{"title":"...","summary":"...","source_url":"...","importance":1-10,"action_implication":"..."}],"overall_assessment":"...","recommended_action":"..."}
PerformanceInsightCard: data: {"period":"today|week|month","metrics":[{"label":"...","value":"...","trend":"up|down|flat"}],"insights":["..."],"focus_recommendation":"..."}
ExecutionPlanCard: data: {"plan_title":"...","steps":[{"step":1,"title":"...","detail":"...","status":"pending|current|done"}],"estimated_time":"...","next_step_action":"..."}
FixCard: data: {"diagnosis":"...","cause":"...","solution":"...","steps":["..."]}
CompanySummaryCard: data: {"name":"...","id":"...","status":"...","warmth":N,"last_contact":"...","contacts":N,"opp_stage":"...","opp_value":"..."}
ContactSummaryCard: data: {"name":"...","id":"...","title":"...","company":"...","stage":"...","last_touch":"...","touchpoint_count":N,"notes":"..."}
TouchpointLogCard: data: {"contact_name":"...","contact_id":"...","group_id":"...","channel":"email|call|meeting|linkedin|note","summary":"...","direction":"outbound|inbound"}
FollowUpCard: data: {"contact_name":"...","contact_id":"...","due_date":"YYYY-MM-DD","task_type":"follow_up|call|meeting","title":"..."}
ExportCard: data: {"export_type":"contacts|capital_partners|underwriting|prospects","url":"...","filename":"..."}
ConfirmationCard: data: {"what":"...","result":"...","entity_id":"..."}
CrmUpdatePreviewCard: data: {"items":["..."],"group_name":"...","contact_name":"...","touchpoint":{"channel":"...","summary":"...","date":"..."}|null,"follow_up":{"title":"...","due_date":"..."}|null,"stage_change":{"entity":"group|contact","new_stage":"..."}|null,"notes":"..."}
AmbiguityCard: data: {"entity_type":"group|contact","choices":[{"id":"...","label":"...","sublabel":"..."}]}
ErrorCard: data: {"error":"...","suggestion":"..."}

═══════════════════════════════
RULES
═══════════════════════════════
1. ALWAYS return exactly ONE <card>...</card> block. No text outside it.
2. Use REAL data from context. Never fabricate.
3. If data is missing: say exactly what's missing, suggest how to fix it.
4. Be specific: "Call Ethan Park about the Q3 allocation" not "Follow up with contacts."
5. Never pretend an action was completed. Only offer executable actions.
6. For strategic: full answer in "text". Multiple paragraphs OK. Use **bold** and bullet points.
7. Tone: direct, sharp, operator-focused. No fluff. Confident but evidence-based.
8. Don't repeat prior chat ideas unless improving them.
9. If user asks about app features, reference product names (SignalStack, Performance, etc.).
10. Proactively suggest next moves.

═══════════════════════════════
SLASH COMMANDS
═══════════════════════════════
/draft [contact] — Draft outreach
/log [note] — Log a touchpoint
/next — Top priority action
/brief — Daily briefing with performance
/export [type] — Export data
/signal [company] — Signal analysis
/sprint — Prioritized work sprint
/plan [topic] — Strategic planning
/fix [issue] — Diagnose and fix"""


# ---------------------------------------------------------------------------
# Proactive insight generator — data-driven pattern detection
# ---------------------------------------------------------------------------

def _generate_proactive_insights():
    """Analyze CRM data for actionable patterns. Returns list of insight strings."""
    insights = []

    # 1. High-warmth contacts not recently touched
    try:
        undertouched = fetch_all(
            """SELECT g.name, g.warmth_score, g.last_contacted_at
               FROM capital_groups g
               WHERE g.warmth_score >= 7
               AND (g.last_contacted_at IS NULL OR g.last_contacted_at < ?)
               ORDER BY g.warmth_score DESC LIMIT 3""",
            [(datetime.utcnow() - timedelta(days=14)).isoformat()]
        )
        if undertouched:
            names = ', '.join(g['name'] for g in undertouched)
            insights.append(
                f"UNDER-FOLLOWED: {len(undertouched)} high-warmth groups "
                f"({names}) haven't been touched in 14+ days"
            )
    except Exception:
        pass

    # 2. Activity trend (this week vs last week)
    try:
        week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
        two_weeks = (datetime.utcnow() - timedelta(days=14)).isoformat()
        this_week = fetch_one(
            "SELECT COUNT(*) as cnt FROM prospecting_touchpoints WHERE occurred_at > ?",
            [week_ago]
        )
        last_week = fetch_one(
            "SELECT COUNT(*) as cnt FROM prospecting_touchpoints WHERE occurred_at > ? AND occurred_at < ?",
            [two_weeks, week_ago]
        )
        tw = this_week['cnt'] if this_week else 0
        lw = last_week['cnt'] if last_week else 0
        if lw > 0 and tw < lw * 0.6:
            pct = int((1 - tw / max(lw, 1)) * 100)
            insights.append(
                f"ACTIVITY DROP: Touchpoints down {pct}% this week ({tw}) "
                f"vs last week ({lw})"
            )
        elif lw > 0 and tw > lw * 1.3:
            pct = int((tw / max(lw, 1) - 1) * 100)
            insights.append(
                f"MOMENTUM: Activity up {pct}% this week ({tw} vs {lw}) — keep pushing"
            )
    except Exception:
        pass

    # 3. Signals detected but not followed up
    try:
        week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
        sig_total = fetch_one(
            "SELECT COUNT(*) as cnt FROM prospecting_signals WHERE detected_at > ?",
            [week_ago]
        )
        sig_acted = fetch_one(
            """SELECT COUNT(DISTINCT s.id) as cnt
               FROM prospecting_signals s
               JOIN prospecting_touchpoints t
                 ON t.group_id = s.group_id AND t.occurred_at > s.detected_at
               WHERE s.detected_at > ?""",
            [week_ago]
        )
        total = sig_total['cnt'] if sig_total else 0
        acted = sig_acted['cnt'] if sig_acted else 0
        if total > 0 and acted < total * 0.3:
            insights.append(
                f"SIGNAL GAP: {total} signals this week, only {acted} followed up on. "
                f"SignalStack is finding opportunities but they're not being actioned."
            )
    except Exception:
        pass

    # 4. Stage bottleneck
    try:
        stages = fetch_all(
            """SELECT relationship_status, COUNT(*) as cnt
               FROM capital_groups
               WHERE relationship_status IS NOT NULL
               GROUP BY relationship_status ORDER BY cnt DESC""", []
        )
        total = sum(s['cnt'] for s in stages) if stages else 0
        if stages and total > 5:
            top = stages[0]
            pct = int(top['cnt'] / max(total, 1) * 100)
            if pct > 55:
                insights.append(
                    f"BOTTLENECK: {pct}% of capital groups ({top['cnt']}/{total}) are at "
                    f"'{top['relationship_status']}' — review pipeline progression"
                )
    except Exception:
        pass

    # 5. Overdue tasks
    try:
        overdue = fetch_one(
            "SELECT COUNT(*) as cnt FROM prospecting_tasks WHERE status = 'pending' AND due_at < ?",
            [datetime.utcnow().strftime('%Y-%m-%d')]
        )
        if overdue and overdue['cnt'] > 2:
            insights.append(
                f"OVERDUE: {overdue['cnt']} tasks past due — address or reschedule"
            )
    except Exception:
        pass

    # 6. Contacts going cold from warm status
    try:
        going_cold = fetch_all(
            """SELECT COUNT(*) as cnt FROM capital_groups
               WHERE last_contacted_at IS NOT NULL
                 AND last_contacted_at < ?
                 AND relationship_status IN ('warm', 'active', 'engaged')""",
            [(datetime.utcnow() - timedelta(days=21)).isoformat()]
        )
        if going_cold and going_cold[0]['cnt'] > 0:
            cnt = going_cold[0]['cnt']
            insights.append(
                f"COOLING: {cnt} previously warm/active groups haven't been "
                f"touched in 21+ days"
            )
    except Exception:
        pass

    return insights


# ---------------------------------------------------------------------------
# Interaction pattern analysis (self-improvement loop)
# ---------------------------------------------------------------------------

def _get_interaction_patterns():
    """Analyze recent chat logs to understand user behavior patterns."""
    try:
        rows = fetch_all(
            """SELECT card_type, user_message, created_at
               FROM assistant_chat_log
               ORDER BY created_at DESC LIMIT 30""", []
        )
        if not rows or len(rows) < 3:
            return ""

        # Count intents/modes from card_type field (format: CardType|intent|mode)
        intent_counts = {}
        mode_counts = {}
        card_counts = {}
        for r in rows:
            parts = r.get('card_type', '').split('|')
            card_type = parts[0] if parts else 'TextCard'
            intent = parts[1] if len(parts) > 1 else 'unknown'
            mode = parts[2] if len(parts) > 2 else 'unknown'
            intent_counts[intent] = intent_counts.get(intent, 0) + 1
            mode_counts[mode] = mode_counts.get(mode, 0) + 1
            card_counts[card_type] = card_counts.get(card_type, 0) + 1

        # Track actions executed
        action_rows = fetch_all(
            """SELECT card_type FROM assistant_chat_log
               WHERE card_type LIKE 'ACTION:%'
               ORDER BY created_at DESC LIMIT 20""", []
        )
        action_counts = {}
        for a in (action_rows or []):
            action_type = a['card_type'].replace('ACTION:', '')
            action_counts[action_type] = action_counts.get(action_type, 0) + 1

        parts = ["INTERACTION PATTERNS (last 30 exchanges):"]
        top_intents = sorted(intent_counts.items(), key=lambda x: x[1], reverse=True)[:4]
        if top_intents:
            parts.append("  Most asked: " + ", ".join(
                f"{k} ({v}x)" for k, v in top_intents if k != 'unknown'
            ))
        top_cards = sorted(card_counts.items(), key=lambda x: x[1], reverse=True)[:4]
        if top_cards:
            parts.append("  Card types received: " + ", ".join(
                f"{k} ({v}x)" for k, v in top_cards
            ))
        if action_counts:
            parts.append("  Actions executed: " + ", ".join(
                f"{k} ({v}x)" for k, v in sorted(action_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            ))
        return "\n".join(parts)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Context builder — full CRM state + insights + patterns
# ---------------------------------------------------------------------------

def _build_context(extra_context=None, include_history=True):
    """Gather current app state including CRM data, performance, insights, and patterns."""
    ctx_parts = []

    # Capital groups
    groups = fetch_all(
        """SELECT id, name, type, relationship_status, warmth_score,
                  last_contacted_at, opportunity_stage, opportunity_value, notes
           FROM capital_groups
           ORDER BY warmth_score DESC, last_contacted_at DESC NULLS LAST LIMIT 20""", []
    )
    if groups:
        ctx_parts.append("CAPITAL GROUPS (top 20):")
        for g in groups:
            line = f"- [{g['id'][:8]}] {g['name']} | status={g['relationship_status']} warmth={g['warmth_score']}"
            if g.get('last_contacted_at'):
                line += f" last_contact={str(g['last_contacted_at'])[:10]}"
            if g.get('opportunity_stage'):
                line += f" opp_stage={g['opportunity_stage']} opp_value={g.get('opportunity_value', '')}"
            if g.get('notes'):
                line += f" notes={str(g['notes'])[:80]}"
            ctx_parts.append(line)

    # Contacts
    contacts = fetch_all(
        """SELECT c.id, c.first_name, c.last_name, c.title, c.email, c.phone,
                  c.relationship_stage, c.last_touch_at, c.notes, c.group_id,
                  g.name as group_name
           FROM prospecting_contacts c
           LEFT JOIN capital_groups g ON c.group_id = g.id
           ORDER BY c.last_touch_at DESC NULLS LAST LIMIT 20""", []
    )
    if contacts:
        ctx_parts.append("\nCONTACTS (top 20 by recent touch):")
        for c in contacts:
            name = f"{c.get('first_name', '')} {c.get('last_name', '')}".strip()
            line = f"- [{c['id'][:8]}] {name}"
            if c.get('title'):
                line += f" ({c['title']})"
            if c.get('group_name'):
                line += f" at {c['group_name']}"
            line += f" stage={c.get('relationship_stage', 'cold')}"
            if c.get('last_touch_at'):
                line += f" last_touch={str(c['last_touch_at'])[:10]}"
            if c.get('email'):
                line += f" email={c['email']}"
            if c.get('phone'):
                line += f" phone={c['phone']}"
            ctx_parts.append(line)

    # Signals
    signals = fetch_all(
        """SELECT id, title, summary, source_url, importance, signal_type, group_id,
                  contact_id, detected_at
           FROM prospecting_signals
           ORDER BY detected_at DESC NULLS LAST, created_at DESC
           LIMIT 10""", []
    )
    if signals:
        ctx_parts.append("\nRECENT SIGNALS (SignalStack):")
        for s in signals:
            line = f"- [{s['id'][:8]}] {s['title']}"
            if s.get('signal_type'):
                line += f" type={s['signal_type']}"
            if s.get('importance'):
                line += f" importance={s['importance']}"
            if s.get('summary'):
                line += f" | {str(s['summary'])[:80]}"
            if s.get('source_url'):
                line += f" url={s['source_url'][:60]}"
            ctx_parts.append(line)

    # Touchpoints
    touchpoints = fetch_all(
        """SELECT t.id, t.channel, t.subject, t.summary, t.occurred_at,
                  c.first_name, c.last_name, g.name as group_name
           FROM prospecting_touchpoints t
           LEFT JOIN prospecting_contacts c ON t.contact_id = c.id
           LEFT JOIN capital_groups g ON t.group_id = g.id
           ORDER BY t.occurred_at DESC LIMIT 10""", []
    )
    if touchpoints:
        ctx_parts.append("\nRECENT TOUCHPOINTS:")
        for t in touchpoints:
            who = f"{t.get('first_name', '')} {t.get('last_name', '')}".strip()
            if not who and t.get('group_name'):
                who = t['group_name']
            line = f"- {t.get('channel', 'note')} with {who or 'unknown'}"
            if t.get('subject'):
                line += f": {t['subject'][:60]}"
            elif t.get('summary'):
                line += f": {str(t['summary'])[:60]}"
            if t.get('occurred_at'):
                line += f" ({str(t['occurred_at'])[:10]})"
            ctx_parts.append(line)

    # Going cold
    cold = fetch_all(
        """SELECT id, name, last_contacted_at, relationship_status, warmth_score
           FROM capital_groups
           WHERE last_contacted_at IS NOT NULL
             AND last_contacted_at < ?
             AND relationship_status NOT IN ('dormant', 'cold')
           ORDER BY warmth_score DESC, last_contacted_at ASC LIMIT 5""",
        [(datetime.utcnow() - timedelta(days=30)).isoformat()]
    )
    if cold:
        ctx_parts.append("\nGOING COLD (30+ days no contact):")
        for r in cold:
            try:
                days = (datetime.utcnow() - datetime.fromisoformat(
                    str(r['last_contacted_at']).replace('Z', '')
                )).days
            except Exception:
                days = '?'
            ctx_parts.append(
                f"- [{r['id'][:8]}] {r['name']} — {days}d silent "
                f"(status={r['relationship_status']}, warmth={r.get('warmth_score', '?')})"
            )

    # Pending tasks
    tasks = fetch_all(
        """SELECT t.id, t.title, t.type, t.due_at, t.priority,
                  g.name as group_name
           FROM prospecting_tasks t
           LEFT JOIN capital_groups g ON t.capital_group_id = g.id
           WHERE t.status = 'pending'
           ORDER BY t.priority DESC, t.due_at ASC NULLS LAST LIMIT 10""", []
    )
    if tasks:
        ctx_parts.append("\nPENDING TASKS:")
        for t in tasks:
            line = f"- [{t['id'][:8]}] {t['title']}"
            if t.get('group_name'):
                line += f" ({t['group_name']})"
            if t.get('due_at'):
                line += f" due={str(t['due_at'])[:10]}"
            if t.get('priority'):
                line += f" priority={t['priority']}"
            ctx_parts.append(line)

    # Performance metrics
    today = datetime.utcnow().strftime('%Y-%m-%d')
    week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
    two_weeks = (datetime.utcnow() - timedelta(days=14)).isoformat()

    tp_today = fetch_one(
        "SELECT COUNT(*) as cnt FROM prospecting_touchpoints WHERE DATE(occurred_at) = ?",
        [today]
    )
    tp_week = fetch_one(
        "SELECT COUNT(*) as cnt FROM prospecting_touchpoints WHERE occurred_at > ?",
        [week_ago]
    )
    tp_last_week = fetch_one(
        "SELECT COUNT(*) as cnt FROM prospecting_touchpoints WHERE occurred_at > ? AND occurred_at < ?",
        [two_weeks, week_ago]
    )
    total_contacts = fetch_one("SELECT COUNT(*) as cnt FROM prospecting_contacts")
    total_groups = fetch_one("SELECT COUNT(*) as cnt FROM capital_groups")
    total_signals = fetch_one(
        "SELECT COUNT(*) as cnt FROM prospecting_signals WHERE detected_at > ?",
        [week_ago]
    )
    tasks_completed = fetch_one(
        "SELECT COUNT(*) as cnt FROM prospecting_tasks WHERE status = 'completed' AND completed_at > ?",
        [week_ago]
    )
    tasks_pending = fetch_one(
        "SELECT COUNT(*) as cnt FROM prospecting_tasks WHERE status = 'pending'"
    )
    overdue_tasks = fetch_all(
        """SELECT t.title, t.due_at, g.name as group_name
           FROM prospecting_tasks t
           LEFT JOIN capital_groups g ON t.capital_group_id = g.id
           WHERE t.status = 'pending' AND t.due_at < ?
           ORDER BY t.due_at ASC LIMIT 5""",
        [today]
    )

    tw = tp_week['cnt'] if tp_week else 0
    lw = tp_last_week['cnt'] if tp_last_week else 0
    trend = 'flat'
    if lw > 0:
        if tw > lw * 1.15:
            trend = 'up'
        elif tw < lw * 0.85:
            trend = 'down'

    ctx_parts.append(f"\nPERFORMANCE (Performance dashboard):")
    ctx_parts.append(f"  Total: {total_contacts['cnt'] if total_contacts else 0} contacts, "
                     f"{total_groups['cnt'] if total_groups else 0} capital groups")
    ctx_parts.append(f"  Today: {tp_today['cnt'] if tp_today else 0} touchpoints")
    ctx_parts.append(f"  This week: {tw} touchpoints (last week: {lw}, trend: {trend})")
    ctx_parts.append(f"  Signals this week: {total_signals['cnt'] if total_signals else 0} (SignalStack)")
    ctx_parts.append(f"  Tasks: {tasks_completed['cnt'] if tasks_completed else 0} completed, "
                     f"{tasks_pending['cnt'] if tasks_pending else 0} pending")
    if overdue_tasks:
        ctx_parts.append(f"  OVERDUE ({len(overdue_tasks)}):")
        for ot in overdue_tasks:
            ctx_parts.append(f"    - {ot['title']}"
                             f"{' (' + ot['group_name'] + ')' if ot.get('group_name') else ''}"
                             f" due={str(ot['due_at'])[:10]}")

    ctx_parts.append(f"\nTODAY: {datetime.utcnow().strftime('%A, %B %d, %Y')}")

    # Proactive insights (data-driven)
    insights = _generate_proactive_insights()
    if insights:
        ctx_parts.append("\nSYSTEM INSIGHTS (computed from your data):")
        for ins in insights:
            ctx_parts.append(f"  ⚠ {ins}")

    # Interaction patterns (self-improvement)
    patterns = _get_interaction_patterns()
    if patterns:
        ctx_parts.append(f"\n{patterns}")

    # Chat history (session memory)
    if include_history:
        recent_chat = _get_recent_chat_summary()
        if recent_chat:
            ctx_parts.append(f"\nPRIOR CHAT THREAD:\n{recent_chat}")

    if extra_context:
        ctx_parts.append(f"\nADDITIONAL CONTEXT:\n{extra_context}")

    return "\n".join(ctx_parts)


def _get_recent_chat_summary():
    try:
        rows = fetch_all(
            """SELECT user_message, card_type, card_json, created_at
               FROM assistant_chat_log
               ORDER BY created_at DESC LIMIT 6""", []
        )
        if not rows:
            return ""
        rows.reverse()
        parts = []
        for r in rows:
            parts.append(f"User: {r['user_message'][:100]}")
            try:
                card = json.loads(r['card_json'])
                parts.append(f"Assistant ({r['card_type'].split('|')[0]}): {card.get('text', '')[:120]}")
            except Exception:
                parts.append(f"Assistant: [response]")
        return "\n".join(parts)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Natural-language CRM command parser
# ---------------------------------------------------------------------------

_CHANNEL_PATTERNS = [
    (r'\b(called|had a call|spoke with|spoke to|phone call|phoned)\b', 'call'),
    (r'\b(emailed|sent an email|email to|sent email)\b', 'email'),
    (r'\b(met with|had a meeting|meeting with|met at|in-person)\b', 'meeting'),
    (r'\b(texted|sent a text|sms|messaged)\b', 'text'),
    (r'\b(linkedin|connected on linkedin|linkedin message)\b', 'linkedin'),
    (r'\b(add note|noted|note that|add a note)\b', 'note'),
]

_STAGE_ALIASES = {
    'active': 'active', 'actively pursuing': 'active',
    'warm': 'warm', 'interested': 'warm',
    'cold': 'cold', 'dead': 'cold', 'inactive': 'cold',
    'nurture': 'nurture', 'nurturing': 'nurture',
    'closing': 'closing', 'close': 'closing',
    'closed': 'closed', 'won': 'closed', 'closed won': 'closed',
    'lost': 'lost', 'closed lost': 'lost', 'passed': 'lost',
    'new': 'new', 'prospect': 'new', 'lead': 'new',
    'qualified': 'qualified', 'researching': 'researching',
    'contacted': 'contacted', 'outreach': 'contacted',
    'loi': 'loi', 'under contract': 'under_contract',
}

_WEEKDAYS = {
    'monday': 0, 'tuesday': 1, 'wednesday': 2, 'thursday': 3,
    'friday': 4, 'saturday': 5, 'sunday': 6,
}


def _detect_channel(text_lower):
    for pattern, channel in _CHANNEL_PATTERNS:
        if re.search(pattern, text_lower):
            return channel
    return None


def _resolve_date_phrase(phrase):
    """Parse relative date phrases into YYYY-MM-DD strings."""
    phrase = phrase.lower().strip()
    today = datetime.utcnow()

    if phrase in ('today', 'now'):
        return today.strftime('%Y-%m-%d')
    if phrase in ('tomorrow', 'tmrw'):
        return (today + timedelta(days=1)).strftime('%Y-%m-%d')
    if phrase == 'yesterday':
        return (today - timedelta(days=1)).strftime('%Y-%m-%d')

    m = re.match(r'(?:in\s+)?(\d+)\s*(day|week|month)s?', phrase)
    if m:
        n, unit = int(m.group(1)), m.group(2)
        if unit == 'day':
            return (today + timedelta(days=n)).strftime('%Y-%m-%d')
        if unit == 'week':
            return (today + timedelta(weeks=n)).strftime('%Y-%m-%d')
        if unit == 'month':
            return (today + timedelta(days=n * 30)).strftime('%Y-%m-%d')

    if phrase == 'next week':
        return (today + timedelta(weeks=1)).strftime('%Y-%m-%d')
    if phrase == 'next month':
        return (today + timedelta(days=30)).strftime('%Y-%m-%d')

    for day_name, day_num in _WEEKDAYS.items():
        if f'next {day_name}' in phrase or phrase == day_name:
            days_ahead = day_num - today.weekday()
            if days_ahead <= 0:
                days_ahead += 7
            return (today + timedelta(days=days_ahead)).strftime('%Y-%m-%d')

    return None


def _detect_follow_up(text_lower):
    """Extract follow-up date from text like 'follow up in 2 weeks'."""
    patterns = [
        r'follow[\s-]?up\s+(?:in\s+)?(.+?)(?:\.|$|and\b|,)',
        r'check\s+back\s+(?:in\s+)?(.+?)(?:\.|$|and\b|,)',
        r'remind\s+me\s+(?:in\s+)?(.+?)(?:\.|$|and\b|,)',
        r'circle\s+back\s+(?:in\s+)?(.+?)(?:\.|$|and\b|,)',
    ]
    for pat in patterns:
        m = re.search(pat, text_lower)
        if m:
            phrase = m.group(1).strip()
            resolved = _resolve_date_phrase(phrase)
            if resolved:
                return resolved
    return None


def _detect_stage_change(text_lower):
    """Detect stage change directives like 'move them to active'."""
    patterns = [
        r'(?:move|change|update|set)\s+(?:them|it|stage|status)?\s*(?:to|as)\s+["\']?(\w[\w\s]*?)["\']?\s*(?:\.|$|and\b|,)',
        r'mark\s+(?:them|it|as)\s+["\']?(\w[\w\s]*?)["\']?\s*(?:\.|$|and\b|,)',
    ]
    for pat in patterns:
        m = re.search(pat, text_lower)
        if m:
            raw = m.group(1).strip().lower()
            return _STAGE_ALIASES.get(raw)
    return None


def _find_groups_fuzzy(text):
    """Find capital groups whose names appear as substrings in user text."""
    all_groups = fetch_all(
        "SELECT id, name, relationship_status, warmth_score FROM capital_groups ORDER BY name",
        []
    )
    text_lower = text.lower()
    matches = []
    for g in all_groups:
        gname = (g.get('name') or '').lower()
        if len(gname) >= 3 and gname in text_lower:
            matches.append(g)
    matches.sort(key=lambda g: len(g.get('name', '')), reverse=True)
    return matches


def _find_contacts_fuzzy(text, group_id=None):
    """Find contacts whose names appear in user text, optionally scoped to a group."""
    if group_id:
        contacts = fetch_all(
            """SELECT c.*, g.name as group_name FROM prospecting_contacts c
               LEFT JOIN capital_groups g ON c.group_id = g.id
               WHERE c.group_id = ?""",
            [group_id]
        )
    else:
        contacts = fetch_all(
            """SELECT c.*, g.name as group_name FROM prospecting_contacts c
               LEFT JOIN capital_groups g ON c.group_id = g.id""",
            []
        )
    text_lower = text.lower()
    matches = []
    for c in contacts:
        first = (c.get('first_name') or '').lower()
        last = (c.get('last_name') or '').lower()
        full = f"{first} {last}".strip()
        if full and len(full) >= 2 and full in text_lower:
            matches.append(c)
        elif first and len(first) >= 3 and first in text_lower:
            matches.append(c)
    return matches


def _extract_summary(text, group_name=None, contact_name=None):
    """Strip command fragments, keep the descriptive notes."""
    cleaned = text
    strip_patterns = [
        r'(?:called|emailed|met with|texted|spoke (?:with|to)|had a (?:call|meeting) (?:with)?)\s*',
        r'follow[\s-]?up\s+(?:in\s+)?[\w\s]+(?:\.|$)',
        r'check\s+back\s+(?:in\s+)?[\w\s]+(?:\.|$)',
        r'(?:move|change|update|set)\s+(?:them|it|stage|status)?\s*(?:to|as)\s+\w+\s*',
        r'mark\s+(?:them|it|as)\s+\w+',
        r'\btoday\b|\byesterday\b',
    ]
    for pat in strip_patterns:
        cleaned = re.sub(pat, '', cleaned, flags=re.IGNORECASE)
    if group_name:
        cleaned = re.sub(re.escape(group_name), '', cleaned, flags=re.IGNORECASE)
    if contact_name:
        cleaned = re.sub(re.escape(contact_name), '', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'\s*[.,]+\s*', '. ', cleaned).strip(' .')
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    return cleaned if len(cleaned) > 2 else ''


def _parse_crm_command(text):
    """
    Parse a natural-language CRM command into structured operations.
    Returns: { 'status': 'ok'|'ambiguous'|'no_entity', 'ops': {...}, 'ambiguous': {...} }
    """
    text_lower = text.lower()

    groups = _find_groups_fuzzy(text)
    contacts = _find_contacts_fuzzy(text)

    group = None
    contact = None

    if len(groups) == 1:
        group = groups[0]
        scoped_contacts = _find_contacts_fuzzy(text, group['id'])
        if len(scoped_contacts) == 1:
            contact = scoped_contacts[0]
        elif len(scoped_contacts) > 1:
            return {
                'status': 'ambiguous',
                'ambiguous': {
                    'type': 'contact',
                    'group': group,
                    'options': scoped_contacts[:5],
                    'original_message': text,
                }
            }
    elif len(groups) > 1:
        return {
            'status': 'ambiguous',
            'ambiguous': {
                'type': 'group',
                'options': groups[:5],
                'original_message': text,
            }
        }
    elif not groups and contacts:
        if len(contacts) == 1:
            contact = contacts[0]
            if contact.get('group_id'):
                group = fetch_one("SELECT * FROM capital_groups WHERE id = ?",
                                  [contact['group_id']])
        elif len(contacts) > 1:
            return {
                'status': 'ambiguous',
                'ambiguous': {
                    'type': 'contact',
                    'options': contacts[:5],
                    'original_message': text,
                }
            }

    if not group and not contact:
        return {'status': 'no_entity'}

    channel = _detect_channel(text_lower)
    follow_up_date = _detect_follow_up(text_lower)
    stage = _detect_stage_change(text_lower)

    group_name = group['name'] if group else ''
    contact_name = ''
    if contact:
        contact_name = f"{contact.get('first_name', '')} {contact.get('last_name', '')}".strip()

    summary = _extract_summary(text, group_name, contact_name)

    ops = {
        'group_id': group['id'] if group else None,
        'group_name': group_name,
        'contact_id': contact['id'] if contact else None,
        'contact_name': contact_name,
    }

    if channel:
        ops['touchpoint'] = {
            'channel': channel,
            'summary': summary or f"{channel.title()} with {contact_name or group_name}",
            'date': datetime.utcnow().strftime('%Y-%m-%d'),
        }

    if follow_up_date:
        ops['follow_up'] = {
            'title': f"Follow up with {group_name or contact_name}",
            'due_date': follow_up_date,
        }

    if stage:
        ops['stage_change'] = {
            'entity': 'group' if group else 'contact',
            'new_stage': stage,
        }

    if summary:
        ops['notes'] = summary

    has_action = any(k in ops for k in ('touchpoint', 'follow_up', 'stage_change'))
    if not has_action:
        return {'status': 'no_entity'}

    return {'status': 'ok', 'ops': ops}


def _build_preview_card(ops, original_msg):
    """Build a CrmUpdatePreviewCard from parsed operations."""
    items = []

    if ops.get('touchpoint'):
        tp = ops['touchpoint']
        items.append(f"Log {tp['channel']} touchpoint: \"{tp['summary']}\"")
    if ops.get('stage_change'):
        sc = ops['stage_change']
        items.append(f"Move {ops.get('group_name') or ops.get('contact_name', '')} to {sc['new_stage']}")
    if ops.get('follow_up'):
        fu = ops['follow_up']
        items.append(f"Create follow-up due {fu['due_date']}: \"{fu['title']}\"")

    text = f"**{ops.get('group_name') or ops.get('contact_name', 'Unknown')}** — "
    text += "here's what I'll update:"

    batch_params = {
        'group_id': ops.get('group_id'),
        'group_name': ops.get('group_name'),
        'contact_id': ops.get('contact_id'),
        'contact_name': ops.get('contact_name'),
    }
    if ops.get('touchpoint'):
        batch_params['touchpoint'] = ops['touchpoint']
    if ops.get('follow_up'):
        batch_params['follow_up'] = ops['follow_up']
    if ops.get('stage_change'):
        batch_params['stage_change'] = ops['stage_change']
    if ops.get('notes'):
        batch_params['notes'] = ops['notes']

    return {
        'type': 'CrmUpdatePreviewCard',
        'text': text,
        'source': original_msg,
        'data': {
            'items': items,
            'group_name': ops.get('group_name', ''),
            'contact_name': ops.get('contact_name', ''),
            'touchpoint': ops.get('touchpoint'),
            'follow_up': ops.get('follow_up'),
            'stage_change': ops.get('stage_change'),
            'notes': ops.get('notes', ''),
        },
        'actions': [
            {'id': 'confirm_batch', 'label': 'Confirm All', 'action': 'execute_batch',
             'params': batch_params},
            {'id': 'cancel_batch', 'label': 'Cancel', 'action': 'cancel', 'params': {}},
        ]
    }


def _build_ambiguity_card(ambiguous_data, original_msg):
    """Build an AmbiguityCard when multiple entities match."""
    entity_type = ambiguous_data['type']
    options = ambiguous_data['options']

    if entity_type == 'group':
        text = f"I found {len(options)} matching companies. Which one did you mean?"
        choices = []
        for g in options:
            choices.append({
                'id': g['id'],
                'label': g['name'],
                'sublabel': f"Status: {g.get('relationship_status', '?')} · Warmth: {g.get('warmth_score', '?')}",
            })
    else:
        group = ambiguous_data.get('group')
        text = f"Multiple contacts found"
        if group:
            text += f" at {group['name']}"
        text += ". Which one?"
        choices = []
        for c in options:
            cname = f"{c.get('first_name', '')} {c.get('last_name', '')}".strip()
            choices.append({
                'id': c['id'],
                'label': cname,
                'sublabel': f"{c.get('title', '')} · {c.get('group_name', '')}".strip(' ·'),
            })

    actions = []
    for ch in choices:
        resolve_params = {
            'entity_type': entity_type,
            'entity_id': ch['id'],
            'entity_name': ch['label'],
            'original_message': original_msg,
        }
        if entity_type == 'contact' and ambiguous_data.get('group'):
            resolve_params['group_id'] = ambiguous_data['group']['id']
            resolve_params['group_name'] = ambiguous_data['group']['name']
        actions.append({
            'id': f"pick_{ch['id'][:8]}",
            'label': ch['label'],
            'sublabel': ch.get('sublabel', ''),
            'action': 'resolve_ambiguity',
            'params': resolve_params,
        })

    return {
        'type': 'AmbiguityCard',
        'text': text,
        'source': original_msg,
        'data': {'entity_type': entity_type, 'choices': choices},
        'actions': actions,
    }


# ---------------------------------------------------------------------------
# Slash command pre-processor
# ---------------------------------------------------------------------------

def _preprocess_slash(text):
    text = text.strip()
    if not text.startswith('/'):
        return text, None

    parts = text.split(None, 1)
    cmd = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else ''

    extra_ctx = None

    if cmd == '/draft':
        if arg:
            contact = _find_contact(arg)
            if contact:
                signal = _latest_signal_for(contact.get('group_id'), contact.get('id'))
                extra_ctx = _format_contact_detail(contact, signal)
                return f"Draft outreach for {arg}. Use the contact details and latest signal below.", extra_ctx
        return f"Draft outreach for {arg or 'my warmest contact'}.", extra_ctx

    if cmd == '/log':
        return f"Log a touchpoint: {arg}" if arg else "Help me log a touchpoint.", extra_ctx

    if cmd == '/next':
        return ("What is the single most important action right now? "
                "Be specific with names and companies. Use a NextActionCard."), extra_ctx

    if cmd == '/brief':
        return ("Daily briefing. Include: today's stats vs last week, overdue items, "
                "going-cold contacts, top 3 priorities, and any system insights. "
                "Use a PerformanceInsightCard."), extra_ctx

    if cmd == '/export':
        return f"Export {arg or 'contacts'} data.", extra_ctx

    if cmd == '/signal':
        if arg:
            signals = _find_signals_for(arg)
            if signals:
                extra_ctx = "MATCHING SIGNALS:\n" + "\n".join(
                    f"- {s['title']} (importance={s.get('importance', '?')}) "
                    f"url={s.get('source_url', 'N/A')} summary={str(s.get('summary', ''))[:80]}"
                    for s in signals[:5]
                )
        return f"Analyze the latest signals for {arg or 'all companies'}. Use a SignalInsightCard.", extra_ctx

    if cmd == '/sprint':
        return ("Start a focused work sprint. My top 5 prioritized actions for today. "
                "Rank by: overdue tasks > going cold high-warmth > unactioned signals > "
                "scheduled follow-ups. Use a NextActionCard."), extra_ctx

    if cmd == '/plan':
        if arg:
            return f"Create a strategic plan for: {arg}. Use a StrategyCard or ExecutionPlanCard.", extra_ctx
        return "What should I be planning right now? Use a StrategyCard.", extra_ctx

    if cmd == '/fix':
        if arg:
            return f"Diagnose and suggest a fix for: {arg}. Use a FixCard.", extra_ctx
        return "Is anything broken or suboptimal in my workflow? Use a FixCard.", extra_ctx

    return text, extra_ctx


# ---------------------------------------------------------------------------
# Context helpers
# ---------------------------------------------------------------------------

def _find_contact(name_query):
    q = f"%{name_query.strip().lower()}%"
    return fetch_one(
        """SELECT c.*, g.name as group_name
           FROM prospecting_contacts c
           LEFT JOIN capital_groups g ON c.group_id = g.id
           WHERE LOWER(c.first_name || ' ' || c.last_name) LIKE ?
              OR LOWER(c.first_name) LIKE ?
              OR LOWER(c.last_name) LIKE ?
           ORDER BY c.last_touch_at DESC NULLS LAST LIMIT 1""",
        [q, q, q]
    )


def _find_group(name_query):
    q = f"%{name_query.strip().lower()}%"
    return fetch_one(
        "SELECT * FROM capital_groups WHERE LOWER(name) LIKE ? ORDER BY warmth_score DESC LIMIT 1",
        [q]
    )


def _latest_signal_for(group_id=None, contact_id=None):
    if group_id:
        return fetch_one(
            "SELECT * FROM prospecting_signals WHERE group_id = ? ORDER BY detected_at DESC LIMIT 1",
            [group_id]
        )
    if contact_id:
        return fetch_one(
            "SELECT * FROM prospecting_signals WHERE contact_id = ? ORDER BY detected_at DESC LIMIT 1",
            [contact_id]
        )
    return None


def _find_signals_for(name_query):
    group = _find_group(name_query)
    if group:
        return fetch_all(
            "SELECT * FROM prospecting_signals WHERE group_id = ? ORDER BY detected_at DESC LIMIT 5",
            [group['id']]
        )
    return fetch_all(
        "SELECT * FROM prospecting_signals ORDER BY detected_at DESC LIMIT 5", []
    )


def _format_contact_detail(contact, signal=None):
    if not contact:
        return ""
    name = f"{contact.get('first_name', '')} {contact.get('last_name', '')}".strip()
    lines = [f"TARGET CONTACT: {name}"]
    lines.append(f"  id={contact['id']}")
    if contact.get('title'):
        lines.append(f"  title={contact['title']}")
    if contact.get('group_name'):
        lines.append(f"  company={contact['group_name']}")
    if contact.get('email'):
        lines.append(f"  email={contact['email']}")
    if contact.get('phone'):
        lines.append(f"  phone={contact['phone']}")
    lines.append(f"  stage={contact.get('relationship_stage', 'cold')}")
    if contact.get('last_touch_at'):
        lines.append(f"  last_touch={str(contact['last_touch_at'])[:10]}")
    if contact.get('notes'):
        lines.append(f"  notes={contact['notes'][:200]}")

    tps = fetch_all(
        """SELECT channel, subject, summary, occurred_at
           FROM prospecting_touchpoints WHERE contact_id = ?
           ORDER BY occurred_at DESC LIMIT 5""",
        [contact['id']]
    )
    if tps:
        lines.append("  RECENT TOUCHPOINTS:")
        for t in tps:
            lines.append(
                f"    - {t.get('channel', 'note')}: "
                f"{t.get('subject') or str(t.get('summary', ''))[:60]} "
                f"({str(t.get('occurred_at', ''))[:10]})"
            )

    if signal:
        lines.append(f"  LATEST SIGNAL: {signal.get('title', '')} — {str(signal.get('summary', ''))[:100]}")
        if signal.get('source_url'):
            lines.append(f"    url={signal['source_url']}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Chat endpoint
# ---------------------------------------------------------------------------

@assistant_bp.route('/chat', methods=['POST'])
def chat():
    data = request.get_json(silent=True) or {}
    messages = data.get('messages', [])
    page_context = data.get('page_context', {})

    if not messages:
        return jsonify({'error': 'No messages provided'}), 400

    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        return jsonify({
            'role': 'assistant', 'content': '',
            'card': {
                'type': 'ErrorCard',
                'text': 'AI assistant is not configured.',
                'data': {'error': 'ANTHROPIC_API_KEY not set',
                         'suggestion': 'Set it in your environment variables.'},
                'actions': []
            }
        })

    last_msg = messages[-1].get('content', '') if messages else ''
    processed_msg, extra_ctx = _preprocess_slash(last_msg)

    intent = _classify_intent(last_msg)
    mode = INTENT_TO_MODE.get(intent, 'strategic')
    max_tokens = MODE_MAX_TOKENS.get(mode, 2000)

    # CRM update intercept — parse locally, skip Claude call
    if intent == 'crm_update':
        parsed = _parse_crm_command(last_msg)
        if parsed['status'] == 'ok':
            card = _build_preview_card(parsed['ops'], last_msg)
            _persist_chat(last_msg, card, 'crm_update', 'execution')
            return jsonify({
                'role': 'assistant', 'content': card['text'],
                'card': card, 'intent': 'crm_update', 'mode': 'execution'
            })
        elif parsed['status'] == 'ambiguous':
            card = _build_ambiguity_card(parsed['ambiguous'], last_msg)
            _persist_chat(last_msg, card, 'crm_update', 'execution')
            return jsonify({
                'role': 'assistant', 'content': card['text'],
                'card': card, 'intent': 'crm_update', 'mode': 'execution'
            })
        # 'no_entity' falls through to Claude

    # Page-aware context
    page_extra = ""
    if page_context.get('active_tab'):
        page_extra += f"\nUser is on the '{page_context['active_tab']}' page."
    if page_context.get('selected_contact_id'):
        contact = fetch_one(
            """SELECT c.*, g.name as group_name FROM prospecting_contacts c
               LEFT JOIN capital_groups g ON c.group_id = g.id
               WHERE c.id = ?""",
            [page_context['selected_contact_id']]
        )
        if contact:
            page_extra += "\n" + _format_contact_detail(
                contact, _latest_signal_for(contact.get('group_id'), contact['id'])
            )
    if page_context.get('selected_group_id'):
        group = fetch_one(
            "SELECT * FROM capital_groups WHERE id = ?",
            [page_context['selected_group_id']]
        )
        if group:
            page_extra += (
                f"\nSelected company: {group['name']} "
                f"(id={group['id'][:8]}, status={group.get('relationship_status')}, "
                f"warmth={group.get('warmth_score')})"
            )

    combined_extra = (extra_ctx or '') + page_extra
    mode_hint = f"\n\nACTIVE MODE: {mode.upper()}\nINTENT: {intent}"
    combined_extra = (combined_extra or '') + mode_hint

    context = _build_context(combined_extra if combined_extra.strip() else None)
    system = SYSTEM_PROMPT + "\n\n--- CURRENT DATA CONTEXT ---\n" + context

    api_messages = []
    for m in messages[:-1]:
        api_messages.append({
            'role': m.get('role', 'user'),
            'content': m.get('content', '')
        })
    api_messages.append({'role': 'user', 'content': processed_msg})
    api_messages = api_messages[-20:]

    try:
        client = anthropic.Anthropic(api_key=api_key)
        resp = client.messages.create(
            model='claude-sonnet-4-20250514',
            max_tokens=max_tokens,
            system=system,
            messages=api_messages
        )
        reply = resp.content[0].text if resp.content else ''

        card = None
        if '<card>' in reply and '</card>' in reply:
            try:
                card_str = reply.split('<card>')[1].split('</card>')[0].strip()
                card = json.loads(card_str)
            except (json.JSONDecodeError, IndexError):
                pass

        action = None
        if not card and '<action>' in reply and '</action>' in reply:
            try:
                action_str = reply.split('<action>')[1].split('</action>')[0].strip()
                action = json.loads(action_str)
                card = _action_to_card(action, reply)
            except (json.JSONDecodeError, IndexError):
                pass

        if not card:
            clean = re.sub(r'<card>[\s\S]*?</card>', '', reply).strip()
            clean = re.sub(r'<action>[\s\S]*?</action>', '', clean).strip()
            card = {
                'type': 'TextCard', 'text': clean or reply,
                'source': None, 'data': {}, 'actions': []
            }

        _persist_chat(messages[-1].get('content', ''), card, intent, mode)

        return jsonify({
            'role': 'assistant',
            'content': card.get('text', ''),
            'card': card,
            'action': action,
            'intent': intent,
            'mode': mode
        })
    except anthropic.APIError as e:
        return jsonify({
            'role': 'assistant', 'content': str(e),
            'card': {
                'type': 'ErrorCard', 'text': 'AI service error.',
                'data': {'error': str(e), 'suggestion': 'Try again in a moment.'},
                'actions': []
            }
        })
    except Exception as e:
        return jsonify({
            'role': 'assistant', 'content': str(e),
            'card': {
                'type': 'ErrorCard', 'text': 'Something went wrong.',
                'data': {'error': str(e), 'suggestion': 'Try rephrasing your request.'},
                'actions': []
            }
        })


def _action_to_card(action, full_reply):
    a_type = action.get('action', '')
    clean = re.sub(r'<action>[\s\S]*?</action>', '', full_reply).strip()

    if a_type in ('draft_message', 'draft_outreach'):
        return {
            'type': 'DraftCard',
            'text': clean or 'Here\'s a draft for you.',
            'source': action.get('context_note'),
            'data': {
                'channel': action.get('channel', 'email'),
                'target_name': action.get('target_name', ''),
                'target_id': action.get('target_id', ''),
                'subject': action.get('subject', ''),
                'body': action.get('body', ''),
                'signal_ref': action.get('signal_ref', '')
            },
            'actions': [
                {'id': 'copy_draft', 'label': 'Copy', 'action': 'copy_text', 'params': {}},
                {'id': 'log_tp', 'label': 'Log Touchpoint', 'action': 'log_touchpoint', 'params': {
                    'contact_id': action.get('target_id', ''),
                    'channel': action.get('channel', 'email'),
                    'summary': f"Outreach to {action.get('target_name', '')}"
                }}
            ]
        }

    if a_type == 'log_touchpoint':
        return {
            'type': 'TouchpointLogCard',
            'text': clean or 'Ready to log this touchpoint.',
            'source': None,
            'data': {
                'contact_name': action.get('contact_name', ''),
                'contact_id': action.get('contact_id', ''),
                'group_id': action.get('group_id', ''),
                'channel': action.get('type', 'note'),
                'summary': action.get('notes', ''),
                'direction': 'outbound'
            },
            'actions': [
                {'id': 'confirm_log', 'label': 'Log It', 'action': 'log_touchpoint', 'params': action}
            ]
        }

    if a_type == 'update_stage':
        return {
            'type': 'ConfirmationCard',
            'text': clean or f"Update stage to {action.get('new_stage', '?')}?",
            'source': None,
            'data': {'what': 'stage update', 'result': 'pending'},
            'actions': [
                {'id': 'confirm_stage', 'label': 'Confirm', 'action': 'update_stage', 'params': action}
            ]
        }

    return {
        'type': 'TextCard', 'text': clean or 'Action parsed.',
        'source': None, 'data': {},
        'actions': [{'id': 'exec', 'label': 'Execute', 'action': a_type, 'params': action}]
    }


# ---------------------------------------------------------------------------
# Action execution + interaction tracking
# ---------------------------------------------------------------------------

@assistant_bp.route('/execute-action', methods=['POST'])
def execute_action():
    data = request.get_json(silent=True) or {}
    action = data.get('action')
    params = data.get('params', {})
    if not action:
        return jsonify({'success': False, 'card': {
            'type': 'ErrorCard', 'text': 'No action specified.',
            'data': {'error': 'Missing action'}, 'actions': []
        }}), 400

    # Track this interaction for self-improvement
    _track_interaction('action_executed', action, params)

    try:
        if action == 'log_touchpoint':
            return _exec_log_touchpoint(params)
        if action == 'update_stage':
            return _exec_update_stage(params)
        if action in ('draft_message', 'draft_outreach', 'copy_text'):
            return jsonify({'success': True, 'card': {
                'type': 'ConfirmationCard',
                'text': 'Draft copied to clipboard.',
                'data': {'what': 'copy', 'result': 'success'}, 'actions': []
            }})
        if action == 'create_followup':
            return _exec_create_followup(params)
        if action == 'complete_task':
            return _exec_complete_task(params)
        if action == 'export':
            return _exec_export(params)
        if action == 'execute_batch':
            return _exec_batch(params)
        if action == 'resolve_ambiguity':
            return _exec_resolve_ambiguity(params)
        if action == 'cancel':
            return jsonify({'success': True, 'card': {
                'type': 'ConfirmationCard', 'text': 'Cancelled.',
                'data': {'what': 'cancel', 'result': 'cancelled'}, 'actions': []
            }})

        return jsonify({'success': False, 'card': {
            'type': 'ErrorCard', 'text': f'Unknown action: {action}',
            'data': {'error': f'No handler for {action}'}, 'actions': []
        }}), 400
    except Exception as e:
        return jsonify({'success': False, 'card': {
            'type': 'ErrorCard', 'text': 'Action failed.',
            'data': {'error': str(e), 'suggestion': 'Try again.'}, 'actions': []
        }}), 500


def _exec_log_touchpoint(params):
    contact_id = params.get('contact_id')
    group_id = params.get('group_id')
    if not contact_id and not group_id:
        return jsonify({'success': False, 'card': {
            'type': 'ErrorCard', 'text': 'Need a contact or company to log against.',
            'data': {'error': 'contact_id or group_id required'}, 'actions': []
        }}), 400

    tp_id = new_id()
    execute(
        """INSERT INTO prospecting_touchpoints
           (id, contact_id, group_id, channel, direction, subject, summary, occurred_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
        [tp_id, contact_id, group_id,
         params.get('channel', 'note'),
         params.get('direction', 'outbound'),
         params.get('subject', ''),
         params.get('summary', params.get('notes', ''))]
    )
    if contact_id:
        execute("UPDATE prospecting_contacts SET last_touch_at = CURRENT_TIMESTAMP WHERE id = ?",
                [contact_id])
    if group_id:
        execute("UPDATE capital_groups SET last_contacted_at = CURRENT_TIMESTAMP WHERE id = ?",
                [group_id])
        tp2 = new_id()
        execute(
            """INSERT INTO capital_group_touchpoints (id, capital_group_id, type, notes, outcome, occurred_at)
               VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
            [tp2, group_id, params.get('channel', 'note'),
             params.get('summary', params.get('notes', '')), '']
        )

    return jsonify({'success': True, 'card': {
        'type': 'ConfirmationCard',
        'text': 'Touchpoint logged successfully.',
        'data': {'what': 'touchpoint', 'result': 'logged', 'entity_id': tp_id},
        'actions': []
    }})


def _exec_update_stage(params):
    group_id = params.get('group_id')
    new_stage = params.get('new_stage')
    contact_id = params.get('contact_id')

    if contact_id and not group_id:
        execute(
            "UPDATE prospecting_contacts SET relationship_stage = ? WHERE id = ?",
            [new_stage, contact_id]
        )
        return jsonify({'success': True, 'card': {
            'type': 'ConfirmationCard', 'text': f'Contact stage updated to {new_stage}.',
            'data': {'what': 'stage', 'result': new_stage, 'entity_id': contact_id},
            'actions': []
        }})

    if not group_id or not new_stage:
        return jsonify({'success': False, 'card': {
            'type': 'ErrorCard', 'text': 'Missing group_id or new_stage.',
            'data': {'error': 'Incomplete params'}, 'actions': []
        }}), 400
    execute(
        "UPDATE capital_groups SET relationship_status = ? WHERE id = ?",
        [new_stage, group_id]
    )
    return jsonify({'success': True, 'card': {
        'type': 'ConfirmationCard', 'text': f'Stage updated to {new_stage}.',
        'data': {'what': 'stage', 'result': new_stage, 'entity_id': group_id},
        'actions': []
    }})


def _exec_create_followup(params):
    title = params.get('title', 'Follow up')
    due_date = params.get('due_date')
    if not due_date:
        due_date = (datetime.utcnow() + timedelta(days=3)).strftime('%Y-%m-%d')
    task_id = new_id()
    execute(
        """INSERT INTO prospecting_tasks
           (id, capital_group_id, type, title, status, priority, due_at, created_at)
           VALUES (?, ?, 'follow_up', ?, 'pending', 7, ?, CURRENT_TIMESTAMP)""",
        [task_id, params.get('group_id'), title, due_date]
    )
    return jsonify({'success': True, 'card': {
        'type': 'ConfirmationCard',
        'text': f'Follow-up created: "{title}" due {due_date}.',
        'data': {'what': 'follow_up', 'result': 'created', 'entity_id': task_id},
        'actions': []
    }})


def _exec_complete_task(params):
    task_id = params.get('task_id')
    if not task_id:
        return jsonify({'success': False, 'card': {
            'type': 'ErrorCard', 'text': 'No task ID provided.',
            'data': {'error': 'task_id required'}, 'actions': []
        }}), 400
    execute(
        "UPDATE prospecting_tasks SET status = 'completed', completed_at = CURRENT_TIMESTAMP WHERE id = ?",
        [task_id]
    )
    return jsonify({'success': True, 'card': {
        'type': 'ConfirmationCard', 'text': 'Task marked complete.',
        'data': {'what': 'task', 'result': 'completed', 'entity_id': task_id},
        'actions': []
    }})


def _exec_export(params):
    export_type = params.get('export_type', 'contacts')
    urls = {
        'contacts': '/api/prospecting/contacts/export',
        'capital_partners': '/api/prospecting/capital-groups-export',
        'underwriting': '/api/underwriting/export?mode=latest',
        'prospects': '/api/export',
    }
    url = urls.get(export_type, urls['contacts'])
    return jsonify({'success': True, 'card': {
        'type': 'ExportCard',
        'text': f'Your {export_type} export is ready.',
        'data': {'export_type': export_type, 'url': url,
                 'filename': f"{export_type}_{datetime.utcnow().strftime('%Y-%m-%d')}"},
        'actions': [
            {'id': 'download', 'label': 'Download', 'action': 'download', 'params': {'url': url}}
        ]
    }})


def _exec_batch(params):
    """Execute a batch of CRM operations from a confirmed preview card."""
    results = []
    group_id = params.get('group_id')
    contact_id = params.get('contact_id')
    group_name = params.get('group_name', '')
    contact_name = params.get('contact_name', '')

    # 1) Log touchpoint (with dedup — check for same channel+date)
    if params.get('touchpoint'):
        tp = params['touchpoint']
        today = tp.get('date', datetime.utcnow().strftime('%Y-%m-%d'))
        existing = None
        if contact_id:
            existing = fetch_one(
                """SELECT id FROM prospecting_touchpoints
                   WHERE contact_id = ? AND channel = ? AND DATE(occurred_at) = ?""",
                [contact_id, tp['channel'], today]
            )
        elif group_id:
            existing = fetch_one(
                """SELECT id FROM capital_group_touchpoints
                   WHERE capital_group_id = ? AND type = ? AND DATE(occurred_at) = ?""",
                [group_id, tp['channel'], today]
            )
        if existing:
            results.append(f"Touchpoint already exists for today — skipped duplicate")
        else:
            tp_id = new_id()
            execute(
                """INSERT INTO prospecting_touchpoints
                   (id, contact_id, group_id, channel, direction, subject, summary, occurred_at)
                   VALUES (?, ?, ?, ?, 'outbound', ?, ?, CURRENT_TIMESTAMP)""",
                [tp_id, contact_id, group_id, tp['channel'], '', tp.get('summary', '')]
            )
            if contact_id:
                execute("UPDATE prospecting_contacts SET last_touch_at = CURRENT_TIMESTAMP WHERE id = ?",
                        [contact_id])
            if group_id:
                execute("UPDATE capital_groups SET last_contacted_at = CURRENT_TIMESTAMP WHERE id = ?",
                        [group_id])
                tp2 = new_id()
                execute(
                    """INSERT INTO capital_group_touchpoints (id, capital_group_id, type, notes, outcome, occurred_at)
                       VALUES (?, ?, ?, ?, '', CURRENT_TIMESTAMP)""",
                    [tp2, group_id, tp['channel'], tp.get('summary', '')]
                )
            results.append(f"Logged {tp['channel']} touchpoint")

    # 2) Stage change
    if params.get('stage_change'):
        sc = params['stage_change']
        new_stage = sc['new_stage']
        if sc.get('entity') == 'contact' and contact_id:
            execute("UPDATE prospecting_contacts SET relationship_stage = ? WHERE id = ?",
                    [new_stage, contact_id])
            results.append(f"Updated {contact_name} stage to {new_stage}")
        elif group_id:
            execute("UPDATE capital_groups SET relationship_status = ? WHERE id = ?",
                    [new_stage, group_id])
            results.append(f"Updated {group_name} status to {new_stage}")

    # 3) Follow-up task
    if params.get('follow_up'):
        fu = params['follow_up']
        task_id = new_id()
        execute(
            """INSERT INTO prospecting_tasks
               (id, capital_group_id, type, title, status, priority, due_at, created_at)
               VALUES (?, ?, 'follow_up', ?, 'pending', 7, ?, CURRENT_TIMESTAMP)""",
            [task_id, group_id, fu['title'], fu['due_date']]
        )
        results.append(f"Created follow-up due {fu['due_date']}")

    summary_text = " · ".join(results) if results else "No changes made"
    return jsonify({'success': True, 'card': {
        'type': 'ConfirmationCard',
        'text': f'Done! {summary_text}',
        'data': {'what': 'batch_update', 'result': 'success',
                 'details': results},
        'actions': []
    }})


def _exec_resolve_ambiguity(params):
    """Re-run NL parsing with the user's entity choice resolved."""
    original_msg = params.get('original_message', '')
    entity_type = params.get('entity_type', '')
    entity_id = params.get('entity_id', '')
    entity_name = params.get('entity_name', '')

    if not original_msg:
        return jsonify({'success': False, 'card': {
            'type': 'ErrorCard', 'text': 'Missing original message for re-parse.',
            'data': {'error': 'original_message required'}, 'actions': []
        }}), 400

    text_lower = original_msg.lower()
    channel = _detect_channel(text_lower)
    follow_up_date = _detect_follow_up(text_lower)
    stage = _detect_stage_change(text_lower)

    group_id = None
    group_name = ''
    contact_id = None
    contact_name = ''

    if entity_type == 'group':
        group_id = entity_id
        group_name = entity_name
        contacts = _find_contacts_fuzzy(original_msg, group_id)
        if len(contacts) == 1:
            contact_id = contacts[0]['id']
            contact_name = f"{contacts[0].get('first_name', '')} {contacts[0].get('last_name', '')}".strip()
    elif entity_type == 'contact':
        contact_id = entity_id
        contact_name = entity_name
        g_id = params.get('group_id')
        if g_id:
            group_id = g_id
            group_name = params.get('group_name', '')
        else:
            c = fetch_one("SELECT group_id FROM prospecting_contacts WHERE id = ?", [contact_id])
            if c and c.get('group_id'):
                group_id = c['group_id']
                g = fetch_one("SELECT name FROM capital_groups WHERE id = ?", [group_id])
                group_name = g['name'] if g else ''

    summary = _extract_summary(original_msg, group_name, contact_name)

    ops = {
        'group_id': group_id, 'group_name': group_name,
        'contact_id': contact_id, 'contact_name': contact_name,
    }
    if channel:
        ops['touchpoint'] = {
            'channel': channel,
            'summary': summary or f"{channel.title()} with {contact_name or group_name}",
            'date': datetime.utcnow().strftime('%Y-%m-%d'),
        }
    if follow_up_date:
        ops['follow_up'] = {
            'title': f"Follow up with {group_name or contact_name}",
            'due_date': follow_up_date,
        }
    if stage:
        ops['stage_change'] = {'entity': 'group' if group_id else 'contact', 'new_stage': stage}
    if summary:
        ops['notes'] = summary

    has_action = any(k in ops for k in ('touchpoint', 'follow_up', 'stage_change'))
    if not has_action:
        return jsonify({'success': False, 'card': {
            'type': 'ErrorCard', 'text': "Couldn't parse any actions from your message. Try rephrasing.",
            'data': {'error': 'No parseable actions'}, 'actions': []
        }}), 400

    card = _build_preview_card(ops, original_msg)
    return jsonify({'success': True, 'card': card})


# ---------------------------------------------------------------------------
# Interaction tracking (self-improvement loop)
# ---------------------------------------------------------------------------

def _track_interaction(event_type, action, params=None):
    """Log user interactions for pattern analysis."""
    try:
        execute(
            """INSERT INTO assistant_chat_log (id, user_message, card_type, card_json, created_at)
               VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)""",
            [new_id(),
             f"[{event_type}] {action}",
             f"ACTION:{action}",
             json.dumps(params or {})[:2000]]
        )
    except Exception:
        pass


@assistant_bp.route('/track', methods=['POST'])
def track_interaction():
    """Frontend calls this to report card views, ignores, and clicks."""
    data = request.get_json(silent=True) or {}
    event = data.get('event', 'unknown')
    card_type = data.get('card_type', '')
    action_id = data.get('action_id', '')

    _track_interaction(event, card_type, {'action_id': action_id})
    return jsonify({'ok': True})


# ---------------------------------------------------------------------------
# Chat persistence
# ---------------------------------------------------------------------------

def _persist_chat(user_msg, card, intent='unknown', mode='unknown'):
    try:
        execute(
            """INSERT INTO assistant_chat_log (id, user_message, card_type, card_json, created_at)
               VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)""",
            [new_id(), user_msg[:500],
             f"{card.get('type', 'TextCard')}|{intent}|{mode}",
             json.dumps(card)[:4000]]
        )
    except Exception:
        pass


@assistant_bp.route('/history', methods=['GET'])
def chat_history():
    rows = fetch_all(
        """SELECT user_message, card_type, card_json, created_at
           FROM assistant_chat_log
           WHERE card_type NOT LIKE 'ACTION:%'
           ORDER BY created_at DESC LIMIT 20""", []
    )
    rows.reverse()
    history = []
    for r in rows:
        history.append({'role': 'user', 'content': r['user_message']})
        try:
            card = json.loads(r['card_json'])
        except Exception:
            card = {'type': 'TextCard', 'text': '(history)', 'data': {}, 'actions': []}
        history.append({'role': 'assistant', 'content': card.get('text', ''), 'card': card})
    return jsonify({'history': history})
