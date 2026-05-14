/* Leo — Operator AI Chat Component (chat.js)
   Proactive intelligence layer with structured cards */
(function() {
'use strict';
var _apiBase = (typeof API_BASE !== 'undefined') ? API_BASE : (window.location.hostname === 'localhost' ? 'http://localhost:5000' : window.location.origin);
// Use _apiBase internally; also check the global each call in case it loaded later
function getApiBase() { return (typeof API_BASE !== 'undefined') ? API_BASE : _apiBase; }

var h = React.createElement;
var useState = React.useState;
var useEffect = React.useEffect;
var useRef = React.useRef;

// --- Card color/icon definitions ---
var CARD_COLORS = {
  DraftCard:              { bg: '#f0fdf4', border: '#bbf7d0', accent: '#15803d', icon: '✉️' },
  NextActionCard:         { bg: '#eff6ff', border: '#bfdbfe', accent: '#1d4ed8', icon: '🎯' },
  SignalCard:             { bg: '#fefce8', border: '#fde68a', accent: '#a16207', icon: '⚡' },
  ContactSummaryCard:     { bg: '#f0f9ff', border: '#bae6fd', accent: '#0369a1', icon: '👤' },
  CompanySummaryCard:     { bg: '#faf5ff', border: '#e9d5ff', accent: '#7c3aed', icon: '🏢' },
  TouchpointLogCard:      { bg: '#ecfdf5', border: '#a7f3d0', accent: '#059669', icon: '📝' },
  FollowUpCard:           { bg: '#fff7ed', border: '#fed7aa', accent: '#c2410c', icon: '📅' },
  ExportCard:             { bg: '#f8fafc', border: '#e2e8f0', accent: '#475569', icon: '⬇️' },
  ConfirmationCard:       { bg: '#f0fdf4', border: '#86efac', accent: '#16a34a', icon: '✅' },
  ErrorCard:              { bg: '#fef2f2', border: '#fecaca', accent: '#dc2626', icon: '⚠️' },
  TextCard:               { bg: '#f8fafc', border: '#e2e8f0', accent: '#64748b', icon: '💬' },
  StrategyCard:           { bg: '#faf5ff', border: '#d8b4fe', accent: '#7c3aed', icon: '🧠' },
  ClaudePromptCard:       { bg: '#f0f9ff', border: '#7dd3fc', accent: '#0284c7', icon: '🔧' },
  ContactInsightCard:     { bg: '#f0f9ff', border: '#bae6fd', accent: '#0369a1', icon: '🔍' },
  SignalInsightCard:      { bg: '#fefce8', border: '#fde68a', accent: '#a16207', icon: '📡' },
  PerformanceInsightCard: { bg: '#ecfdf5', border: '#6ee7b7', accent: '#059669', icon: '📊' },
  ExecutionPlanCard:      { bg: '#eff6ff', border: '#93c5fd', accent: '#1d4ed8', icon: '📋' },
  FixCard:                { bg: '#fef2f2', border: '#fca5a5', accent: '#b91c1c', icon: '🔧' },
  CrmUpdatePreviewCard:   { bg: '#f0fdf4', border: '#86efac', accent: '#059669', icon: '📋' },
  AmbiguityCard:          { bg: '#fefce8', border: '#fde68a', accent: '#d97706', icon: '❓' },
  DailyPlanCard:          { bg: '#f8fafc', border: '#e2e8f0', accent: '#0f172a', icon: '📅' },
  SprintCard:             { bg: '#eff6ff', border: '#bfdbfe', accent: '#1d4ed8', icon: '⚡' },
  InsightCard:            { bg: '#fffbeb', border: '#fde68a', accent: '#92400e', icon: '💡' },
  QueueCard:              { bg: '#f0f9ff', border: '#93c5fd', accent: '#1e40af', icon: '📋' },
  BatchDraftCard:         { bg: '#f0fdf4', border: '#86efac', accent: '#15803d', icon: '✉️' },
  ApprovalQueueCard:      { bg: '#fefce8', border: '#fde68a', accent: '#a16207', icon: '✅' },
  ProbabilityCard:        { bg: '#faf5ff', border: '#d8b4fe', accent: '#7c3aed', icon: '🎲' },
  RelationshipCard:       { bg: '#fdf2f8', border: '#fbcfe8', accent: '#be185d', icon: '🤝' },
  FunnelCard:             { bg: '#f0f9ff', border: '#bae6fd', accent: '#0369a1', icon: '📊' },
  PredictionCard:         { bg: '#ecfdf5', border: '#a7f3d0', accent: '#059669', icon: '🔮' },
  AutomationCard:         { bg: '#fffbeb', border: '#fde68a', accent: '#92400e', icon: '⚙️' },
  BriefCard:              { bg: '#f0f9ff', border: '#bae6fd', accent: '#0c4a6e', icon: '📰' },
  MeetingCard:            { bg: '#f0fdf4', border: '#bbf7d0', accent: '#15803d', icon: '📅' }
};

var SLASH_HINTS = [
  { cmd: '/draft', desc: 'Draft outreach', ex: '/draft Ethan' },
  { cmd: '/log', desc: 'Log touchpoint', ex: '/log Called about deal' },
  { cmd: '/next', desc: 'Top action', ex: '/next' },
  { cmd: '/brief', desc: 'Daily briefing', ex: '/brief' },
  { cmd: '/export', desc: 'Export data', ex: '/export contacts' },
  { cmd: '/signal', desc: 'Signal analysis', ex: '/signal Acme Corp' },
  { cmd: '/sprint', desc: 'Work sprint', ex: '/sprint' },
  { cmd: '/plan', desc: 'Strategic plan', ex: '/plan outreach strategy' },
  { cmd: '/fix', desc: 'Diagnose issue', ex: '/fix low response rate' },
  { cmd: '/queue', desc: 'Execution queue', ex: '/queue' },
  { cmd: '/approve', desc: 'Approval queue', ex: '/approve all' },
  { cmd: '/probability', desc: 'Deal score', ex: '/probability Acme' },
  { cmd: '/followups', desc: 'Follow-ups', ex: '/followups' },
  { cmd: '/signals', desc: 'Signal intel', ex: '/signals' },
  { cmd: '/relationship', desc: 'Relationship intel', ex: '/relationship Acme' },
  { cmd: '/funnel', desc: 'Conversion funnel', ex: '/funnel' },
  { cmd: '/predict', desc: 'Outcome prediction', ex: '/predict Acme' },
  { cmd: '/automate', desc: 'Automation scan', ex: '/automate' },
  { cmd: '/brief-pdf', desc: 'Daily brief PDF', ex: '/brief-pdf' },
  { cmd: '/patterns', desc: 'Pipeline patterns', ex: '/patterns' },
  { cmd: '/meeting', desc: 'Schedule meeting', ex: '/meeting John Smith' },
  { cmd: '/calendar', desc: 'Open calendar', ex: '/calendar' }
];

var MODE_LABELS = {
  conversational: '',
  strategic: 'Strategy',
  execution: 'Execute',
  analyst: 'Analyst',
  builder: 'Builder',
  coach: 'Coach'
};

var MODE_COLORS = {
  conversational: '#64748b',
  strategic: '#7c3aed',
  execution: '#16a34a',
  analyst: '#0369a1',
  builder: '#0284c7',
  coach: '#f59e0b'
};

// --- Simple markdown renderer for rich text ---
function renderMarkdownText(text) {
  if (!text) return null;
  var lines = text.split('\n');
  var elements = [];
  var inList = false;
  var listItems = [];

  function flushList() {
    if (listItems.length > 0) {
      elements.push(h('ul', { key: 'ul' + elements.length, style: { margin: '0.3rem 0', paddingLeft: '1.1rem', listStyleType: 'disc' } },
        listItems.map(function(li, j) { return h('li', { key: j, style: { marginBottom: '0.15rem' } }, li); })
      ));
      listItems = [];
    }
    inList = false;
  }

  lines.forEach(function(line, i) {
    var trimmed = line.trim();
    if (!trimmed) {
      flushList();
      elements.push(h('div', { key: 'sp' + i, style: { height: '0.35rem' } }));
      return;
    }

    if (trimmed.match(/^[-*]\s/)) {
      inList = true;
      listItems.push(renderInlineMarkdown(trimmed.replace(/^[-*]\s+/, ''), i));
      return;
    }

    if (trimmed.match(/^\d+\.\s/)) {
      inList = true;
      listItems.push(renderInlineMarkdown(trimmed.replace(/^\d+\.\s+/, ''), i));
      return;
    }

    flushList();
    elements.push(h('div', { key: 'p' + i, style: { marginBottom: '0.15rem' } }, renderInlineMarkdown(trimmed, i)));
  });
  flushList();
  return elements;
}

function renderInlineMarkdown(text, key) {
  var parts = [];
  var regex = /\*\*(.+?)\*\*/g;
  var lastIdx = 0;
  var match;
  var partKey = 0;
  while ((match = regex.exec(text)) !== null) {
    if (match.index > lastIdx) {
      parts.push(text.substring(lastIdx, match.index));
    }
    parts.push(h('strong', { key: 'b' + key + '_' + partKey, style: { fontWeight: 700, color: '#0f172a' } }, match[1]));
    partKey++;
    lastIdx = regex.lastIndex;
  }
  if (lastIdx < text.length) parts.push(text.substring(lastIdx));
  return parts.length > 0 ? parts : text;
}


// --- Text sanitizer: strip all internal/backend syntax from display ---
function sanitizeDisplayText(text) {
  if (!text) return '';
  var s = text;
  // Strip <card ...>...</card> with or without attributes
  s = s.replace(/<card[^>]*>[\s\S]*?<\/card>/gi, '');
  // Strip orphan <card> or </card> tags
  s = s.replace(/<\/?card[^>]*>/gi, '');
  // Strip <action>...</action>
  s = s.replace(/<action[^>]*>[\s\S]*?<\/action>/gi, '');
  s = s.replace(/<\/?action[^>]*>/gi, '');
  // Strip standalone JSON blocks (lines that look like raw JSON)
  s = s.replace(/^\s*\{[^}]{20,}\}\s*$/gm, '');
  // Strip ```json ... ```
  s = s.replace(/```json\s*/g, '');
  s = s.replace(/```\s*/g, '');
  // Clean up excess whitespace
  s = s.replace(/\n{3,}/g, '\n\n');
  return s.trim();
}

// --- Frontend card recovery: catch any card-like text that slipped through parsing ---
function tryRecoverCard(text) {
  if (!text) return null;

  // Try to find <card>{...}</card> in the text
  var cardTagMatch = text.match(/<card[^>]*>([\s\S]*?)<\/card>/i);
  if (cardTagMatch) {
    try {
      var braceMatch = cardTagMatch[1].match(/\{[\s\S]*\}/);
      if (braceMatch) {
        var obj = JSON.parse(braceMatch[0]);
        if (obj.type) return ensureCardActions(obj);
      }
    } catch (e) {}
  }

  // Try to find raw JSON with a "type":"...Card" in text
  var jsonMatch = text.match(/\{[^{}]*"type"\s*:\s*"(\w+Card)"[^{}]*\}/);
  if (jsonMatch) {
    try {
      var parsed = JSON.parse(jsonMatch[0]);
      if (parsed.type) return ensureCardActions(parsed);
    } catch (e) {}
  }

  // Detect card type names rendered as raw text: <ExportCard>, <DraftCard>, etc.
  var rawTagMatch = text.match(/<(Export|Draft|Brief|Meeting|FollowUp|Touchpoint|Signal|NextAction)Card\s*\/?>/i);
  if (rawTagMatch) {
    var cardType = rawTagMatch[1] + 'Card';
    var fallback = { type: cardType, text: sanitizeDisplayText(text), data: {}, actions: [] };
    return ensureCardActions(fallback);
  }

  return null;
}

function ensureCardActions(card) {
  if (!card || !card.type) return card;
  if (!card.data) card.data = {};
  if (!card.actions) card.actions = [];
  var d = card.data;

  if (card.type === 'DraftCard' && card.actions.length === 0) {
    card.actions = [
      { id: 'copy_draft', label: 'Copy', action: 'copy_draft', params: { body: d.body || '' } }
    ];
  }
  if (card.type === 'ExportCard') {
    var url = d.url || d.fileUrl || '';
    if (url && card.actions.length === 0) {
      card.actions = [
        { id: 'download', label: 'Download', action: 'download', params: { url: url, fileName: d.fileName || d.filename || '' } }
      ];
    }
    if (!url && card.actions.length === 0) {
      card.type = 'ErrorCard';
      card.text = 'Export not available — no download URL.';
      card.data = { error: 'No file URL' };
    }
  }
  if (card.type === 'BriefCard' && card.actions.length === 0) {
    card.actions = [
      { id: 'download_brief', label: 'Download PDF', action: 'download', params: { url: '/api/brief/download', fileName: 'BTR_Brief.pdf' } }
    ];
  }
  if (card.type === 'TouchpointLogCard' && card.actions.length === 0) {
    card.actions = [
      { id: 'log_tp', label: 'Log Touchpoint', action: 'log_touchpoint', params: { contact_id: d.contact_id || '', group_id: d.group_id || '', channel: d.channel || 'note', summary: d.summary || '' } }
    ];
  }
  if (card.type === 'FollowUpCard' && card.actions.length === 0) {
    card.actions = [
      { id: 'create_fu', label: 'Create Follow-Up', action: 'create_followup', params: { contact_id: d.contact_id || '', title: d.title || '', due_date: d.due_date || '' } }
    ];
  }
  if (card.type === 'MeetingCard' && card.actions.length === 0) {
    card.actions = [
      { id: 'nav_cal', label: 'Open Calendar', action: 'navigate', params: { tab: 'calendar' } }
    ];
  }
  return card;
}

// --- Typing effect component ---
function TypingText(props) {
  var fullText = props.text || '';
  var _tv = useState('');
  var displayed = _tv[0];
  var setDisplayed = _tv[1];
  var _td = useState(false);
  var done = _td[0];
  var setDone = _td[1];

  useEffect(function() {
    if (!fullText) { setDone(true); return; }
    var idx = 0;
    var speed = Math.max(8, Math.min(25, 800 / fullText.length));
    var timer = setInterval(function() {
      idx += 1;
      // Advance by chunks (word boundaries) for smoother feel
      var next = fullText.indexOf(' ', idx);
      if (next === -1 || next <= idx) next = idx;
      setDisplayed(fullText.substring(0, next));
      if (next >= fullText.length) {
        setDisplayed(fullText);
        setDone(true);
        clearInterval(timer);
      }
      idx = next;
    }, speed);
    return function() { clearInterval(timer); };
  }, [fullText]);

  if (done) return renderMarkdownText(fullText);
  var els = renderMarkdownText(displayed);
  // Append blinking cursor
  if (Array.isArray(els)) {
    els = els.concat([h('span', { key: 'cursor', style: { color: '#94a3b8', animation: 'pulse 1s infinite' } }, '|')]);
  }
  return els;
}

// --- Interaction tracking (self-improvement loop) ---
function trackInteraction(event, cardType, actionId) {
  try {
    fetch(getApiBase() + '/api/assistant/track', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event: event, card_type: cardType || '', action_id: actionId || '' })
    }).catch(function() {});
  } catch(e) {}
}

// --- Action button handler ---
function executeCardAction(act, messages, setMessages, setActionLoading) {
  if (!act) return;
  trackInteraction('action_clicked', act.action, act.id);

  if (act.action === 'copy_text' || act.action === 'copy_draft') {
    if (act.params && act.params.body && navigator.clipboard) {
      var copyText = (act.params.subject ? 'Subject: ' + act.params.subject + '\n\n' : '') + act.params.body;
      navigator.clipboard.writeText(copyText);
    }
    setMessages(function(prev) {
      return prev.concat([{ role: 'assistant', card: {
        type: 'ConfirmationCard', text: 'Copied to clipboard.', data: {}, actions: []
      }}]);
    });
    return;
  }

  if (act.action === 'download') {
    var rawUrl = (act.params && act.params.url) || '';
    var dlUrl = rawUrl;
    if (rawUrl && rawUrl.charAt(0) === '/') {
      dlUrl = getApiBase() + rawUrl;
    }
    if (!dlUrl) {
      setMessages(function(prev) {
        return prev.concat([{ role: 'assistant', card: {
          type: 'ErrorCard', text: 'Download failed — no file URL available.', data: { error: 'No download URL provided' }, actions: []
        }}]);
      });
      return;
    }
    var a = document.createElement('a');
    a.href = dlUrl;
    a.download = (act.params && act.params.fileName) || '';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setMessages(function(prev) {
      return prev.concat([{ role: 'assistant', card: {
        type: 'ConfirmationCard', text: 'Download started.', data: {}, actions: []
      }}]);
    });
    return;
  }

  if (act.action === 'navigate') {
    var tab = act.params && act.params.tab;
    if (tab) {
      window.dispatchEvent(new CustomEvent('btr-navigate', { detail: { tab: tab } }));
    }
    return;
  }

  if (act.action === 'cancel') {
    setMessages(function(prev) {
      return prev.concat([{ role: 'assistant', card: {
        type: 'ConfirmationCard', text: 'Cancelled — no changes made.',
        data: { what: 'cancel', result: 'cancelled' }, actions: []
      }}]);
    });
    return;
  }

  setActionLoading(act.id || true);
  fetch(getApiBase() + '/api/assistant/execute-action', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: act.action, params: act.params || {} })
  })
    .then(function(r) { return r.json(); })
    .then(function(d) {
      setActionLoading(false);
      if (d.card) {
        setMessages(function(prev) {
          return prev.concat([{ role: 'assistant', card: d.card }]);
        });
      } else {
        setMessages(function(prev) {
          return prev.concat([{ role: 'assistant', card: {
            type: d.success ? 'ConfirmationCard' : 'ErrorCard',
            text: d.message || (d.success ? 'Done.' : 'Failed.'),
            data: {}, actions: []
          }}]);
        });
      }
    })
    .catch(function() {
      setActionLoading(false);
      setMessages(function(prev) {
        return prev.concat([{ role: 'assistant', card: {
          type: 'ErrorCard', text: 'Action failed — connection error.',
          data: { error: 'Network error' }, actions: []
        }}]);
      });
    });
}

// --- Card renderers ---

function renderDraftCard(card, onAction) {
  var d = card.data || {};
  var colors = CARD_COLORS.DraftCard;
  var channelLabel = { email: 'Email', linkedin: 'LinkedIn', call: 'Call Script' }[d.channel] || d.channel || 'Draft';

  var draftActions = card.actions && card.actions.length > 0 ? card.actions : [
    { id: 'copy_draft', label: 'Copy', action: 'copy_draft', params: { body: d.body || '', subject: d.subject || '' } }
  ];

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.6rem 0.7rem' } },
    h('div', { style: { display: 'flex', alignItems: 'center', gap: '0.3rem', marginBottom: '0.3rem', fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em' } },
      colors.icon, ' ', channelLabel, ' Draft',
      d.target_name ? h('span', { style: { fontWeight: 400, color: '#4b5563', textTransform: 'none' } }, ' — ' + d.target_name) : null
    ),
    d.subject ? h('div', { style: { fontWeight: 600, color: '#1e293b', marginBottom: '0.25rem', fontSize: '0.74rem' } }, d.subject) : null,
    h('div', { style: { color: '#374151', whiteSpace: 'pre-wrap', lineHeight: 1.5, fontSize: '0.72rem', maxHeight: '220px', overflowY: 'auto', background: '#ffffff', borderRadius: '0.35rem', padding: '0.5rem', border: '1px solid ' + colors.border } }, d.body || ''),
    d.signal_ref ? h('div', { style: { marginTop: '0.25rem', fontSize: '0.63rem', color: '#6b7280', fontStyle: 'italic' } }, '⚡ ' + d.signal_ref) : null,
    card.source ? h('div', { style: { marginTop: '0.2rem', fontSize: '0.63rem', color: '#6b7280', fontStyle: 'italic' } }, card.source) : null,
    renderActionButtons(draftActions, onAction, d)
  );
}

function renderNextActionCard(card, onAction) {
  var d = card.data || {};
  var recs = d.recommendations || [];
  var colors = CARD_COLORS.NextActionCard;
  var prioColors = { high: '#dc2626', medium: '#f59e0b', low: '#6b7280' };

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.6rem 0.7rem' } },
    h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em', marginBottom: '0.35rem' } }, colors.icon + ' Recommended Actions'),
    recs.length > 0 ? h('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.3rem' } },
      recs.map(function(r, i) {
        return h('div', { key: i, style: { display: 'flex', alignItems: 'flex-start', gap: '0.4rem', padding: '0.35rem 0.4rem', background: '#ffffff', borderRadius: '0.35rem', border: '1px solid #e2e8f0' } },
          h('span', { style: { width: '6px', height: '6px', borderRadius: '50%', background: prioColors[r.priority] || '#6b7280', marginTop: '0.3rem', flexShrink: 0 } }),
          h('div', { style: { flex: 1 } },
            h('div', { style: { fontSize: '0.74rem', fontWeight: 600, color: '#1e293b' } }, r.action || ''),
            r.target ? h('div', { style: { fontSize: '0.65rem', color: '#64748b' } }, r.target) : null,
            r.reason ? h('div', { style: { fontSize: '0.63rem', color: '#94a3b8', fontStyle: 'italic' } }, r.reason) : null
          )
        );
      })
    ) : h('div', { style: { fontSize: '0.74rem', color: '#64748b' } }, 'No urgent actions right now.'),
    card.source ? h('div', { style: { marginTop: '0.3rem', fontSize: '0.63rem', color: '#6b7280', fontStyle: 'italic' } }, card.source) : null,
    renderActionButtons(card.actions, onAction)
  );
}

function renderSignalCard(card, onAction) {
  var d = card.data || {};
  var signals = d.signals || [];
  var colors = CARD_COLORS.SignalCard;

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.6rem 0.7rem' } },
    h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em', marginBottom: '0.35rem' } }, colors.icon + ' Signals'),
    signals.length > 0 ? h('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.25rem' } },
      signals.map(function(s, i) {
        return h('div', { key: i, style: { padding: '0.3rem 0.4rem', background: '#ffffff', borderRadius: '0.35rem', border: '1px solid #fde68a' } },
          h('div', { style: { fontSize: '0.74rem', fontWeight: 600, color: '#1e293b' } }, s.title || 'Signal'),
          s.summary ? h('div', { style: { fontSize: '0.65rem', color: '#64748b', marginTop: '0.15rem' } }, s.summary.substring(0, 150)) : null,
          s.source_url ? h('a', { href: s.source_url, target: '_blank', rel: 'noopener', style: { fontSize: '0.6rem', color: '#2563eb', textDecoration: 'none' } }, 'View source →') : null
        );
      })
    ) : h('div', { style: { fontSize: '0.74rem', color: '#64748b' } }, 'No signals found.'),
    renderActionButtons(card.actions, onAction)
  );
}

function renderSummaryCard(card, onAction) {
  var d = card.data || {};
  var colors = CARD_COLORS[card.type] || CARD_COLORS.TextCard;

  var rows = [];
  var fields = ['name', 'title', 'company', 'stage', 'status', 'last_touch', 'last_contact',
                'warmth', 'touchpoint_count', 'contacts', 'opp_stage', 'opp_value', 'email', 'phone', 'notes'];
  var labels = { name: 'Name', title: 'Title', company: 'Company', stage: 'Stage', status: 'Status',
                 last_touch: 'Last Touch', last_contact: 'Last Contact', warmth: 'Warmth', touchpoint_count: 'Touchpoints',
                 contacts: 'Contacts', opp_stage: 'Opp Stage', opp_value: 'Opp Value', email: 'Email', phone: 'Phone', notes: 'Notes' };

  fields.forEach(function(f) {
    if (d[f] !== undefined && d[f] !== null && d[f] !== '') {
      rows.push({ label: labels[f] || f, value: String(d[f]) });
    }
  });

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.6rem 0.7rem' } },
    h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em', marginBottom: '0.35rem' } },
      colors.icon + ' ' + (card.type === 'ContactSummaryCard' ? 'Contact' : 'Company') + ' Summary'
    ),
    rows.length > 0 ? h('div', { style: { display: 'grid', gridTemplateColumns: '0.4fr 1fr', gap: '0.15rem 0.5rem', fontSize: '0.72rem' } },
      rows.map(function(r, i) {
        return [
          h('span', { key: 'l' + i, style: { color: '#94a3b8', fontWeight: 500 } }, r.label),
          h('span', { key: 'v' + i, style: { color: '#1e293b', wordBreak: 'break-word' } },
            r.value.length > 100 ? r.value.substring(0, 100) + '…' : r.value
          )
        ];
      }).flat()
    ) : null,
    card.source ? h('div', { style: { marginTop: '0.3rem', fontSize: '0.63rem', color: '#6b7280', fontStyle: 'italic' } }, card.source) : null,
    renderActionButtons(card.actions, onAction)
  );
}

function renderTouchpointCard(card, onAction) {
  var d = card.data || {};
  var colors = CARD_COLORS.TouchpointLogCard;

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.6rem 0.7rem' } },
    h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em', marginBottom: '0.25rem' } }, colors.icon + ' Log Touchpoint'),
    h('div', { style: { fontSize: '0.74rem', color: '#1e293b', marginBottom: '0.2rem' } },
      (d.channel || 'Note') + ' with ' + (d.contact_name || 'contact')
    ),
    d.summary ? h('div', { style: { fontSize: '0.7rem', color: '#64748b', fontStyle: 'italic' } }, '“' + d.summary + '”') : null,
    renderActionButtons(card.actions, onAction)
  );
}

function renderFollowUpCard(card, onAction) {
  var d = card.data || {};
  var colors = CARD_COLORS.FollowUpCard;

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.6rem 0.7rem' } },
    h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em', marginBottom: '0.25rem' } }, colors.icon + ' Follow-Up'),
    h('div', { style: { fontSize: '0.74rem', color: '#1e293b' } }, d.title || 'Follow up'),
    d.contact_name ? h('div', { style: { fontSize: '0.68rem', color: '#64748b' } }, 'with ' + d.contact_name) : null,
    d.due_date ? h('div', { style: { fontSize: '0.68rem', color: colors.accent, fontWeight: 600, marginTop: '0.15rem' } }, 'Due: ' + d.due_date) : null,
    renderActionButtons(card.actions, onAction)
  );
}

function renderExportCard(card, onAction) {
  var d = card.data || {};
  var colors = CARD_COLORS.ExportCard;
  var fileUrl = d.url || d.fileUrl || '';
  var fileName = d.fileName || d.filename || '';
  var exportType = d.export_type || 'Data';

  if (!fileUrl && (!card.actions || card.actions.length === 0)) {
    return null;
  }

  var displayName = fileName || (exportType + ' export');

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.7rem' } },
    h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em', marginBottom: '0.3rem' } }, colors.icon + ' Export Ready'),
    h('div', { style: { fontSize: '0.78rem', fontWeight: 600, color: '#1e293b', marginBottom: '0.15rem' } }, exportType.charAt(0).toUpperCase() + exportType.slice(1).replace(/_/g, ' ')),
    fileName ? h('div', { style: { fontSize: '0.65rem', color: '#64748b', marginBottom: '0.3rem' } }, '📄 ' + displayName) : null,
    renderActionButtons(card.actions, onAction)
  );
}

function renderConfirmationCard(card) {
  var colors = CARD_COLORS.ConfirmationCard;
  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.5rem 0.7rem', fontSize: '0.74rem', color: colors.accent, fontWeight: 600 } },
    colors.icon + ' ' + (card.text || 'Done.')
  );
}

function renderErrorCard(card) {
  var d = card.data || {};
  var colors = CARD_COLORS.ErrorCard;
  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.5rem 0.7rem' } },
    h('div', { style: { fontSize: '0.74rem', color: colors.accent, fontWeight: 600 } }, colors.icon + ' ' + (card.text || 'Error')),
    d.suggestion ? h('div', { style: { fontSize: '0.65rem', color: '#6b7280', marginTop: '0.2rem' } }, d.suggestion) : null
  );
}

// --- New card renderers ---

function renderStrategyCard(card, onAction) {
  var d = card.data || {};
  var colors = CARD_COLORS.StrategyCard;
  var recs = d.recommendations || [];
  var steps = d.implementation_order || [];
  var risks = d.risks || [];
  var effortColors = { low: '#16a34a', medium: '#f59e0b', high: '#dc2626' };
  var impactColors = { low: '#94a3b8', medium: '#3b82f6', high: '#7c3aed' };

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.7rem' } },
    h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em', marginBottom: '0.4rem' } }, colors.icon + ' Strategic Analysis'),

    d.diagnosis ? h('div', { style: { marginBottom: '0.4rem' } },
      h('div', { style: { fontSize: '0.63rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', marginBottom: '0.15rem' } }, 'Diagnosis'),
      h('div', { style: { fontSize: '0.72rem', color: '#1e293b', lineHeight: 1.5, padding: '0.3rem 0.4rem', background: '#ffffff', borderRadius: '0.35rem', border: '1px solid ' + colors.border } }, renderMarkdownText(d.diagnosis))
    ) : null,

    recs.length > 0 ? h('div', { style: { marginBottom: '0.4rem' } },
      h('div', { style: { fontSize: '0.63rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', marginBottom: '0.15rem' } }, 'Recommendations'),
      h('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.25rem' } },
        recs.map(function(r, i) {
          return h('div', { key: i, style: { padding: '0.35rem 0.4rem', background: '#ffffff', borderRadius: '0.35rem', border: '1px solid #e9d5ff' } },
            h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' } },
              h('div', { style: { fontSize: '0.74rem', fontWeight: 600, color: '#1e293b' } }, (i + 1) + '. ' + (r.title || '')),
              h('div', { style: { display: 'flex', gap: '0.3rem' } },
                r.effort ? h('span', { style: { fontSize: '0.58rem', padding: '0.1rem 0.3rem', borderRadius: '0.2rem', background: (effortColors[r.effort] || '#94a3b8') + '18', color: effortColors[r.effort] || '#94a3b8', fontWeight: 600 } }, r.effort + ' effort') : null,
                r.impact ? h('span', { style: { fontSize: '0.58rem', padding: '0.1rem 0.3rem', borderRadius: '0.2rem', background: (impactColors[r.impact] || '#94a3b8') + '18', color: impactColors[r.impact] || '#94a3b8', fontWeight: 600 } }, r.impact + ' impact') : null
              )
            ),
            r.detail ? h('div', { style: { fontSize: '0.68rem', color: '#475569', marginTop: '0.15rem', lineHeight: 1.4 } }, renderMarkdownText(r.detail)) : null
          );
        })
      )
    ) : null,

    steps.length > 0 ? h('div', { style: { marginBottom: '0.4rem' } },
      h('div', { style: { fontSize: '0.63rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', marginBottom: '0.15rem' } }, 'Implementation Order'),
      h('ol', { style: { margin: 0, paddingLeft: '1.2rem', fontSize: '0.7rem', color: '#374151', lineHeight: 1.5 } },
        steps.map(function(s, i) {
          return h('li', { key: i, style: { marginBottom: '0.1rem' } }, s);
        })
      )
    ) : null,

    risks.length > 0 ? h('div', { style: { marginBottom: '0.3rem' } },
      h('div', { style: { fontSize: '0.63rem', fontWeight: 700, color: '#dc2626', textTransform: 'uppercase', marginBottom: '0.15rem' } }, '⚠️ Risks'),
      h('ul', { style: { margin: 0, paddingLeft: '1.1rem', fontSize: '0.68rem', color: '#991b1b', lineHeight: 1.4, listStyleType: 'disc' } },
        risks.map(function(r, i) {
          return h('li', { key: i }, r);
        })
      )
    ) : null,

    d.claude_prompt ? h('div', { style: { marginBottom: '0.3rem' } },
      h('div', { style: { fontSize: '0.63rem', fontWeight: 700, color: '#0284c7', textTransform: 'uppercase', marginBottom: '0.15rem' } }, '🔧 Follow-up Prompt'),
      h('div', { style: { fontSize: '0.68rem', color: '#1e293b', background: '#f0f9ff', borderRadius: '0.35rem', padding: '0.4rem', border: '1px solid #bae6fd', fontFamily: "'JetBrains Mono', monospace", whiteSpace: 'pre-wrap', lineHeight: 1.4, maxHeight: '100px', overflowY: 'auto' } }, d.claude_prompt)
    ) : null,

    card.source ? h('div', { style: { fontSize: '0.63rem', color: '#6b7280', fontStyle: 'italic' } }, card.source) : null,
    renderActionButtons(card.actions, onAction)
  );
}

function renderClaudePromptCard(card, onAction) {
  var d = card.data || {};
  var colors = CARD_COLORS.ClaudePromptCard;
  var constraints = d.constraints || [];

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.7rem' } },
    h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em', marginBottom: '0.35rem' } }, colors.icon + ' Claude Prompt'),
    d.prompt_title ? h('div', { style: { fontSize: '0.78rem', fontWeight: 700, color: '#0f172a', marginBottom: '0.3rem' } }, d.prompt_title) : null,
    d.prompt_body ? h('div', { style: { fontSize: '0.7rem', color: '#1e293b', background: '#ffffff', borderRadius: '0.35rem', padding: '0.5rem', border: '1px solid ' + colors.border, fontFamily: "'JetBrains Mono', monospace", whiteSpace: 'pre-wrap', lineHeight: 1.45, maxHeight: '200px', overflowY: 'auto', marginBottom: '0.3rem' } }, d.prompt_body) : null,
    constraints.length > 0 ? h('div', { style: { marginBottom: '0.3rem' } },
      h('div', { style: { fontSize: '0.63rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', marginBottom: '0.1rem' } }, 'Constraints'),
      h('ul', { style: { margin: 0, paddingLeft: '1.1rem', fontSize: '0.68rem', color: '#475569', lineHeight: 1.4 } },
        constraints.map(function(c, i) { return h('li', { key: i }, c); })
      )
    ) : null,
    d.output_format ? h('div', { style: { fontSize: '0.63rem', color: '#6b7280' } },
      h('span', { style: { fontWeight: 600 } }, 'Output: '), d.output_format
    ) : null,
    renderActionButtons(card.actions || [{ id: 'copy_prompt', label: 'Copy Prompt', action: 'copy_text', params: {} }], onAction, { body: d.prompt_body || '' })
  );
}

function renderContactInsightCard(card, onAction) {
  var d = card.data || {};
  var colors = CARD_COLORS.ContactInsightCard;
  var insights = d.key_insights || [];
  var trendColors = { rising: '#16a34a', stable: '#3b82f6', declining: '#dc2626' };
  var trendIcons = { rising: '↑', stable: '→', declining: '↓' };

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.7rem' } },
    h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' } },
      h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em' } }, colors.icon + ' Contact Insight'),
      d.engagement_trend ? h('span', { style: { fontSize: '0.63rem', fontWeight: 600, color: trendColors[d.engagement_trend] || '#64748b', background: (trendColors[d.engagement_trend] || '#64748b') + '14', padding: '0.1rem 0.4rem', borderRadius: '0.2rem' } },
        (trendIcons[d.engagement_trend] || '') + ' ' + d.engagement_trend
      ) : null
    ),
    h('div', { style: { display: 'grid', gridTemplateColumns: '0.4fr 1fr', gap: '0.12rem 0.4rem', fontSize: '0.72rem', marginBottom: '0.35rem' } },
      d.name ? [h('span', { key: 'nl', style: { color: '#94a3b8', fontWeight: 500 } }, 'Name'), h('span', { key: 'nv', style: { color: '#0f172a', fontWeight: 600 } }, d.name)] : null,
      d.company ? [h('span', { key: 'cl', style: { color: '#94a3b8', fontWeight: 500 } }, 'Company'), h('span', { key: 'cv', style: { color: '#1e293b' } }, d.company)] : null,
      d.title ? [h('span', { key: 'tl', style: { color: '#94a3b8', fontWeight: 500 } }, 'Title'), h('span', { key: 'tv', style: { color: '#1e293b' } }, d.title)] : null,
      d.stage ? [h('span', { key: 'sl', style: { color: '#94a3b8', fontWeight: 500 } }, 'Stage'), h('span', { key: 'sv', style: { color: '#1e293b' } }, d.stage)] : null,
      d.last_touch ? [h('span', { key: 'ltl', style: { color: '#94a3b8', fontWeight: 500 } }, 'Last Touch'), h('span', { key: 'ltv', style: { color: '#1e293b' } }, d.last_touch)] : null,
      d.touchpoint_count !== undefined ? [h('span', { key: 'tcl', style: { color: '#94a3b8', fontWeight: 500 } }, 'Touchpoints'), h('span', { key: 'tcv', style: { color: '#1e293b' } }, String(d.touchpoint_count))] : null
    ),
    insights.length > 0 ? h('div', { style: { marginBottom: '0.3rem' } },
      h('div', { style: { fontSize: '0.63rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', marginBottom: '0.1rem' } }, 'Key Insights'),
      h('ul', { style: { margin: 0, paddingLeft: '1.1rem', fontSize: '0.68rem', color: '#475569', lineHeight: 1.5, listStyleType: 'disc' } },
        insights.map(function(ins, i) { return h('li', { key: i }, ins); })
      )
    ) : null,
    d.next_move ? h('div', { style: { fontSize: '0.72rem', color: '#0f172a', fontWeight: 600, padding: '0.3rem 0.4rem', background: '#dbeafe', borderRadius: '0.3rem', marginBottom: '0.2rem' } }, '🎯 Next: ' + d.next_move) : null,
    card.source ? h('div', { style: { fontSize: '0.63rem', color: '#6b7280', fontStyle: 'italic' } }, card.source) : null,
    renderActionButtons(card.actions, onAction)
  );
}

function renderSignalInsightCard(card, onAction) {
  var d = card.data || {};
  var colors = CARD_COLORS.SignalInsightCard;
  var signals = d.signals || [];

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.7rem' } },
    h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em', marginBottom: '0.35rem' } },
      colors.icon + ' Signal Analysis' + (d.company_name ? ' — ' + d.company_name : '')
    ),
    signals.length > 0 ? h('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.25rem', marginBottom: '0.35rem' } },
      signals.map(function(s, i) {
        var impColor = (s.importance || 0) >= 7 ? '#dc2626' : (s.importance || 0) >= 4 ? '#f59e0b' : '#6b7280';
        return h('div', { key: i, style: { padding: '0.35rem 0.4rem', background: '#ffffff', borderRadius: '0.35rem', border: '1px solid #fde68a' } },
          h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' } },
            h('div', { style: { fontSize: '0.74rem', fontWeight: 600, color: '#1e293b', flex: 1 } }, s.title || 'Signal'),
            s.importance ? h('span', { style: { fontSize: '0.58rem', fontWeight: 700, color: impColor, background: impColor + '14', padding: '0.08rem 0.3rem', borderRadius: '0.2rem' } }, s.importance + '/10') : null
          ),
          s.summary ? h('div', { style: { fontSize: '0.65rem', color: '#64748b', marginTop: '0.15rem' } }, s.summary.substring(0, 150)) : null,
          s.action_implication ? h('div', { style: { fontSize: '0.63rem', color: '#0369a1', marginTop: '0.1rem', fontWeight: 500 } }, '→ ' + s.action_implication) : null,
          s.source_url ? h('a', { href: s.source_url, target: '_blank', rel: 'noopener', style: { fontSize: '0.6rem', color: '#2563eb', textDecoration: 'none' } }, 'Source →') : null
        );
      })
    ) : null,
    d.overall_assessment ? h('div', { style: { fontSize: '0.72rem', color: '#1e293b', lineHeight: 1.5, padding: '0.35rem 0.4rem', background: '#ffffff', borderRadius: '0.35rem', border: '1px solid #fde68a', marginBottom: '0.25rem' } }, renderMarkdownText(d.overall_assessment)) : null,
    d.recommended_action ? h('div', { style: { fontSize: '0.72rem', color: '#0f172a', fontWeight: 600, padding: '0.3rem 0.4rem', background: '#fef9c3', borderRadius: '0.3rem' } }, '🎯 ' + d.recommended_action) : null,
    card.source ? h('div', { style: { marginTop: '0.2rem', fontSize: '0.63rem', color: '#6b7280', fontStyle: 'italic' } }, card.source) : null,
    renderActionButtons(card.actions, onAction)
  );
}

function renderPerformanceInsightCard(card, onAction) {
  var d = card.data || {};
  var colors = CARD_COLORS.PerformanceInsightCard;
  var metrics = d.metrics || [];
  var insights = d.insights || [];
  var trendIcons = { up: '↑', down: '↓', flat: '→' };
  var trendColors = { up: '#16a34a', down: '#dc2626', flat: '#94a3b8' };

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.7rem' } },
    h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' } },
      h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em' } }, colors.icon + ' Performance'),
      d.period ? h('span', { style: { fontSize: '0.63rem', color: '#64748b', fontWeight: 500 } }, d.period) : null
    ),
    metrics.length > 0 ? h('div', { style: { display: 'flex', flexWrap: 'wrap', gap: '0.3rem', marginBottom: '0.35rem' } },
      metrics.map(function(m, i) {
        return h('div', { key: i, style: { flex: '1 1 auto', minWidth: '80px', padding: '0.35rem 0.5rem', background: '#ffffff', borderRadius: '0.35rem', border: '1px solid #d1fae5', textAlign: 'center' } },
          h('div', { style: { fontSize: '1rem', fontWeight: 800, color: '#0f172a', lineHeight: 1.2 } }, m.value || '0'),
          h('div', { style: { fontSize: '0.6rem', color: '#64748b', marginTop: '0.1rem' } }, m.label || ''),
          m.trend ? h('span', { style: { fontSize: '0.58rem', fontWeight: 600, color: trendColors[m.trend] || '#94a3b8' } }, trendIcons[m.trend] || '') : null
        );
      })
    ) : null,
    insights.length > 0 ? h('div', { style: { marginBottom: '0.3rem' } },
      h('div', { style: { fontSize: '0.63rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', marginBottom: '0.1rem' } }, 'Insights'),
      h('ul', { style: { margin: 0, paddingLeft: '1.1rem', fontSize: '0.68rem', color: '#475569', lineHeight: 1.5, listStyleType: 'disc' } },
        insights.map(function(ins, i) { return h('li', { key: i }, ins); })
      )
    ) : null,
    d.focus_recommendation ? h('div', { style: { fontSize: '0.72rem', color: '#0f172a', fontWeight: 600, padding: '0.3rem 0.4rem', background: '#d1fae5', borderRadius: '0.3rem' } }, '🎯 Focus: ' + d.focus_recommendation) : null,
    card.source ? h('div', { style: { marginTop: '0.2rem', fontSize: '0.63rem', color: '#6b7280', fontStyle: 'italic' } }, card.source) : null,
    renderActionButtons(card.actions, onAction)
  );
}


function renderExecutionPlanCard(card, onAction) {
  var d = card.data || {};
  var colors = CARD_COLORS.ExecutionPlanCard;
  var steps = d.steps || [];
  var statusIcons = { done: '✅', current: '▶️', pending: '○' };
  var statusColors = { done: '#16a34a', current: '#1d4ed8', pending: '#94a3b8' };

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.7rem' } },
    h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em', marginBottom: '0.35rem' } },
      colors.icon + ' Execution Plan' + (d.plan_title ? ' — ' + d.plan_title : '')
    ),
    steps.length > 0 ? h('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.2rem', marginBottom: '0.3rem' } },
      steps.map(function(s, i) {
        var st = s.status || 'pending';
        var isCurrent = st === 'current';
        return h('div', { key: i, style: { display: 'flex', alignItems: 'flex-start', gap: '0.4rem', padding: '0.35rem 0.4rem', background: isCurrent ? '#dbeafe' : '#ffffff', borderRadius: '0.35rem', border: '1px solid ' + (isCurrent ? '#93c5fd' : '#e2e8f0') } },
          h('span', { style: { fontSize: '0.7rem', flexShrink: 0, marginTop: '0.05rem' } }, statusIcons[st] || '○'),
          h('div', { style: { flex: 1 } },
            h('div', { style: { fontSize: '0.74rem', fontWeight: isCurrent ? 700 : 500, color: statusColors[st] || '#1e293b' } }, (s.step ? s.step + '. ' : '') + (s.title || '')),
            s.detail ? h('div', { style: { fontSize: '0.65rem', color: '#64748b', marginTop: '0.1rem' } }, s.detail) : null
          )
        );
      })
    ) : null,
    d.estimated_time ? h('div', { style: { fontSize: '0.63rem', color: '#64748b', marginBottom: '0.2rem' } }, '⏱ Est: ' + d.estimated_time) : null,
    d.next_step_action ? h('div', { style: { fontSize: '0.72rem', color: '#0f172a', fontWeight: 600, padding: '0.3rem 0.4rem', background: '#dbeafe', borderRadius: '0.3rem', marginBottom: '0.2rem' } }, '→ Next: ' + d.next_step_action) : null,
    card.source ? h('div', { style: { fontSize: '0.63rem', color: '#6b7280', fontStyle: 'italic' } }, card.source) : null,
    renderActionButtons(card.actions, onAction)
  );
}

function renderFixCard(card, onAction) {
  var d = card.data || {};
  var colors = CARD_COLORS.FixCard;
  var steps = d.steps || [];

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.7rem' } },
    h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em', marginBottom: '0.35rem' } }, colors.icon + ' Diagnosis & Fix'),
    d.diagnosis ? h('div', { style: { marginBottom: '0.3rem' } },
      h('div', { style: { fontSize: '0.63rem', fontWeight: 700, color: '#991b1b', textTransform: 'uppercase', marginBottom: '0.1rem' } }, 'Problem'),
      h('div', { style: { fontSize: '0.72rem', color: '#1e293b', padding: '0.3rem 0.4rem', background: '#ffffff', borderRadius: '0.35rem', border: '1px solid #fecaca', lineHeight: 1.5 } }, renderMarkdownText(d.diagnosis))
    ) : null,
    d.cause ? h('div', { style: { marginBottom: '0.3rem' } },
      h('div', { style: { fontSize: '0.63rem', fontWeight: 700, color: '#92400e', textTransform: 'uppercase', marginBottom: '0.1rem' } }, 'Root Cause'),
      h('div', { style: { fontSize: '0.72rem', color: '#475569', padding: '0.3rem 0.4rem', background: '#ffffff', borderRadius: '0.35rem', border: '1px solid #fecaca', lineHeight: 1.5 } }, renderMarkdownText(d.cause))
    ) : null,
    d.solution ? h('div', { style: { marginBottom: '0.3rem' } },
      h('div', { style: { fontSize: '0.63rem', fontWeight: 700, color: '#16a34a', textTransform: 'uppercase', marginBottom: '0.1rem' } }, 'Solution'),
      h('div', { style: { fontSize: '0.72rem', color: '#1e293b', padding: '0.3rem 0.4rem', background: '#f0fdf4', borderRadius: '0.35rem', border: '1px solid #86efac', lineHeight: 1.5 } }, renderMarkdownText(d.solution))
    ) : null,
    steps.length > 0 ? h('div', { style: { marginBottom: '0.2rem' } },
      h('div', { style: { fontSize: '0.63rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', marginBottom: '0.1rem' } }, 'Steps to Fix'),
      h('ol', { style: { margin: 0, paddingLeft: '1.2rem', fontSize: '0.7rem', color: '#374151', lineHeight: 1.5 } },
        steps.map(function(s, i) { return h('li', { key: i, style: { marginBottom: '0.1rem' } }, s); })
      )
    ) : null,
    card.source ? h('div', { style: { fontSize: '0.63rem', color: '#6b7280', fontStyle: 'italic' } }, card.source) : null,
    renderActionButtons(card.actions, onAction)
  );
}

function renderCrmUpdatePreviewCard(card, onAction) {
  var colors = CARD_COLORS.CrmUpdatePreviewCard;
  var d = card.data || {};
  var items = d.items || [];
  var tp = d.touchpoint;
  var fu = d.follow_up;
  var sc = d.stage_change;

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border,
      borderRadius: '0.5rem', padding: '0.6rem', fontSize: '0.75rem' } },
    h('div', { style: { display: 'flex', alignItems: 'center', gap: '0.35rem', marginBottom: '0.4rem' } },
      h('span', null, colors.icon),
      h('span', { style: { fontWeight: 700, color: colors.accent } }, 'CRM Update Preview')
    ),
    h('div', { style: { fontWeight: 600, marginBottom: '0.35rem', color: '#1e293b' } },
      (d.group_name || d.contact_name || 'Unknown')
    ),
    tp ? h('div', { style: { display: 'flex', alignItems: 'center', gap: '0.3rem', marginBottom: '0.2rem',
        padding: '0.25rem 0.4rem', background: '#ecfdf5', borderRadius: '0.25rem' } },
      h('span', { style: { color: '#059669', fontWeight: 600 } }, 'Touchpoint:'),
      h('span', null, tp.channel + ' — "' + tp.summary + '"')
    ) : null,
    sc ? h('div', { style: { display: 'flex', alignItems: 'center', gap: '0.3rem', marginBottom: '0.2rem',
        padding: '0.25rem 0.4rem', background: '#eff6ff', borderRadius: '0.25rem' } },
      h('span', { style: { color: '#1d4ed8', fontWeight: 600 } }, 'Stage:'),
      h('span', null, 'Move to ' + sc.new_stage)
    ) : null,
    fu ? h('div', { style: { display: 'flex', alignItems: 'center', gap: '0.3rem', marginBottom: '0.2rem',
        padding: '0.25rem 0.4rem', background: '#fff7ed', borderRadius: '0.25rem' } },
      h('span', { style: { color: '#c2410c', fontWeight: 600 } }, 'Follow-up:'),
      h('span', null, fu.title + ' (due ' + fu.due_date + ')')
    ) : null,
    d.notes ? h('div', { style: { fontSize: '0.7rem', color: '#475569', fontStyle: 'italic',
        marginTop: '0.2rem' } }, 'Notes: ' + d.notes) : null,
    renderActionButtons(card.actions, onAction)
  );
}

function renderAmbiguityCard(card, onAction) {
  var colors = CARD_COLORS.AmbiguityCard;
  var d = card.data || {};
  var choices = d.choices || [];
  var actions = card.actions || [];

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border,
      borderRadius: '0.5rem', padding: '0.6rem', fontSize: '0.75rem' } },
    h('div', { style: { display: 'flex', alignItems: 'center', gap: '0.35rem', marginBottom: '0.4rem' } },
      h('span', null, colors.icon),
      h('span', { style: { fontWeight: 700, color: colors.accent } },
        d.entity_type === 'group' ? 'Which company?' : 'Which contact?')
    ),
    h('div', { style: { fontSize: '0.72rem', color: '#475569', marginBottom: '0.4rem' } },
      card.text || 'Multiple matches found. Pick one:'),
    h('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.3rem' } },
      actions.map(function(act, i) {
        return h('button', {
          key: i,
          onClick: function() { onAction(act); },
          style: { display: 'flex', flexDirection: 'column', alignItems: 'flex-start',
            padding: '0.4rem 0.6rem', background: '#fff', border: '1px solid #e5e7eb',
            borderRadius: '0.4rem', cursor: 'pointer', transition: 'all 0.15s',
            textAlign: 'left', width: '100%', fontSize: '0.72rem' },
          onMouseOver: function(e) { e.currentTarget.style.borderColor = '#d97706'; e.currentTarget.style.background = '#fffbeb'; },
          onMouseOut: function(e) { e.currentTarget.style.borderColor = '#e5e7eb'; e.currentTarget.style.background = '#fff'; }
        },
          h('span', { style: { fontWeight: 600, color: '#1e293b' } }, act.label),
          act.sublabel ? h('span', { style: { fontSize: '0.65rem', color: '#6b7280' } }, act.sublabel) : null
        );
      })
    )
  );
}

function renderDailyPlanCard(card, onAction) {
  var d = card.data || {};
  var plan = d.plan || [];
  var prioColors = { critical: '#dc2626', high: '#f59e0b', medium: '#3b82f6', low: '#94a3b8' };
  var prioLabels = { critical: 'OVERDUE', high: 'HIGH', medium: 'MED', low: 'LOW' };
  var typeIcons = { overdue_task: '!', cooling_contact: '~', unactioned_signal: '*', scheduled_followup: '#', opportunity: '+' };

  return h('div', { style: { background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '0.5rem', padding: '0.6rem 0.7rem' } },
    h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' } },
      h('div', { style: { fontSize: '0.72rem', fontWeight: 700, color: '#0f172a' } }, "Today's Plan"),
      d.total_minutes ? h('span', { style: { fontSize: '0.6rem', color: '#64748b', background: '#f1f5f9', padding: '0.1rem 0.4rem', borderRadius: '0.2rem' } }, '~' + d.total_minutes + ' min') : null
    ),
    plan.length > 0 ? h('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.3rem' } },
      plan.map(function(item, i) {
        var pColor = prioColors[item.priority] || '#94a3b8';
        return h('div', { key: i, style: { display: 'flex', gap: '0.4rem', padding: '0.35rem 0.45rem', background: '#ffffff', borderRadius: '0.35rem', border: '1px solid #e2e8f0', borderLeft: '3px solid ' + pColor } },
          h('div', { style: { display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: '18px' } },
            h('span', { style: { fontSize: '0.58rem', fontWeight: 700, color: pColor } }, prioLabels[item.priority] || ''),
            h('span', { style: { fontSize: '0.75rem', color: '#94a3b8' } }, typeIcons[item.type] || (i + 1))
          ),
          h('div', { style: { flex: 1 } },
            h('div', { style: { fontSize: '0.72rem', fontWeight: 600, color: '#1e293b' } }, item.action),
            item.target ? h('div', { style: { fontSize: '0.63rem', color: '#64748b' } }, item.target) : null,
            item.reason ? h('div', { style: { fontSize: '0.6rem', color: '#94a3b8', fontStyle: 'italic' } }, item.reason) : null
          ),
          item.est_minutes ? h('span', { style: { fontSize: '0.58rem', color: '#94a3b8', whiteSpace: 'nowrap' } }, item.est_minutes + 'm') : null
        );
      })
    ) : h('div', { style: { fontSize: '0.72rem', color: '#64748b', textAlign: 'center', padding: '0.5rem' } }, 'No urgent actions today.'),
    renderActionButtons(card.actions, onAction)
  );
}

function renderSprintCard(card, onAction) {
  var d = card.data || {};
  var tasks = d.tasks || [];
  var completed = d.completed || 0;
  var total = d.total || tasks.length;
  var pct = total > 0 ? Math.round((completed / total) * 100) : 0;

  return h('div', { style: { background: '#eff6ff', border: '1px solid #bfdbfe', borderRadius: '0.5rem', padding: '0.6rem 0.7rem' } },
    h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' } },
      h('div', { style: { fontSize: '0.72rem', fontWeight: 700, color: '#1d4ed8' } }, 'Sprint Mode'),
      h('span', { style: { fontSize: '0.65rem', fontWeight: 600, color: pct >= 100 ? '#16a34a' : '#1d4ed8' } }, pct + '% complete')
    ),
    h('div', { style: { background: '#e2e8f0', borderRadius: '4px', height: '4px', marginBottom: '0.4rem', overflow: 'hidden' } },
      h('div', { style: { background: pct >= 100 ? '#16a34a' : '#3b82f6', height: '100%', width: pct + '%', borderRadius: '4px', transition: 'width 0.3s ease' } })
    ),
    tasks.length > 0 ? h('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.25rem' } },
      tasks.map(function(t, i) {
        var isDone = t.status === 'done';
        var isCurrent = t.status === 'current';
        return h('div', { key: i, style: { display: 'flex', alignItems: 'center', gap: '0.35rem', padding: '0.3rem 0.4rem', background: isDone ? '#f0fdf4' : (isCurrent ? '#eff6ff' : '#ffffff'), borderRadius: '0.3rem', border: '1px solid ' + (isDone ? '#bbf7d0' : (isCurrent ? '#93c5fd' : '#e2e8f0')), opacity: isDone ? 0.7 : 1 } },
          h('span', { style: { fontSize: '0.7rem', width: '18px', textAlign: 'center', flexShrink: 0 } }, isDone ? '+' : (isCurrent ? '>' : t.step)),
          h('div', { style: { flex: 1 } },
            h('div', { style: { fontSize: '0.7rem', fontWeight: isDone ? 400 : 600, color: isDone ? '#64748b' : '#1e293b', textDecoration: isDone ? 'line-through' : 'none' } }, t.title),
            t.reason && !isDone ? h('div', { style: { fontSize: '0.58rem', color: '#94a3b8' } }, t.reason) : null
          ),
          t.est_minutes ? h('span', { style: { fontSize: '0.55rem', color: '#94a3b8' } }, t.est_minutes + 'm') : null
        );
      })
    ) : null,
    d.total_minutes ? h('div', { style: { fontSize: '0.6rem', color: '#64748b', marginTop: '0.3rem', textAlign: 'right' } }, 'Est. ' + d.total_minutes + ' min total') : null,
    renderActionButtons(card.actions, onAction)
  );
}

function renderInsightCard(card, onAction) {
  var d = card.data || {};
  var insights = d.insights || [];
  var catColors = { risk: '#dc2626', momentum: '#f59e0b', opportunity: '#16a34a', pipeline: '#7c3aed', execution: '#0369a1' };
  var catIcons = { risk: '!', momentum: '^', opportunity: '*', pipeline: '|', execution: '>' };

  return h('div', { style: { background: '#fffbeb', border: '1px solid #fde68a', borderRadius: '0.5rem', padding: '0.5rem 0.65rem' } },
    h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: '#92400e', marginBottom: '0.3rem' } }, 'System Intelligence'),
    insights.length > 0 ? h('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.25rem' } },
      insights.map(function(ins, i) {
        var cc = catColors[ins.category] || '#64748b';
        return h('div', { key: i, style: { display: 'flex', gap: '0.35rem', padding: '0.3rem 0.4rem', background: '#ffffff', borderRadius: '0.3rem', border: '1px solid #fde68a' } },
          h('span', { style: { fontSize: '0.68rem', color: cc, fontWeight: 700, minWidth: '14px' } }, catIcons[ins.category] || '-'),
          h('div', { style: { flex: 1 } },
            h('div', { style: { fontSize: '0.7rem', fontWeight: 600, color: '#1e293b' } }, ins.title),
            ins.detail ? h('div', { style: { fontSize: '0.6rem', color: '#64748b' } }, ins.detail) : null
          )
        );
      })
    ) : h('div', { style: { fontSize: '0.72rem', color: '#64748b' } }, 'All clear.'),
    renderActionButtons(card.actions, onAction)
  );
}

function renderQueueCard(card, onAction) {
  var d = card.data || {};
  var items = d.items || [];
  var colors = CARD_COLORS.QueueCard;
  var urgColors = { critical: '#dc2626', high: '#f59e0b', medium: '#3b82f6', low: '#94a3b8' };
  var probColors = { High: '#16a34a', Medium: '#f59e0b', Low: '#dc2626' };

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.6rem 0.7rem' } },
    h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' } },
      h('div', { style: { fontSize: '0.72rem', fontWeight: 700, color: colors.accent } }, colors.icon + ' Execution Queue'),
      h('span', { style: { fontSize: '0.6rem', color: '#64748b', background: '#f1f5f9', padding: '0.1rem 0.4rem', borderRadius: '0.2rem' } }, items.length + ' actions')
    ),
    items.length > 0 ? h('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.3rem' } },
      items.map(function(item, i) {
        var uc = urgColors[item.urgency] || '#94a3b8';
        var prob = item.probability || {};
        var pc = probColors[prob.label] || '#94a3b8';
        return h('div', { key: i, style: { display: 'flex', gap: '0.4rem', padding: '0.4rem 0.45rem', background: '#ffffff', borderRadius: '0.35rem', border: '1px solid #e2e8f0', borderLeft: '3px solid ' + uc } },
          h('div', { style: { display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: '22px' } },
            h('span', { style: { fontSize: '0.85rem', fontWeight: 800, color: colors.accent } }, '#' + item.rank)
          ),
          h('div', { style: { flex: 1 } },
            h('div', { style: { fontSize: '0.72rem', fontWeight: 600, color: '#1e293b' } }, item.action),
            item.target ? h('div', { style: { fontSize: '0.63rem', color: '#64748b' } }, item.target) : null,
            h('div', { style: { display: 'flex', gap: '0.3rem', marginTop: '0.2rem', flexWrap: 'wrap' } },
              h('span', { style: { fontSize: '0.55rem', fontWeight: 600, color: pc, background: pc + '14', padding: '0.08rem 0.3rem', borderRadius: '0.2rem' } }, prob.label + ' ' + (prob.score || 0)),
              item.confidence ? h('span', { style: { fontSize: '0.55rem', fontWeight: 600, color: item.confidence.level === 'High' ? '#16a34a' : item.confidence.level === 'Medium' ? '#f59e0b' : '#dc2626', background: '#f8fafc', padding: '0.08rem 0.3rem', borderRadius: '0.2rem' } }, item.confidence.level + ' conf.') : null,
              item.reason ? h('span', { style: { fontSize: '0.55rem', color: '#94a3b8', fontStyle: 'italic' } }, item.reason) : null
            ),
            item.expected_outcome ? h('div', { style: { fontSize: '0.58rem', color: '#6b7280', marginTop: '0.15rem' } }, '→ ' + item.expected_outcome) : null
          ),
          h('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.2rem', flexShrink: 0 } },
            h('button', {
              onClick: function() { onAction({ action: 'draft_outreach', params: { target_name: item.target, group_id: item.target_id, channel: 'email' } }); },
              style: { fontSize: '0.55rem', padding: '0.15rem 0.3rem', background: '#eff6ff', border: '1px solid #bfdbfe', borderRadius: '0.2rem', cursor: 'pointer', color: '#1d4ed8', fontWeight: 600 }
            }, 'Draft')
          )
        );
      })
    ) : h('div', { style: { fontSize: '0.72rem', color: '#64748b', textAlign: 'center', padding: '0.5rem' } }, 'Queue is empty — great work!'),
    items.length > 0 && items[0].rank_reason ? h('div', { style: { marginTop: '0.3rem', fontSize: '0.6rem', color: '#1e40af', background: '#dbeafe', padding: '0.25rem 0.4rem', borderRadius: '0.25rem' } }, '💡 Why #1: ' + items[0].rank_reason) : null,
    renderActionButtons(card.actions, onAction)
  );
}

function renderBatchDraftCard(card, onAction) {
  var d = card.data || {};
  var drafts = d.drafts || [];
  var colors = CARD_COLORS.BatchDraftCard;
  var probColors = { High: '#16a34a', Medium: '#f59e0b', Low: '#dc2626' };

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.6rem 0.7rem' } },
    h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' } },
      h('div', { style: { fontSize: '0.72rem', fontWeight: 700, color: colors.accent } }, colors.icon + ' Batch Drafts'),
      h('span', { style: { fontSize: '0.6rem', color: '#64748b', background: '#f1f5f9', padding: '0.1rem 0.4rem', borderRadius: '0.2rem' } }, drafts.length + ' drafts')
    ),
    drafts.length > 0 ? h('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.35rem' } },
      drafts.map(function(draft, i) {
        var prob = draft.probability || {};
        var pc = probColors[prob.label] || '#94a3b8';
        return h('div', { key: i, style: { padding: '0.4rem 0.5rem', background: '#ffffff', borderRadius: '0.35rem', border: '1px solid ' + colors.border } },
          h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.2rem' } },
            h('div', { style: { fontSize: '0.72rem', fontWeight: 600, color: '#1e293b' } }, '#' + draft.rank + ' ' + (draft.contact_name || draft.target)),
            h('span', { style: { fontSize: '0.55rem', fontWeight: 600, color: pc, background: pc + '14', padding: '0.08rem 0.3rem', borderRadius: '0.2rem' } }, prob.label + ' ' + (prob.score || 0))
          ),
          draft.reason ? h('div', { style: { fontSize: '0.6rem', color: '#64748b', marginBottom: '0.2rem', fontStyle: 'italic' } }, draft.reason) : null,
          draft.subject ? h('div', { style: { fontSize: '0.68rem', fontWeight: 600, color: '#374151', marginBottom: '0.15rem' } }, draft.subject) : null,
          h('div', { style: { fontSize: '0.65rem', color: '#475569', whiteSpace: 'pre-wrap', lineHeight: 1.45, maxHeight: '80px', overflowY: 'auto', background: '#f8fafc', borderRadius: '0.25rem', padding: '0.3rem 0.4rem', border: '1px solid #e2e8f0' } }, draft.body || ''),
          draft.signal_ref ? h('div', { style: { fontSize: '0.55rem', color: '#6b7280', marginTop: '0.15rem' } }, '⚡ ' + draft.signal_ref) : null,
          h('div', { style: { display: 'flex', gap: '0.25rem', marginTop: '0.3rem' } },
            h('button', {
              onClick: function() { onAction({ action: 'approve_queue_item', params: { item_id: draft.id } }); },
              style: { fontSize: '0.6rem', padding: '0.2rem 0.45rem', background: '#15803d', border: 'none', borderRadius: '0.25rem', cursor: 'pointer', color: '#fff', fontWeight: 600 }
            }, 'Approve'),
            h('button', {
              onClick: function() {
                var text = (draft.subject ? 'Subject: ' + draft.subject + '\n\n' : '') + (draft.body || '');
                if (navigator.clipboard) navigator.clipboard.writeText(text);
              },
              style: { fontSize: '0.6rem', padding: '0.2rem 0.45rem', background: 'transparent', border: '1px solid #d1d5db', borderRadius: '0.25rem', cursor: 'pointer', color: '#374151', fontWeight: 600 }
            }, 'Copy'),
            h('button', {
              onClick: function() { onAction({ action: 'skip_queue_item', params: { item_id: draft.id } }); },
              style: { fontSize: '0.6rem', padding: '0.2rem 0.45rem', background: 'transparent', border: '1px solid #d1d5db', borderRadius: '0.25rem', cursor: 'pointer', color: '#94a3b8', fontWeight: 600 }
            }, 'Skip')
          )
        );
      })
    ) : h('div', { style: { fontSize: '0.72rem', color: '#64748b', textAlign: 'center', padding: '0.5rem' } }, 'No drafts to show.'),
    renderActionButtons(card.actions, onAction)
  );
}

function renderApprovalQueueCard(card, onAction) {
  var d = card.data || {};
  var items = d.items || [];
  var colors = CARD_COLORS.ApprovalQueueCard;
  var probColors = { High: '#16a34a', Medium: '#f59e0b', Low: '#dc2626' };

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.6rem 0.7rem' } },
    h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' } },
      h('div', { style: { fontSize: '0.72rem', fontWeight: 700, color: colors.accent } }, colors.icon + ' Approval Queue'),
      h('span', { style: { fontSize: '0.6rem', color: '#64748b', background: '#f1f5f9', padding: '0.1rem 0.4rem', borderRadius: '0.2rem' } }, items.length + ' pending')
    ),
    items.length > 0 ? h('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.3rem' } },
      items.map(function(item, i) {
        var prob = item.probability || {};
        var pc = probColors[prob.label] || '#94a3b8';
        return h('div', { key: i, style: { display: 'flex', gap: '0.4rem', padding: '0.35rem 0.45rem', background: '#ffffff', borderRadius: '0.35rem', border: '1px solid #e2e8f0' } },
          h('div', { style: { flex: 1 } },
            h('div', { style: { fontSize: '0.72rem', fontWeight: 600, color: '#1e293b' } }, item.action || ''),
            h('div', { style: { fontSize: '0.63rem', color: '#64748b' } }, item.target || ''),
            h('div', { style: { display: 'flex', gap: '0.3rem', marginTop: '0.15rem' } },
              h('span', { style: { fontSize: '0.55rem', fontWeight: 600, color: pc, background: pc + '14', padding: '0.08rem 0.3rem', borderRadius: '0.2rem' } }, prob.label + ' ' + (prob.score || 0))
            )
          ),
          h('div', { style: { display: 'flex', gap: '0.2rem', alignItems: 'center', flexShrink: 0 } },
            h('button', {
              onClick: function() { onAction({ action: 'approve_queue_item', params: { item_id: item.id } }); },
              style: { fontSize: '0.58rem', padding: '0.18rem 0.35rem', background: '#16a34a', border: 'none', borderRadius: '0.2rem', cursor: 'pointer', color: '#fff', fontWeight: 600 }
            }, '✓'),
            h('button', {
              onClick: function() { onAction({ action: 'skip_queue_item', params: { item_id: item.id } }); },
              style: { fontSize: '0.58rem', padding: '0.18rem 0.35rem', background: 'transparent', border: '1px solid #d1d5db', borderRadius: '0.2rem', cursor: 'pointer', color: '#94a3b8', fontWeight: 600 }
            }, '✕'),
            h('button', {
              onClick: function() { onAction({ action: 'delete_queue_item', params: { item_id: item.id } }); },
              style: { fontSize: '0.58rem', padding: '0.18rem 0.35rem', background: 'transparent', border: '1px solid #fca5a5', borderRadius: '0.2rem', cursor: 'pointer', color: '#dc2626', fontWeight: 600 }
            }, '🗑')
          )
        );
      })
    ) : h('div', { style: { fontSize: '0.72rem', color: '#64748b', textAlign: 'center', padding: '0.5rem' } }, 'No pending approvals.'),
    renderActionButtons(card.actions, onAction)
  );
}

function renderProbabilityCard(card, onAction) {
  var d = card.data || {};
  var colors = CARD_COLORS.ProbabilityCard;
  var probColors = { High: '#16a34a', Medium: '#f59e0b', Low: '#dc2626' };
  var pc = probColors[d.label] || '#94a3b8';
  var pct = d.score || 0;

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.7rem' } },
    h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em', marginBottom: '0.35rem' } }, colors.icon + ' Deal Probability'),
    h('div', { style: { display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' } },
      h('div', { style: { fontSize: '1.1rem', fontWeight: 800, color: pc } }, pct),
      h('div', { style: { flex: 1 } },
        h('div', { style: { fontSize: '0.82rem', fontWeight: 700, color: '#1e293b' } }, d.company || ''),
        h('div', { style: { display: 'flex', gap: '0.3rem', marginTop: '0.1rem' } },
          h('span', { style: { fontSize: '0.6rem', fontWeight: 700, color: pc, background: pc + '14', padding: '0.1rem 0.4rem', borderRadius: '0.2rem' } }, d.label),
          d.stage ? h('span', { style: { fontSize: '0.6rem', color: '#64748b', background: '#f1f5f9', padding: '0.1rem 0.4rem', borderRadius: '0.2rem' } }, d.stage) : null,
          d.warmth !== undefined ? h('span', { style: { fontSize: '0.6rem', color: '#64748b', background: '#f1f5f9', padding: '0.1rem 0.4rem', borderRadius: '0.2rem' } }, 'Warmth ' + d.warmth + '/10') : null
        )
      )
    ),
    h('div', { style: { background: '#e2e8f0', borderRadius: '4px', height: '6px', marginBottom: '0.35rem', overflow: 'hidden' } },
      h('div', { style: { background: pc, height: '100%', width: pct + '%', borderRadius: '4px', transition: 'width 0.5s ease' } })
    ),
    d.reason ? h('div', { style: { fontSize: '0.68rem', color: '#475569', lineHeight: 1.5, padding: '0.3rem 0.4rem', background: '#ffffff', borderRadius: '0.35rem', border: '1px solid ' + colors.border } }, d.reason) : null,
    renderActionButtons(card.actions, onAction)
  );
}

function renderRelationshipCard(card, onAction) {
  var d = card.data || {};
  var colors = CARD_COLORS.RelationshipCard;
  var labelColors = { hot: '#dc2626', warm: '#f59e0b', cooling: '#3b82f6', cold: '#94a3b8' };
  var lc = labelColors[d.label] || '#94a3b8';
  var pct = d.relationship_score || 0;
  var resp = d.responsiveness || {};
  var style = d.communication_style || {};
  var breakdown = style.channel_breakdown || {};

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.7rem' } },
    h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em', marginBottom: '0.35rem' } }, colors.icon + ' Relationship Intelligence'),
    h('div', { style: { display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' } },
      h('div', { style: { fontSize: '1.1rem', fontWeight: 800, color: lc } }, pct),
      h('div', { style: { flex: 1 } },
        h('div', { style: { fontSize: '0.82rem', fontWeight: 700, color: '#1e293b' } }, d.company || ''),
        h('div', { style: { display: 'flex', gap: '0.3rem', marginTop: '0.1rem' } },
          h('span', { style: { fontSize: '0.6rem', fontWeight: 700, color: lc, background: lc + '14', padding: '0.1rem 0.4rem', borderRadius: '0.2rem', textTransform: 'uppercase' } }, d.label),
          style.preferred_channel ? h('span', { style: { fontSize: '0.6rem', color: '#64748b', background: '#f1f5f9', padding: '0.1rem 0.4rem', borderRadius: '0.2rem' } }, 'Prefers ' + style.preferred_channel) : null,
          d.days_silent !== undefined ? h('span', { style: { fontSize: '0.6rem', color: '#64748b', background: '#f1f5f9', padding: '0.1rem 0.4rem', borderRadius: '0.2rem' } }, d.days_silent + 'd silent') : null
        )
      )
    ),
    h('div', { style: { background: '#e2e8f0', borderRadius: '4px', height: '6px', marginBottom: '0.35rem', overflow: 'hidden' } },
      h('div', { style: { background: lc, height: '100%', width: pct + '%', borderRadius: '4px', transition: 'width 0.5s ease' } })
    ),
    h('div', { style: { display: 'flex', gap: '0.5rem', marginBottom: '0.3rem' } },
      h('div', { style: { flex: 1, background: '#ffffff', borderRadius: '0.35rem', border: '1px solid ' + colors.border, padding: '0.3rem 0.4rem' } },
        h('div', { style: { fontSize: '0.58rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.15rem' } }, 'Responsiveness'),
        h('div', { style: { fontSize: '0.72rem', fontWeight: 700, color: '#334155' } }, (resp.label || 'Unknown').replace('_', ' ')),
        resp.avg_days !== null && resp.avg_days !== undefined ? h('div', { style: { fontSize: '0.6rem', color: '#64748b' } }, 'Avg ' + resp.avg_days + 'd reply') : null
      ),
      h('div', { style: { flex: 1, background: '#ffffff', borderRadius: '0.35rem', border: '1px solid ' + colors.border, padding: '0.3rem 0.4rem' } },
        h('div', { style: { fontSize: '0.58rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.15rem' } }, 'Channels'),
        Object.keys(breakdown).length > 0 ? h('div', { style: { fontSize: '0.65rem', color: '#334155' } },
          Object.keys(breakdown).map(function(ch) { return ch + ': ' + breakdown[ch]; }).join(', ')
        ) : h('div', { style: { fontSize: '0.65rem', color: '#94a3b8' } }, 'No data')
      )
    ),
    (d.factors && d.factors.length > 0) ? h('div', { style: { background: '#ffffff', borderRadius: '0.35rem', border: '1px solid ' + colors.border, padding: '0.3rem 0.4rem' } },
      d.factors.map(function(f, i) {
        return h('div', { key: i, style: { fontSize: '0.65rem', color: '#475569', padding: '0.1rem 0' } }, '• ' + f);
      })
    ) : null,
    renderActionButtons(card.actions, onAction)
  );
}

function renderFunnelCard(card, onAction) {
  var d = card.data || {};
  var colors = CARD_COLORS.FunnelCard;
  var funnel = d.funnel || [];
  var rates = d.rates || {};
  var bottlenecks = d.bottlenecks || [];
  var maxCount = Math.max.apply(null, funnel.map(function(f) { return f.count; }).concat([1]));

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.7rem' } },
    h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em', marginBottom: '0.35rem' } }, colors.icon + ' Conversion Funnel'),
    h('div', { style: { display: 'flex', gap: '0.5rem', marginBottom: '0.4rem', flexWrap: 'wrap' } },
      h('div', { style: { fontSize: '0.6rem', color: '#64748b', background: '#f1f5f9', padding: '0.15rem 0.4rem', borderRadius: '0.2rem' } }, 'Reply: ' + (rates.outreach_to_reply || 0) + '%'),
      h('div', { style: { fontSize: '0.6rem', color: '#64748b', background: '#f1f5f9', padding: '0.15rem 0.4rem', borderRadius: '0.2rem' } }, 'Meeting: ' + (rates.reply_to_meeting || 0) + '%'),
      h('div', { style: { fontSize: '0.6rem', color: '#64748b', background: '#f1f5f9', padding: '0.15rem 0.4rem', borderRadius: '0.2rem' } }, 'Conversion: ' + (rates.overall_conversion || 0) + '%')
    ),
    funnel.length > 0 ? h('div', { style: { marginBottom: '0.4rem' } },
      funnel.filter(function(f) { return f.count > 0; }).map(function(f, i) {
        var widthPct = Math.max(Math.round(f.count / maxCount * 100), 8);
        return h('div', { key: i, style: { display: 'flex', alignItems: 'center', gap: '0.3rem', marginBottom: '0.15rem' } },
          h('div', { style: { fontSize: '0.6rem', color: '#64748b', width: '4rem', textAlign: 'right', flexShrink: 0 } }, f.stage),
          h('div', { style: { flex: 1, background: '#e2e8f0', borderRadius: '3px', height: '14px', overflow: 'hidden' } },
            h('div', { style: { background: colors.accent, height: '100%', width: widthPct + '%', borderRadius: '3px', display: 'flex', alignItems: 'center', justifyContent: 'flex-end', paddingRight: '0.25rem' } },
              h('span', { style: { fontSize: '0.55rem', color: '#fff', fontWeight: 700 } }, f.count)
            )
          )
        );
      })
    ) : null,
    bottlenecks.length > 0 ? h('div', { style: { background: '#ffffff', borderRadius: '0.35rem', border: '1px solid ' + colors.border, padding: '0.3rem 0.4rem' } },
      h('div', { style: { fontSize: '0.58rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.15rem' } }, 'Bottlenecks'),
      bottlenecks.map(function(b, i) {
        var sevColors = { high: '#dc2626', medium: '#f59e0b', low: '#22c55e' };
        return h('div', { key: i, style: { fontSize: '0.65rem', color: '#475569', padding: '0.15rem 0', borderBottom: i < bottlenecks.length - 1 ? '1px solid #f1f5f9' : 'none' } },
          h('span', { style: { color: sevColors[b.severity] || '#94a3b8', fontWeight: 700 } }, '● '),
          b.suggestion
        );
      })
    ) : null,
    renderActionButtons(card.actions, onAction)
  );
}

function renderPredictionCard(card, onAction) {
  var d = card.data || {};
  var colors = CARD_COLORS.PredictionCard;
  var reply = d.reply_likelihood || {};
  var meeting = d.meeting_likelihood || {};
  var rel = d.relationship || {};
  var labelColors = { High: '#16a34a', Medium: '#f59e0b', Low: '#dc2626' };

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.7rem' } },
    h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em', marginBottom: '0.35rem' } }, colors.icon + ' Outcome Prediction'),
    d.company ? h('div', { style: { fontSize: '0.82rem', fontWeight: 700, color: '#1e293b', marginBottom: '0.35rem' } }, d.company) : null,
    h('div', { style: { display: 'flex', gap: '0.5rem', marginBottom: '0.35rem' } },
      h('div', { style: { flex: 1, background: '#ffffff', borderRadius: '0.35rem', border: '1px solid ' + colors.border, padding: '0.4rem', textAlign: 'center' } },
        h('div', { style: { fontSize: '0.58rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.15rem' } }, 'Reply Likelihood'),
        h('div', { style: { fontSize: '1.1rem', fontWeight: 800, color: labelColors[reply.label] || '#94a3b8' } }, reply.score || 0),
        h('div', { style: { fontSize: '0.6rem', fontWeight: 700, color: labelColors[reply.label] || '#94a3b8' } }, reply.label || '?'),
        h('div', { style: { background: '#e2e8f0', borderRadius: '3px', height: '4px', marginTop: '0.2rem', overflow: 'hidden' } },
          h('div', { style: { background: labelColors[reply.label] || '#94a3b8', height: '100%', width: (reply.score || 0) + '%', borderRadius: '3px' } })
        )
      ),
      h('div', { style: { flex: 1, background: '#ffffff', borderRadius: '0.35rem', border: '1px solid ' + colors.border, padding: '0.4rem', textAlign: 'center' } },
        h('div', { style: { fontSize: '0.58rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.15rem' } }, 'Meeting Likelihood'),
        h('div', { style: { fontSize: '1.1rem', fontWeight: 800, color: labelColors[meeting.label] || '#94a3b8' } }, meeting.score || 0),
        h('div', { style: { fontSize: '0.6rem', fontWeight: 700, color: labelColors[meeting.label] || '#94a3b8' } }, meeting.label || '?'),
        h('div', { style: { background: '#e2e8f0', borderRadius: '3px', height: '4px', marginTop: '0.2rem', overflow: 'hidden' } },
          h('div', { style: { background: labelColors[meeting.label] || '#94a3b8', height: '100%', width: (meeting.score || 0) + '%', borderRadius: '3px' } })
        )
      )
    ),
    h('div', { style: { display: 'flex', gap: '0.3rem', marginBottom: '0.3rem', flexWrap: 'wrap' } },
      d.recommended_channel ? h('span', { style: { fontSize: '0.6rem', color: '#64748b', background: '#f1f5f9', padding: '0.15rem 0.4rem', borderRadius: '0.2rem' } }, 'Best channel: ' + d.recommended_channel) : null,
      d.best_timing ? h('span', { style: { fontSize: '0.6rem', color: '#64748b', background: '#f1f5f9', padding: '0.15rem 0.4rem', borderRadius: '0.2rem' } }, 'Timing: ' + d.best_timing) : null,
      rel.label ? h('span', { style: { fontSize: '0.6rem', color: '#64748b', background: '#f1f5f9', padding: '0.15rem 0.4rem', borderRadius: '0.2rem' } }, 'Relationship: ' + rel.label) : null
    ),
    (reply.factors && reply.factors.length > 0) ? h('div', { style: { background: '#ffffff', borderRadius: '0.35rem', border: '1px solid ' + colors.border, padding: '0.3rem 0.4rem' } },
      h('div', { style: { fontSize: '0.58rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.15rem' } }, 'Key Factors'),
      reply.factors.map(function(f, i) {
        return h('div', { key: i, style: { fontSize: '0.65rem', color: '#475569', padding: '0.1rem 0' } }, '• ' + f);
      })
    ) : null,
    d.confidence ? h('div', { style: { display: 'flex', alignItems: 'center', gap: '0.3rem', marginTop: '0.25rem', padding: '0.2rem 0.4rem', background: '#f8fafc', borderRadius: '0.25rem' } },
      h('span', { style: { fontSize: '0.58rem', fontWeight: 700, color: d.confidence.level === 'High' ? '#16a34a' : d.confidence.level === 'Medium' ? '#f59e0b' : '#dc2626' } }, 'Confidence: ' + d.confidence.level),
      d.confidence.reasons && d.confidence.reasons[0] ? h('span', { style: { fontSize: '0.55rem', color: '#94a3b8' } }, '— ' + d.confidence.reasons[0]) : null
    ) : null,
    renderActionButtons(card.actions, onAction)
  );
}

function renderAutomationCard(card, onAction) {
  var d = card.data || {};
  var colors = CARD_COLORS.AutomationCard;
  var patterns = d.patterns || [];
  var suggestions = d.suggestions || [];
  var impactColors = { high: '#dc2626', medium: '#f59e0b', low: '#22c55e' };

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.7rem' } },
    h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' } },
      h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em' } }, colors.icon + ' Automation Scan'),
      d.time_savings_est > 0 ? h('div', { style: { fontSize: '0.6rem', fontWeight: 700, color: '#16a34a', background: '#f0fdf4', padding: '0.15rem 0.4rem', borderRadius: '0.2rem' } }, '~' + d.time_savings_est + ' min savings') : null
    ),
    patterns.length > 0 ? h('div', { style: { marginBottom: '0.35rem' } },
      h('div', { style: { fontSize: '0.58rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.15rem' } }, 'Patterns Detected'),
      patterns.map(function(p, i) {
        return h('div', { key: 'p' + i, style: { fontSize: '0.65rem', color: '#475569', padding: '0.15rem 0', borderBottom: i < patterns.length - 1 ? '1px solid #fef3c7' : 'none' } },
          '• ' + p.detail
        );
      })
    ) : null,
    suggestions.length > 0 ? h('div', { style: { background: '#ffffff', borderRadius: '0.35rem', border: '1px solid ' + colors.border, padding: '0.3rem 0.4rem' } },
      h('div', { style: { fontSize: '0.58rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.15rem' } }, 'Suggestions'),
      suggestions.map(function(s, i) {
        return h('div', { key: 's' + i, style: { display: 'flex', alignItems: 'flex-start', gap: '0.3rem', padding: '0.2rem 0', borderBottom: i < suggestions.length - 1 ? '1px solid #f1f5f9' : 'none' } },
          h('span', { style: { fontSize: '0.55rem', fontWeight: 700, color: impactColors[s.impact] || '#94a3b8', background: (impactColors[s.impact] || '#94a3b8') + '14', padding: '0.05rem 0.3rem', borderRadius: '0.15rem', flexShrink: 0 } }, s.impact),
          h('div', { style: { fontSize: '0.65rem', color: '#334155' } }, s.action,
            s.time_saved_min > 0 ? h('span', { style: { fontSize: '0.55rem', color: '#16a34a', marginLeft: '0.3rem' } }, '(~' + s.time_saved_min + ' min)') : null
          )
        );
      })
    ) : null,
    renderActionButtons(card.actions, onAction)
  );
}

function renderBriefCard(card, onAction) {
  var d = card.data || {};
  var colors = CARD_COLORS.BriefCard;
  var snapshots = d.market_snapshot || [];
  var actions_list = d.action_items || [];
  var targets = d.daily_targets || [];

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.7rem' } },
    h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' } },
      h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em' } }, colors.icon + ' Daily Intelligence Brief'),
      h('div', { style: { fontSize: '0.6rem', color: '#64748b' } }, d.date || '')
    ),
    h('div', { style: { fontSize: '0.82rem', fontWeight: 700, color: '#0f172a', marginBottom: '0.35rem' } }, d.title || 'BTR Daily Brief'),
    snapshots.length > 0 ? h('div', { style: { marginBottom: '0.35rem' } },
      h('div', { style: { fontSize: '0.58rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.15rem' } }, 'Market Snapshot'),
      snapshots.map(function(s, i) {
        return h('div', { key: 'ms' + i, style: { fontSize: '0.62rem', color: '#334155', padding: '0.1rem 0' } }, '• ' + s.substring(0, 80) + (s.length > 80 ? '...' : ''));
      })
    ) : null,
    actions_list.length > 0 ? h('div', { style: { marginBottom: '0.35rem' } },
      h('div', { style: { fontSize: '0.58rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.15rem' } }, 'Top Actions'),
      actions_list.map(function(a, i) {
        return h('div', { key: 'ai' + i, style: { fontSize: '0.62rem', color: '#334155', padding: '0.1rem 0' } }, (i + 1) + '. ' + a.substring(0, 70) + (a.length > 70 ? '...' : ''));
      })
    ) : null,
    targets.length > 0 ? h('div', { style: { marginBottom: '0.35rem' } },
      h('div', { style: { fontSize: '0.58rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.15rem' } }, 'Targets'),
      targets.map(function(t, i) {
        return h('div', { key: 'dt' + i, style: { fontSize: '0.62rem', color: '#334155', padding: '0.1rem 0' } }, '• ' + t);
      })
    ) : null,
    h('div', { style: { fontSize: '0.6rem', color: '#64748b', fontStyle: 'italic', marginBottom: '0.3rem' } }, 'Full brief includes BTR intelligence, analysis, learning insight, and more.'),
    renderActionButtons(card.actions, onAction)
  );
}

function renderActionButtons(actions, onAction, draftData) {
  if (!actions || actions.length === 0) return null;

  return h('div', { style: { display: 'flex', gap: '0.35rem', flexWrap: 'wrap', marginTop: '0.4rem' } },
    actions.map(function(act) {
      var isCopy = act.action === 'copy_text' || act.action === 'copy_draft';
      return h('button', {
        key: act.id,
        onClick: function() {
          if (isCopy && draftData) {
            var text = (draftData.subject ? 'Subject: ' + draftData.subject + '\n\n' : '') + (draftData.body || '');
            if (navigator.clipboard) {
              navigator.clipboard.writeText(text);
            }
          }
          onAction(act);
        },
        style: {
          background: isCopy ? '#15803d' : 'transparent',
          border: isCopy ? 'none' : '1px solid #d1d5db',
          color: isCopy ? '#ffffff' : '#374151',
          padding: '0.25rem 0.55rem',
          borderRadius: '0.3rem',
          fontSize: '0.68rem',
          fontWeight: 600,
          cursor: 'pointer',
          fontFamily: "'Inter', sans-serif",
          transition: 'all 0.15s'
        }
      }, act.label);
    })
  );
}

function renderMeetingCard(card, onAction) {
  var d = card.data || {};
  var colors = CARD_COLORS.MeetingCard;
  var statusColor = d.status === 'completed' ? '#16a34a' : d.status === 'cancelled' ? '#94a3b8' : '#3b82f6';
  var typeLabels = { general: 'Meeting', intro: 'Introduction', follow_up: 'Follow-up', pitch: 'Pitch', review: 'Review', call: 'Call' };

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.7rem' } },
    h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em', marginBottom: '0.3rem' } }, colors.icon + ' Meeting Scheduled'),
    h('div', { style: { fontSize: '0.82rem', fontWeight: 600, color: '#0f172a', marginBottom: '0.15rem' } }, d.title || 'Meeting'),
    h('div', { style: { fontSize: '0.72rem', color: '#334155', marginBottom: '0.1rem' } },
      (d.contact_name ? '👤 ' + d.contact_name : '') + (d.company_name ? ' — ' + d.company_name : '')),
    h('div', { style: { fontSize: '0.72rem', color: '#475569', marginBottom: '0.15rem' } },
      '🕐 ' + (d.meeting_date || '—') + ' at ' + (d.meeting_time || '—') + ' · ' + (d.duration_min || 30) + 'min'),
    h('div', { style: { display: 'flex', gap: '0.3rem', marginBottom: '0.3rem', flexWrap: 'wrap' } },
      h('span', { style: { fontSize: '0.6rem', padding: '0.1rem 0.4rem', borderRadius: '1rem', background: statusColor + '18', color: statusColor, fontWeight: 600 } }, d.status || 'scheduled'),
      h('span', { style: { fontSize: '0.6rem', padding: '0.1rem 0.4rem', borderRadius: '1rem', background: '#f1f5f9', color: '#475569', fontWeight: 600 } }, typeLabels[d.meeting_type] || d.meeting_type || 'general')
    ),
    d.notes ? h('div', { style: { fontSize: '0.68rem', color: '#64748b', fontStyle: 'italic', marginBottom: '0.25rem' } }, d.notes) : null,
    renderActionButtons(card.actions, onAction)
  );
}

// --- Card dispatcher ---
function renderCard(card, onAction) {
  if (!card) return null;
  var type = card.type || 'TextCard';

  switch (type) {
    case 'DraftCard': return renderDraftCard(card, onAction);
    case 'NextActionCard': return renderNextActionCard(card, onAction);
    case 'SignalCard': return renderSignalCard(card, onAction);
    case 'ContactSummaryCard':
    case 'CompanySummaryCard': return renderSummaryCard(card, onAction);
    case 'TouchpointLogCard': return renderTouchpointCard(card, onAction);
    case 'FollowUpCard': return renderFollowUpCard(card, onAction);
    case 'ExportCard': return renderExportCard(card, onAction);
    case 'ConfirmationCard': return renderConfirmationCard(card);
    case 'ErrorCard': return renderErrorCard(card);
    case 'StrategyCard': return renderStrategyCard(card, onAction);
    case 'ClaudePromptCard': return renderClaudePromptCard(card, onAction);
    case 'ContactInsightCard': return renderContactInsightCard(card, onAction);
    case 'SignalInsightCard': return renderSignalInsightCard(card, onAction);
    case 'PerformanceInsightCard': return renderPerformanceInsightCard(card, onAction);
    case 'ExecutionPlanCard': return renderExecutionPlanCard(card, onAction);
    case 'FixCard': return renderFixCard(card, onAction);
    case 'CrmUpdatePreviewCard': return renderCrmUpdatePreviewCard(card, onAction);
    case 'AmbiguityCard': return renderAmbiguityCard(card, onAction);
    case 'DailyPlanCard': return renderDailyPlanCard(card, onAction);
    case 'SprintCard': return renderSprintCard(card, onAction);
    case 'InsightCard': return renderInsightCard(card, onAction);
    case 'QueueCard': return renderQueueCard(card, onAction);
    case 'BatchDraftCard': return renderBatchDraftCard(card, onAction);
    case 'ApprovalQueueCard': return renderApprovalQueueCard(card, onAction);
    case 'ProbabilityCard': return renderProbabilityCard(card, onAction);
    case 'RelationshipCard': return renderRelationshipCard(card, onAction);
    case 'FunnelCard': return renderFunnelCard(card, onAction);
    case 'PredictionCard': return renderPredictionCard(card, onAction);
    case 'AutomationCard': return renderAutomationCard(card, onAction);
    case 'BriefCard': return renderBriefCard(card, onAction);
    case 'MeetingCard': return renderMeetingCard(card, onAction);
    default: return null;
  }
}

// --- Main component ---
function BTRAssistantChat(props) {
  var user = props.user;
  var activeTab = props.activeTab || '';

  var _s = useState(false); var open = _s[0]; var setOpen = _s[1];
  var _m = useState([]); var messages = _m[0]; var setMessages = _m[1];
  var _i = useState(''); var input = _i[0]; var setInput = _i[1];
  var _l = useState(false); var loading = _l[0]; var setLoading = _l[1];
  var _a = useState(false); var actionLoading = _a[0]; var setActionLoading = _a[1];
  var _sh = useState(false); var showSlash = _sh[0]; var setShowSlash = _sh[1];
  var _md = useState(null); var lastMode = _md[0]; var setLastMode = _md[1];
  var _sp = useState(null); var sprint = _sp[0]; var setSprint = _sp[1];
  var _pf = useState(false); var proactiveFetched = _pf[0]; var setProactiveFetched = _pf[1];
  var _ib = useState(0); var insightBadge = _ib[0]; var setInsightBadge = _ib[1];
  var scrollRef = useRef(null);
  var inputRef = useRef(null);

  useEffect(function() {
    if (open && inputRef.current) inputRef.current.focus();
  }, [open]);

  useEffect(function() {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages, loading]);

  // Proactive: fetch insights + gameplan on first open
  useEffect(function() {
    if (!open || proactiveFetched) return;
    setProactiveFetched(true);

    // Fetch insights
    fetch(getApiBase() + '/api/assistant/insights')
      .then(function(r) { return r.json(); })
      .then(function(d) {
        var insights = d.insights || [];
        if (insights.length > 0) {
          var insightCard = {
            type: 'InsightCard',
            text: '',
            data: { insights: insights },
            actions: []
          };
          // Add a start sprint button if any high-impact insight suggests it
          var hasSprint = insights.some(function(ins) { return ins.action_type === 'start_sprint'; });
          if (hasSprint) {
            insightCard.actions.push({ id: 'start_sprint_insight', label: 'Start Sprint', action: 'start_sprint', params: {} });
          }
          setMessages(function(prev) {
            return prev.concat([{ role: 'assistant', card: insightCard, mode: 'analyst' }]);
          });
        }
      })
      .catch(function() {});

    // Fetch daily gameplan
    fetch(getApiBase() + '/api/assistant/gameplan')
      .then(function(r) { return r.json(); })
      .then(function(d) {
        var plan = d.plan || [];
        if (plan.length > 0) {
          var planCard = {
            type: 'DailyPlanCard',
            text: '',
            data: { plan: plan, total_minutes: d.total_minutes, date: d.date },
            actions: [
              { id: 'start_sprint_plan', label: 'Start Sprint', action: 'start_sprint', params: {} },
              { id: 'view_opps', label: 'Top Opportunities', action: 'show_opportunities', params: { opportunities: d.opportunities || [] } }
            ]
          };
          setMessages(function(prev) {
            return prev.concat([{ role: 'assistant', card: planCard, mode: 'execution' }]);
          });
        }
      })
      .catch(function() {});
  }, [open, proactiveFetched]);

  // Proactive: initial badge check on mount + periodic polling
  useEffect(function() {
    fetch(getApiBase() + '/api/assistant/insights')
      .then(function(r) { return r.json(); })
      .then(function(d) {
        var highImpact = (d.insights || []).filter(function(ins) { return ins.impact >= 80; });
        setInsightBadge(highImpact.length);
      })
      .catch(function() {});

    var interval = setInterval(function() {
      fetch(getApiBase() + '/api/assistant/insights')
        .then(function(r) { return r.json(); })
        .then(function(d) {
          var highImpact = (d.insights || []).filter(function(ins) { return ins.impact >= 80; });
          setInsightBadge(highImpact.length);
        })
        .catch(function() {});
    }, 5 * 60 * 1000);
    return function() { clearInterval(interval); };
  }, []);

  var handleAction = function(act) {
    // Sprint start intercept
    if (act.action === 'start_sprint') {
      fetch(getApiBase() + '/api/assistant/sprint', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'start' })
      })
        .then(function(r) { return r.json(); })
        .then(function(d) {
          if (d.sprint) {
            var sp = d.sprint;
            if (sp.tasks.length > 0) sp.tasks[0].status = 'current';
            setSprint(sp);
            var sprintCard = {
              type: 'SprintCard',
              text: 'Sprint started! Focus on these ' + sp.tasks.length + ' tasks.',
              data: sp,
              actions: []
            };
            setMessages(function(prev) {
              return prev.concat([{ role: 'assistant', card: sprintCard, mode: 'execution' }]);
            });
          }
        })
        .catch(function() {});
      return;
    }

    // Sprint task completion
    if (act.action === 'complete_sprint_task' && sprint) {
      var taskId = act.params && act.params.task_id;
      var updatedTasks = sprint.tasks.map(function(t) {
        if (t.id === taskId) return Object.assign({}, t, { status: 'done' });
        return t;
      });
      var doneCount = updatedTasks.filter(function(t) { return t.status === 'done'; }).length;
      var nextPending = updatedTasks.find(function(t) { return t.status === 'pending'; });
      if (nextPending) nextPending.status = 'current';
      var updatedSprint = Object.assign({}, sprint, { tasks: updatedTasks, completed: doneCount });
      setSprint(updatedSprint);

      fetch(getApiBase() + '/api/assistant/sprint', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'complete_task', task_id: taskId, original_task_id: act.params && act.params.original_task_id })
      }).catch(function() {});

      var progressCard = {
        type: 'SprintCard',
        text: doneCount >= updatedSprint.total ? 'Sprint complete!' : 'Task done! ' + (updatedSprint.total - doneCount) + ' remaining.',
        data: updatedSprint,
        actions: []
      };
      setMessages(function(prev) {
        return prev.concat([{ role: 'assistant', card: progressCard, mode: 'execution' }]);
      });
      return;
    }

    // Show opportunities card
    if (act.action === 'show_opportunities') {
      var opps = (act.params && act.params.opportunities) || [];
      if (opps.length > 0) {
        var recs = opps.map(function(o) {
          return { priority: o.score >= 70 ? 'high' : (o.score >= 40 ? 'medium' : 'low'), action: 'Engage ' + o.name, target: o.name + ' (score: ' + o.score + ')', reason: o.reason };
        });
        setMessages(function(prev) {
          return prev.concat([{ role: 'assistant', card: { type: 'NextActionCard', text: 'Top Opportunities — ranked by composite score', data: { recommendations: recs }, actions: [] }, mode: 'analyst' }]);
        });
      }
      return;
    }

    executeCardAction(act, messages, setMessages, setActionLoading);
  };

  var sendMessage = function() {
    var text = input.trim();
    if (!text || loading) return;

    var newMsgs = messages.concat([{ role: 'user', content: text }]);
    setMessages(newMsgs);
    setInput('');
    setShowSlash(false);
    setLoading(true);

    var pageCtx = { active_tab: activeTab };

    fetch(getApiBase() + '/api/assistant/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages: newMsgs, page_context: pageCtx })
    })
      .then(function(r) { return r.json(); })
      .then(function(d) {
        var card = d.card || null;

        // Frontend safety net: if card is TextCard but content has card-like markers, try to recover
        if ((!card || card.type === 'TextCard') && d.content) {
          var recovered = tryRecoverCard(d.content);
          if (recovered) card = recovered;
        }

        // Sanitize card text on receipt — never display raw backend syntax
        if (card && card.text) {
          card.text = sanitizeDisplayText(card.text);
        }
        var cardText = card ? (card.text || '') : '';
        var rawContent = sanitizeDisplayText(d.content || '');
        // Use card text first, fall back to content, never leave blank
        var text = cardText || rawContent || '';
        setMessages(function(prev) {
          return prev.concat([{ role: 'assistant', content: text, card: card, mode: d.mode, intent: d.intent }]);
        });
        if (d.mode) setLastMode(d.mode);
        setLoading(false);
      })
      .catch(function() {
        setMessages(function(prev) {
          return prev.concat([{ role: 'assistant', content: 'Connection error.', card: {
            type: 'ErrorCard', text: 'Connection error.', data: { error: 'Network', suggestion: 'Check your connection.' }, actions: []
          }}]);
        });
        setLoading(false);
      });
  };

  var handleKeyDown = function(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  var handleInputChange = function(e) {
    var val = e.target.value;
    setInput(val);
    setShowSlash(val === '/' || (val.startsWith('/') && val.indexOf(' ') === -1 && val.length < 10));
  };

  var pickSlash = function(cmd) {
    setInput(cmd + ' ');
    setShowSlash(false);
    if (inputRef.current) inputRef.current.focus();
  };

  // --- Closed state (FAB) ---
  if (!open) {
    return h('div', { style: { position: 'fixed', bottom: '1.5rem', right: '1.5rem', zIndex: 9990 } },
      h('button', {
        onClick: function() { setOpen(true); },
        style: {
          width: '48px', height: '48px', borderRadius: '50%',
          background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
          border: '2px solid #334155',
          color: '#f8fafc', fontSize: '1.2rem', cursor: 'pointer',
          boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          transition: 'transform 0.15s, box-shadow 0.15s'
        },
        onMouseEnter: function(e) { e.currentTarget.style.transform = 'scale(1.08)'; },
        onMouseLeave: function(e) { e.currentTarget.style.transform = 'scale(1)'; }
      }, '✨'),
      insightBadge > 0 ? h('span', {
        style: {
          position: 'absolute', top: '-4px', right: '-4px',
          background: '#dc2626', color: '#fff', fontSize: '0.55rem', fontWeight: 700,
          width: '18px', height: '18px', borderRadius: '50%',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          border: '2px solid #fff', boxShadow: '0 1px 3px rgba(0,0,0,0.2)'
        }
      }, insightBadge) : null
    );
  }

  // --- Open state ---
  return h('div', {
    style: {
      position: 'fixed', bottom: '1.5rem', right: '1.5rem', zIndex: 9990,
      width: '420px', height: '600px', maxHeight: 'calc(100vh - 4rem)',
      background: '#FFFFFF', border: '1px solid #e2e8f0',
      borderRadius: '0.75rem', boxShadow: '0 8px 32px rgba(0,0,0,0.15)',
      display: 'flex', flexDirection: 'column', overflow: 'hidden',
      fontFamily: "'Inter', -apple-system, sans-serif",
      animation: 'fadeInUp 0.2s ease-out'
    }
  },
    // Header
    h('div', {
      style: {
        padding: '0.6rem 0.85rem',
        background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
        color: '#f8fafc',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        flexShrink: 0
      }
    },
      h('div', { style: { display: 'flex', alignItems: 'center', gap: '0.5rem' } },
        h('span', { style: { fontSize: '0.78rem', fontWeight: 700, background: 'linear-gradient(135deg, #14b8a6, #3b82f6)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' } }, 'L'),
        h('span', {
          style: { fontFamily: "'Orbitron', sans-serif", fontSize: '0.72rem', fontWeight: 700, letterSpacing: '0.05em' }
        }, 'LEO'),
        h('span', { style: { fontSize: '0.55rem', color: '#94a3b8', fontWeight: 400, marginLeft: '0.2rem' } }, 'Operator AI'),
        lastMode ? h('span', { style: { fontSize: '0.5rem', color: MODE_COLORS[lastMode] || '#94a3b8', background: (MODE_COLORS[lastMode] || '#94a3b8') + '22', padding: '0.08rem 0.3rem', borderRadius: '0.2rem', fontWeight: 600, marginLeft: '0.3rem' } }, MODE_LABELS[lastMode] || lastMode) : null
      ),
      h('div', { style: { display: 'flex', alignItems: 'center', gap: '0.3rem' } },
        h('button', {
          onClick: function() { setMessages([]); setLastMode(null); },
          title: 'Clear chat',
          style: {
            background: 'none', border: 'none', color: '#64748b', fontSize: '0.7rem',
            cursor: 'pointer', padding: '0.15rem 0.35rem'
          }
        }, 'Clear'),
        h('button', {
          onClick: function() { setOpen(false); },
          style: {
            background: 'none', border: 'none', color: '#94a3b8', fontSize: '1.1rem',
            cursor: 'pointer', padding: '0.1rem 0.3rem', lineHeight: 1
          }
        }, '✕')
      )
    ),

    // Messages
    h('div', {
      ref: scrollRef,
      style: {
        flex: 1, overflowY: 'auto', padding: '0.65rem',
        display: 'flex', flexDirection: 'column', gap: '0.45rem'
      }
    },
      // Empty state
      messages.length === 0 && h('div', {
        style: { textAlign: 'center', padding: '1.2rem 0.75rem', color: '#94a3b8' }
      },
        h('div', { style: { fontSize: '1.3rem', marginBottom: '0.4rem', opacity: 0.3, fontWeight: 900, fontFamily: "'Orbitron', sans-serif", background: 'linear-gradient(135deg, #14b8a6, #3b82f6)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' } }, 'L'),
        h('div', { style: { fontSize: '0.82rem', fontWeight: 600, marginBottom: '0.25rem', color: '#475569' } }, 'Leo — Operator AI'),
        h('div', { style: { fontSize: '0.68rem', lineHeight: 1.5, marginBottom: '0.5rem', color: '#94a3b8' } },
          'Ask me anything — strategy, outreach, data, or actions'
        ),
        h('div', { style: { fontSize: '0.62rem', color: '#94a3b8', marginBottom: '0.5rem' } }, 'Ask me anything, or type / for commands'),
        h('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.25rem' } },
          [
            'How should I approach my top prospects?',
            "I talked to Material Capital but don't want to bother them",
            "What's working in my outreach right now?",
            '/queue',
            '/funnel'
          ].map(function(q) {
            return h('button', {
              key: q,
              onClick: function() { setInput(q); if (inputRef.current) inputRef.current.focus(); },
              style: {
                background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '0.35rem',
                padding: '0.35rem 0.55rem', fontSize: '0.7rem', color: '#475569',
                cursor: 'pointer', textAlign: 'left', fontFamily: "'Inter', sans-serif",
                transition: 'border-color 0.15s'
              },
              onMouseEnter: function(e) { e.currentTarget.style.borderColor = '#94a3b8'; },
              onMouseLeave: function(e) { e.currentTarget.style.borderColor = '#e2e8f0'; }
            }, q);
          })
        )
      ),

      // Message list
      messages.map(function(m, i) {
        var isUser = m.role === 'user';

        if (isUser) {
          return h('div', { key: i, style: { display: 'flex', justifyContent: 'flex-end' } },
            h('div', {
              style: {
                maxWidth: '85%',
                background: '#0f172a', color: '#f8fafc',
                borderRadius: '0.55rem 0.55rem 0.1rem 0.55rem',
                padding: '0.45rem 0.65rem',
                fontSize: '0.76rem', lineHeight: 1.5,
                whiteSpace: 'pre-wrap', wordBreak: 'break-word'
              }
            }, m.content)
          );
        }

        // Assistant message
        var modeLabel = m.mode && MODE_LABELS[m.mode];
        var modeColor = m.mode && MODE_COLORS[m.mode];
        var hasCard = m.card && m.card.type && m.card.type !== 'TextCard';
        var isTextCard = m.card && m.card.type === 'TextCard';
        var isLastMsg = i === messages.length - 1;
        var cardText = m.card && m.card.text ? sanitizeDisplayText(m.card.text) : '';
        var contentText = m.content ? sanitizeDisplayText(m.content) : '';
        // Guarantee: at least one of cardText or contentText must be non-empty for display
        var displayText = cardText || contentText;
        var showTextBubble = isTextCard ? !!displayText : (!hasCard && !!displayText);

        return h('div', { key: i, style: { display: 'flex', justifyContent: 'flex-start', maxWidth: '95%' } },
          h('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.25rem', width: '100%' } },
            // Mode badge
            modeLabel ? h('div', { style: { fontSize: '0.55rem', fontWeight: 600, color: modeColor || '#64748b', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '-0.1rem' } }, modeLabel + ' mode') : null,

            // Structured card (non-TextCard): render the card widget
            hasCard ? renderCard(m.card, handleAction) : null,

            // Text bubble: TextCard text, content text, or any text alongside structured cards
            showTextBubble ? h('div', {
              style: {
                background: '#f8fafc', border: '1px solid #e2e8f0',
                borderRadius: '0.55rem 0.55rem 0.55rem 0.1rem',
                padding: '0.55rem 0.7rem',
                fontSize: '0.76rem', lineHeight: 1.55, color: '#1e293b',
                wordBreak: 'break-word'
              }
            }, isLastMsg && !loading ? h(TypingText, { text: displayText }) : renderMarkdownText(displayText)) : null,

            // Structured card with text alongside it
            hasCard && contentText && !cardText ? h('div', {
              style: {
                background: '#f8fafc', border: '1px solid #e2e8f0',
                borderRadius: '0.55rem 0.55rem 0.55rem 0.1rem',
                padding: '0.45rem 0.65rem',
                fontSize: '0.76rem', lineHeight: 1.5, color: '#1e293b',
                wordBreak: 'break-word'
              }
            }, renderMarkdownText(contentText)) : null
          )
        );
      }),

      // Loading indicator
      loading && h('div', { style: { display: 'flex', justifyContent: 'flex-start' } },
        h('div', {
          style: {
            background: '#f8fafc', border: '1px solid #e2e8f0',
            borderRadius: '0.55rem 0.55rem 0.55rem 0.1rem',
            padding: '0.45rem 0.65rem', fontSize: '0.76rem', color: '#94a3b8'
          }
        },
          h('span', { style: { display: 'inline-flex', alignItems: 'center', gap: '0.3rem' } },
            h('span', { style: { animation: 'pulse 1.2s ease-in-out infinite' } }, 'Leo is thinking'),
            h('span', { style: { animation: 'pulse 1.2s ease-in-out infinite 0.2s' } }, '.'),
            h('span', { style: { animation: 'pulse 1.2s ease-in-out infinite 0.4s' } }, '.'),
            h('span', { style: { animation: 'pulse 1.2s ease-in-out infinite 0.6s' } }, '.')
          )
        )
      )
    ),

    // Slash command hints
    showSlash && h('div', {
      style: {
        position: 'absolute', bottom: '52px', left: '0.5rem', right: '0.5rem',
        background: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '0.5rem',
        boxShadow: '0 -4px 12px rgba(0,0,0,0.08)', padding: '0.35rem',
        display: 'flex', flexDirection: 'column', gap: '0.1rem', zIndex: 10
      }
    },
      SLASH_HINTS.filter(function(s) {
        return !input || input === '/' || s.cmd.startsWith(input.toLowerCase());
      }).map(function(s) {
        return h('button', {
          key: s.cmd,
          onClick: function() { pickSlash(s.cmd); },
          style: {
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            background: 'transparent', border: 'none', padding: '0.3rem 0.5rem',
            cursor: 'pointer', borderRadius: '0.3rem', fontFamily: "'Inter', sans-serif",
            transition: 'background 0.1s', width: '100%', textAlign: 'left'
          },
          onMouseEnter: function(e) { e.currentTarget.style.background = '#f1f5f9'; },
          onMouseLeave: function(e) { e.currentTarget.style.background = 'transparent'; }
        },
          h('span', { style: { fontSize: '0.72rem', fontWeight: 600, color: '#0f172a', fontFamily: "'JetBrains Mono', monospace" } }, s.cmd),
          h('span', { style: { fontSize: '0.65rem', color: '#94a3b8' } }, s.desc)
        );
      })
    ),

    // Input bar
    h('div', {
      style: {
        padding: '0.45rem 0.65rem', borderTop: '1px solid #e2e8f0',
        display: 'flex', gap: '0.35rem', flexShrink: 0, background: '#FFFFFF'
      }
    },
      h('textarea', {
        ref: inputRef,
        value: input,
        onChange: handleInputChange,
        onKeyDown: handleKeyDown,
        placeholder: 'Ask Leo anything or type / for commands…',
        rows: 1,
        style: {
          flex: 1, resize: 'none', border: '1px solid #e2e8f0',
          borderRadius: '0.4rem', padding: '0.45rem 0.6rem',
          fontSize: '0.76rem', fontFamily: "'Inter', sans-serif",
          color: '#1e293b', background: '#f8fafc', outline: 'none',
          lineHeight: 1.4, maxHeight: '72px', overflowY: 'auto'
        }
      }),
      h('button', {
        onClick: sendMessage,
        disabled: loading || !input.trim(),
        style: {
          background: loading || !input.trim() ? '#cbd5e1' : 'linear-gradient(135deg, #0f172a, #1e293b)',
          border: 'none', color: '#f8fafc', borderRadius: '0.4rem',
          padding: '0.45rem 0.7rem', fontSize: '0.78rem', fontWeight: 600,
          cursor: loading || !input.trim() ? 'default' : 'pointer',
          fontFamily: "'Inter', sans-serif", flexShrink: 0
        }
      }, '→')
    )
  );
}

window.BTRAssistantChat = BTRAssistantChat;
})();
