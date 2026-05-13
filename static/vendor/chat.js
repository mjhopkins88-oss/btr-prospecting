/* BTR Command — AI Chat Component (chat.js)
   Structured response cards, action buttons, slash commands, CRM-aware */
(function() {
'use strict';
var h = React.createElement;
var useState = React.useState;
var useEffect = React.useEffect;
var useRef = React.useRef;

// --- Styles ---
var CARD_COLORS = {
  DraftCard:          { bg: '#f0fdf4', border: '#bbf7d0', accent: '#15803d', icon: '✉️' },
  NextActionCard:     { bg: '#eff6ff', border: '#bfdbfe', accent: '#1d4ed8', icon: '🎯' },
  SignalCard:         { bg: '#fefce8', border: '#fde68a', accent: '#a16207', icon: '⚡' },
  ContactSummaryCard: { bg: '#f0f9ff', border: '#bae6fd', accent: '#0369a1', icon: '👤' },
  CompanySummaryCard: { bg: '#faf5ff', border: '#e9d5ff', accent: '#7c3aed', icon: '🏢' },
  TouchpointLogCard:  { bg: '#ecfdf5', border: '#a7f3d0', accent: '#059669', icon: '📝' },
  FollowUpCard:       { bg: '#fff7ed', border: '#fed7aa', accent: '#c2410c', icon: '📅' },
  ExportCard:         { bg: '#f8fafc', border: '#e2e8f0', accent: '#475569', icon: '⬇️' },
  ConfirmationCard:   { bg: '#f0fdf4', border: '#86efac', accent: '#16a34a', icon: '✅' },
  ErrorCard:          { bg: '#fef2f2', border: '#fecaca', accent: '#dc2626', icon: '⚠️' },
  TextCard:           { bg: '#f8fafc', border: '#e2e8f0', accent: '#64748b', icon: '💬' }
};

var SLASH_HINTS = [
  { cmd: '/draft', desc: 'Draft outreach', ex: '/draft Ethan' },
  { cmd: '/log', desc: 'Log touchpoint', ex: '/log Called about deal' },
  { cmd: '/next', desc: 'Top action', ex: '/next' },
  { cmd: '/brief', desc: 'Daily briefing', ex: '/brief' },
  { cmd: '/export', desc: 'Export data', ex: '/export contacts' },
  { cmd: '/signal', desc: 'Latest signals', ex: '/signal Acme Corp' },
  { cmd: '/sprint', desc: 'Work sprint', ex: '/sprint' }
];

// --- Action button handler ---
function executeCardAction(act, messages, setMessages, setActionLoading) {
  if (!act) return;

  if (act.action === 'copy_text' || act.action === 'copy_draft') {
    return;
  }

  if (act.action === 'download') {
    var a = document.createElement('a');
    a.href = (act.params && act.params.url) || '';
    a.download = '';
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

  setActionLoading(act.id || true);
  fetch(API_BASE + '/api/assistant/execute-action', {
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

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.6rem 0.7rem' } },
    h('div', { style: { display: 'flex', alignItems: 'center', gap: '0.3rem', marginBottom: '0.3rem', fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em' } },
      colors.icon, ' ', channelLabel, ' Draft',
      d.target_name ? h('span', { style: { fontWeight: 400, color: '#4b5563', textTransform: 'none' } }, ' — ' + d.target_name) : null
    ),
    d.subject ? h('div', { style: { fontWeight: 600, color: '#1e293b', marginBottom: '0.25rem', fontSize: '0.74rem' } }, d.subject) : null,
    h('div', { style: { color: '#374151', whiteSpace: 'pre-wrap', lineHeight: 1.5, fontSize: '0.72rem', maxHeight: '180px', overflowY: 'auto', background: '#ffffff', borderRadius: '0.35rem', padding: '0.5rem', border: '1px solid ' + colors.border } }, d.body || ''),
    card.source ? h('div', { style: { marginTop: '0.3rem', fontSize: '0.63rem', color: '#6b7280', fontStyle: 'italic' } }, card.source) : null,
    renderActionButtons(card.actions, onAction, d)
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
          s.summary ? h('div', { style: { fontSize: '0.65rem', color: '#64748b', marginTop: '0.15rem' } }, s.summary.substring(0, 120)) : null,
          s.source_url ? h('a', { href: s.source_url, target: '_blank', rel: 'noopener', style: { fontSize: '0.6rem', color: '#2563eb', textDecoration: 'none' } }, 'View source →') : null
        );
      })
    ) : h('div', { style: { fontSize: '0.74rem', color: '#64748b' } }, 'No signals found.'),
    renderActionButtons(card.actions, onAction)
  );
}

function renderSummaryCard(card, onAction, icon, accentColor) {
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
    d.summary ? h('div', { style: { fontSize: '0.7rem', color: '#64748b', fontStyle: 'italic' } }, '"' + d.summary + '"') : null,
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

  return h('div', { style: { background: colors.bg, border: '1px solid ' + colors.border, borderRadius: '0.5rem', padding: '0.6rem 0.7rem' } },
    h('div', { style: { fontSize: '0.68rem', fontWeight: 700, color: colors.accent, textTransform: 'uppercase', letterSpacing: '0.03em', marginBottom: '0.25rem' } }, colors.icon + ' Export Ready'),
    h('div', { style: { fontSize: '0.74rem', color: '#1e293b' } }, d.export_type || 'Data'),
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
  var scrollRef = useRef(null);
  var inputRef = useRef(null);

  useEffect(function() {
    if (open && inputRef.current) inputRef.current.focus();
  }, [open]);

  useEffect(function() {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages, loading]);

  var handleAction = function(act) {
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

    fetch(API_BASE + '/api/assistant/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages: newMsgs, page_context: pageCtx })
    })
      .then(function(r) { return r.json(); })
      .then(function(d) {
        var card = d.card || null;
        var text = card ? (card.text || '') : (d.content || '');
        setMessages(function(prev) {
          return prev.concat([{ role: 'assistant', content: text, card: card }]);
        });
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
    return h('button', {
      onClick: function() { setOpen(true); },
      style: {
        position: 'fixed', bottom: '1.5rem', right: '1.5rem', zIndex: 9990,
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
    }, '✨');
  }

  // --- Open state ---
  return h('div', {
    style: {
      position: 'fixed', bottom: '1.5rem', right: '1.5rem', zIndex: 9990,
      width: '400px', height: '560px', maxHeight: 'calc(100vh - 4rem)',
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
        h('span', { style: { fontSize: '0.85rem' } }, '✨'),
        h('span', {
          style: { fontFamily: "'Orbitron', sans-serif", fontSize: '0.72rem', fontWeight: 700, letterSpacing: '0.05em' }
        }, 'BTR COMMAND'),
        h('span', { style: { fontSize: '0.58rem', color: '#94a3b8', fontWeight: 400, marginLeft: '0.3rem' } }, 'AI')
      ),
      h('div', { style: { display: 'flex', alignItems: 'center', gap: '0.3rem' } },
        h('button', {
          onClick: function() { setMessages([]); },
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
        style: { textAlign: 'center', padding: '1.5rem 0.75rem', color: '#94a3b8' }
      },
        h('div', { style: { fontSize: '1.3rem', marginBottom: '0.4rem', opacity: 0.25 } }, '✨'),
        h('div', { style: { fontSize: '0.8rem', fontWeight: 500, marginBottom: '0.25rem', color: '#475569' } }, 'How can I help?'),
        h('div', { style: { fontSize: '0.68rem', lineHeight: 1.5, marginBottom: '0.6rem' } },
          'Draft outreach, log touchpoints, get next actions, or ask about your CRM data.'
        ),
        h('div', { style: { fontSize: '0.62rem', color: '#94a3b8', marginBottom: '0.5rem' } }, 'Try a slash command: /draft, /next, /brief, /sprint'),
        h('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.25rem' } },
          [
            'Who needs a follow-up?',
            '/draft my warmest contact',
            '/next',
            '/sprint'
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
        return h('div', { key: i, style: { display: 'flex', justifyContent: 'flex-start', maxWidth: '92%' } },
          h('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.25rem', width: '100%' } },
            // Card rendering
            m.card ? renderCard(m.card, handleAction) : null,

            // Text fallback (only if no card or TextCard with content)
            (!m.card && m.content) ? h('div', {
              style: {
                background: '#f8fafc', border: '1px solid #e2e8f0',
                borderRadius: '0.55rem 0.55rem 0.55rem 0.1rem',
                padding: '0.45rem 0.65rem',
                fontSize: '0.76rem', lineHeight: 1.5, color: '#1e293b',
                whiteSpace: 'pre-wrap', wordBreak: 'break-word'
              }
            }, m.content) : null,

            // TextCard shows text in bubble style
            (m.card && m.card.type === 'TextCard' && m.card.text) ? h('div', {
              style: {
                background: '#f8fafc', border: '1px solid #e2e8f0',
                borderRadius: '0.55rem 0.55rem 0.55rem 0.1rem',
                padding: '0.45rem 0.65rem',
                fontSize: '0.76rem', lineHeight: 1.5, color: '#1e293b',
                whiteSpace: 'pre-wrap', wordBreak: 'break-word'
              }
            }, m.card.text) : null,

            // Non-TextCard shows text above the card
            (m.card && m.card.type !== 'TextCard' && m.card.text) ? h('div', {
              style: { fontSize: '0.74rem', color: '#475569', marginBottom: '0.1rem' }
            }, m.card.text) : null
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
        }, 'Thinking…')
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
        placeholder: 'Ask anything or type / for commands…',
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
