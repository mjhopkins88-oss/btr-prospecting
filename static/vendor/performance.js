window.PerformancePage = function PerformancePage() {
  var useState = React.useState;
  var useEffect = React.useEffect;
  var API_BASE = window.location.hostname === 'localhost' ? 'http://localhost:5000' : window.location.origin;

  var _today = new Date().toISOString().slice(0, 10);
  var _month = _today.slice(0, 7);

  function _lsGet(key, fallback) { try { var v = localStorage.getItem(key); return v !== null ? JSON.parse(v) : fallback; } catch(e) { return fallback; } }
  function _lsSet(key, val) { try { localStorage.setItem(key, JSON.stringify(val)); } catch(e) {} }

  var _wo = useState(function() { return _lsGet('perf_workout_' + _today, false); });
  var workout = _wo[0]; var setWorkout = _wo[1];
  var _sq = useState(function() { return _lsGet('perf_squats_' + _today, 0); });
  var squats = _sq[0]; var setSquats = _sq[1];
  var _rev = useState(function() { return _lsGet('perf_revenue_' + _month, 0); });
  var revenue = _rev[0]; var setRevenue = _rev[1];
  var _tgt = useState(function() { return _lsGet('perf_target_' + _month, 50000); });
  var revTarget = _tgt[0]; var setRevTarget = _tgt[1];
  var _editRev = useState(false); var editingRev = _editRev[0]; var setEditingRev = _editRev[1];
  var _editTgt = useState(false); var editingTgt = _editTgt[0]; var setEditingTgt = _editTgt[1];
  var _eng = useState(null); var eng = _eng[0]; var setEng = _eng[1];
  var _lt = useState(''); var logText = _lt[0]; var setLogText = _lt[1];
  var _lc = useState(null); var logConfirm = _lc[0]; var setLogConfirm = _lc[1];
  var _fc = useState(function() { return _lsGet('perf_focus_' + _today, ''); });
  var focus = _fc[0]; var setFocus = _fc[1];
  var _fl = useState(function() { var f = _lsGet('perf_focus_' + _today, ''); return f.length > 0; });
  var focusLocked = _fl[0]; var setFocusLocked = _fl[1];

  useEffect(function() { _lsSet('perf_workout_' + _today, workout); }, [workout]);
  useEffect(function() { _lsSet('perf_squats_' + _today, squats); }, [squats]);
  useEffect(function() { _lsSet('perf_revenue_' + _month, revenue); }, [revenue]);
  useEffect(function() { _lsSet('perf_target_' + _month, revTarget); }, [revTarget]);
  useEffect(function() { _lsSet('perf_focus_' + _today, focus); }, [focus]);

  useEffect(function() {
    fetch(API_BASE + '/api/prospecting/engagement')
      .then(function(r) { return r.ok ? r.json() : null; })
      .then(function(d) { if (d) setEng(d); })
      .catch(function() {});
  }, []);

  var touchpoints = eng ? eng.today_touchpoints : 0;
  var followups = eng ? (eng.daily_checklist || {}).followups || 0 : 0;
  var relActions = eng ? (eng.daily_checklist || {}).relationship || 0 : 0;
  var callsMeetings = eng ? ((eng.daily_checklist || {}).followups || 0) + ((eng.daily_checklist || {}).outreach || 0) : 0;
  var engMomentum = eng ? (eng.momentum || 'low') : 'low';

  var todayHasActivity = workout || touchpoints > 0 || followups > 0 || relActions > 0;
  var dayOfWeek = new Date().getDay();
  var isWeekday = dayOfWeek >= 1 && dayOfWeek <= 5;
  var serverStreak = eng ? eng.streak : 0;
  var streak = serverStreak;
  if (isWeekday && todayHasActivity && serverStreak === 0) streak = 1;
  if (isWeekday && !todayHasActivity && serverStreak > 0) streak = serverStreak - 1;

  var revPct = revTarget > 0 ? revenue / revTarget : 0;
  var daily = _perfScore(workout, squats, touchpoints, followups, relActions, revPct);
  var weeklyTp = eng ? (eng.week_tp_count || 0) : 0;
  var weeklyGoal = eng ? (eng.weekly_goal || 40) : 40;
  var weekly = Math.min(100, Math.round((weeklyTp / weeklyGoal) * 100));
  var momentum = engMomentum === 'high' ? 'HIGH' : engMomentum === 'building' ? 'BUILDING' : 'SLIPPING';

  var momentumColors = {
    HIGH: { color: '#10b981', bg: 'rgba(16,185,129,0.08)', border: 'rgba(16,185,129,0.25)' },
    BUILDING: { color: '#f59e0b', bg: 'rgba(245,158,11,0.08)', border: 'rgba(245,158,11,0.25)' },
    SLIPPING: { color: '#ef4444', bg: 'rgba(239,68,68,0.08)', border: 'rgba(239,68,68,0.25)' }
  };
  var mc = momentumColors[momentum] || momentumColors.BUILDING;

  var cardStyle = {
    flex: '1 1 0',
    background: '#FFFFFF',
    border: '1px solid rgba(226,232,240,0.5)',
    borderRadius: '0.75rem',
    padding: '1.1rem 1.25rem',
    minWidth: '140px'
  };
  var labelStyle = {
    fontSize: '0.7rem',
    color: '#64748b',
    textTransform: 'uppercase',
    fontWeight: 700,
    letterSpacing: '0.06em',
    marginBottom: '0.35rem',
    fontFamily: "'Inter', sans-serif"
  };
  var valueStyle = {
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: '1.7rem',
    fontWeight: 700,
    color: '#0f172a',
    lineHeight: 1.2
  };

  function _handleLog() {
    var raw = logText.trim();
    if (!raw) return;
    var low = raw.toLowerCase();
    var num = _extractNum(low);
    var msg = null;

    if (low.indexOf('squat') !== -1) {
      var add = num > 0 ? num : 10;
      setSquats(squats + add);
      msg = '+' + add + ' squats';
    } else if (low.indexOf('workout') !== -1 || low.indexOf('worked out') !== -1 || low.indexOf('gym') !== -1) {
      setWorkout(true);
      msg = 'Workout logged';
    } else if (low.indexOf('deal') !== -1 || low.indexOf('$') !== -1 || low.indexOf('revenue') !== -1 || low.indexOf('closed') !== -1) {
      var amt = num > 0 ? num : 0;
      if (low.indexOf('k') !== -1 && amt < 1000) amt = amt * 1000;
      if (amt > 0) { setRevenue(revenue + amt); msg = '+$' + amt.toLocaleString() + ' revenue'; }
      else { msg = 'No amount found'; }
    } else if (low.indexOf('call') !== -1 || low.indexOf('met ') !== -1 || low.indexOf('meeting') !== -1) {
      msg = 'Call noted (log a touchpoint in CRM to track)';
    } else {
      msg = 'Logged: ' + raw;
    }

    setLogText('');
    if (msg) { setLogConfirm(msg); setTimeout(function() { setLogConfirm(null); }, 2500); }
  }

  return React.createElement('div', { style: { padding: '0' } },
    React.createElement('div', {
      style: { display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.25rem' }
    },
      React.createElement('h2', {
        style: {
          fontFamily: "'Orbitron', sans-serif",
          fontSize: '1.3rem',
          fontWeight: 700,
          color: '#0f172a',
          margin: 0,
          letterSpacing: '0.03em',
          flexShrink: 0
        }
      }, 'Performance'),
      React.createElement('div', { style: { flex: 1, position: 'relative' } },
        React.createElement('input', {
          value: logText,
          onChange: function(e) { setLogText(e.target.value); },
          onKeyDown: function(e) { if (e.key === 'Enter') _handleLog(); },
          placeholder: 'Log anything... "did 20 squats" "worked out" "closed deal 15k"',
          style: {
            width: '100%', padding: '0.55rem 0.85rem', fontSize: '0.82rem',
            fontFamily: "'Inter', sans-serif", background: '#F7F9FC',
            border: '1px solid #e2e8f0', borderRadius: '0.5rem', outline: 'none',
            color: '#1e293b', boxSizing: 'border-box'
          }
        }),
        logConfirm ? React.createElement('div', {
          style: {
            position: 'absolute', top: '100%', left: 0, marginTop: '0.3rem',
            fontSize: '0.72rem', fontWeight: 600, color: '#10b981',
            fontFamily: "'Inter', sans-serif", whiteSpace: 'nowrap'
          }
        }, logConfirm) : null
      )
    ),

    React.createElement('div', {
      style: { display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginBottom: '1.5rem' }
    },
      React.createElement('div', { style: cardStyle },
        React.createElement('div', { style: labelStyle }, 'Daily Score'),
        React.createElement('div', { style: { ...valueStyle, color: '#14b8a6' } }, daily)
      ),
      React.createElement('div', { style: cardStyle },
        React.createElement('div', { style: labelStyle }, 'Weekly Score'),
        React.createElement('div', { style: valueStyle }, weekly)
      ),
      React.createElement('div', { style: cardStyle },
        React.createElement('div', { style: labelStyle }, 'Streak'),
        React.createElement('div', { style: { display: 'flex', alignItems: 'baseline', gap: '0.3rem' } },
          React.createElement('span', { style: { ...valueStyle, color: '#6366f1' } }, streak),
          React.createElement('span', { style: { fontSize: '0.8rem', color: '#94a3b8', fontWeight: 500 } }, 'days')
        )
      ),
      React.createElement('div', { style: { ...cardStyle, borderColor: mc.border, background: mc.bg } },
        React.createElement('div', { style: labelStyle }, 'Momentum'),
        React.createElement('div', { style: { ...valueStyle, color: mc.color, fontSize: '1.4rem' } }, momentum)
      )
    ),

    React.createElement('div', {
      style: {
        background: '#FFFFFF', border: '1px solid rgba(226,232,240,0.5)',
        borderRadius: '0.75rem', padding: '1rem 1.25rem', marginBottom: '1rem',
        display: 'flex', alignItems: 'center', gap: '0.75rem'
      }
    },
      React.createElement('span', {
        style: { fontSize: '0.72rem', color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', fontFamily: "'Inter', sans-serif", flexShrink: 0 }
      }, 'Focus'),
      focusLocked && focus
        ? React.createElement('div', {
            style: { flex: 1, display: 'flex', alignItems: 'center', gap: '0.5rem', minWidth: 0 }
          },
            React.createElement('span', {
              style: { fontSize: '0.92rem', fontWeight: 600, color: '#0f172a', fontFamily: "'Inter', sans-serif" }
            }, focus),
            React.createElement('button', {
              onClick: function() { setFocusLocked(false); },
              style: { background: 'none', border: 'none', color: '#94a3b8', fontSize: '0.68rem', cursor: 'pointer', fontFamily: "'Inter', sans-serif", padding: '0.1rem 0.3rem', flexShrink: 0 }
            }, 'edit')
          )
        : React.createElement('input', {
            value: focus,
            onChange: function(e) { setFocus(e.target.value); },
            onKeyDown: function(e) { if (e.key === 'Enter' && focus.trim()) setFocusLocked(true); },
            placeholder: 'Enter today\'s main focus...',
            style: {
              flex: 1, padding: '0.4rem 0.65rem', fontSize: '0.88rem', fontWeight: 500,
              fontFamily: "'Inter', sans-serif", background: 'transparent',
              border: '1px solid #e2e8f0', borderRadius: '0.4rem', outline: 'none',
              color: '#0f172a', boxSizing: 'border-box'
            }
          })
    ),

    React.createElement('div', {
      style: {
        background: '#FFFFFF',
        border: '1px solid rgba(226,232,240,0.5)',
        borderRadius: '0.75rem',
        padding: '1.25rem',
        marginBottom: '1.5rem'
      }
    },
      React.createElement('h3', {
        style: {
          fontSize: '0.72rem', color: '#64748b', fontWeight: 700,
          textTransform: 'uppercase', letterSpacing: '0.06em',
          margin: '0 0 0.85rem', fontFamily: "'Inter', sans-serif"
        }
      }, 'Today'),

      React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.6rem' } },

        React.createElement('div', {
          style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.55rem 0.7rem', background: workout ? 'rgba(16,185,129,0.06)' : '#F7F9FC', borderRadius: '0.5rem', border: '1px solid ' + (workout ? 'rgba(16,185,129,0.2)' : '#e2e8f0'), cursor: 'pointer', transition: 'all 0.15s' },
          onClick: function() { setWorkout(!workout); }
        },
          React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '0.6rem' } },
            React.createElement('div', {
              style: {
                width: '1.15rem', height: '1.15rem', borderRadius: '0.3rem',
                border: workout ? 'none' : '2px solid #cbd5e1',
                background: workout ? '#10b981' : 'transparent',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: '0.7rem', color: '#FFFFFF', fontWeight: 700, flexShrink: 0
              }
            }, workout ? '✓' : null),
            React.createElement('span', {
              style: { fontSize: '0.85rem', fontWeight: 600, color: workout ? '#10b981' : '#1e293b', fontFamily: "'Inter', sans-serif" }
            }, 'Workout')
          ),
          workout
            ? React.createElement('span', { style: { fontSize: '0.68rem', color: '#10b981', fontWeight: 600 } }, 'DONE')
            : null
        ),

        React.createElement('div', {
          style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.55rem 0.7rem', background: '#F7F9FC', borderRadius: '0.5rem', border: '1px solid #e2e8f0' }
        },
          React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '0.6rem' } },
            React.createElement('span', {
              style: { fontSize: '0.85rem', fontWeight: 600, color: '#1e293b', fontFamily: "'Inter', sans-serif" }
            }, 'Air Squats')
          ),
          React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '0.4rem' } },
            React.createElement('span', {
              style: { fontFamily: "'JetBrains Mono', monospace", fontSize: '0.95rem', fontWeight: 700, color: squats > 0 ? '#6366f1' : '#94a3b8', minWidth: '2rem', textAlign: 'right' }
            }, squats),
            React.createElement('button', {
              onClick: function() { setSquats(squats + 10); },
              style: {
                background: 'rgba(99,102,241,0.08)', border: '1px solid rgba(99,102,241,0.2)',
                color: '#6366f1', padding: '0.2rem 0.5rem', borderRadius: '0.3rem',
                fontSize: '0.7rem', fontWeight: 600, cursor: 'pointer', fontFamily: "'Inter', sans-serif"
              }
            }, '+10'),
            React.createElement('button', {
              onClick: function() { setSquats(squats + 20); },
              style: {
                background: 'rgba(99,102,241,0.08)', border: '1px solid rgba(99,102,241,0.2)',
                color: '#6366f1', padding: '0.2rem 0.5rem', borderRadius: '0.3rem',
                fontSize: '0.7rem', fontWeight: 600, cursor: 'pointer', fontFamily: "'Inter', sans-serif"
              }
            }, '+20')
          )
        ),

        _checklistRow('Touchpoints', touchpoints, '#14b8a6'),
        _checklistRow('Follow-ups', followups, '#f59e0b'),
        _checklistRow('Relationship Actions', relActions, '#3b82f6')
      )
    ),

    _revenueCard(revenue, setRevenue, revTarget, setRevTarget, editingRev, setEditingRev, editingTgt, setEditingTgt),

    _businessOutputCard(touchpoints, callsMeetings, followups, relActions),

    _recoveryCard(daily, touchpoints, revPct, workout, squats, setWorkout, setSquats),

    _weeklySummaryCard(weeklyTp, callsMeetings, workout, followups, weekly, weeklyGoal)
  );
};

function _revenueCard(revenue, setRevenue, target, setTarget, editingRev, setEditingRev, editingTgt, setEditingTgt) {
  var pct = target > 0 ? Math.min(100, Math.round((revenue / target) * 100)) : 0;
  var gap = Math.max(0, target - revenue);
  var barColor = pct >= 100 ? '#10b981' : pct >= 60 ? '#14b8a6' : pct >= 30 ? '#f59e0b' : '#ef4444';

  var sectionLabel = {
    fontSize: '0.72rem', color: '#64748b', fontWeight: 700,
    textTransform: 'uppercase', letterSpacing: '0.06em',
    margin: '0 0 0.85rem', fontFamily: "'Inter', sans-serif"
  };
  var inputStyle = {
    fontFamily: "'JetBrains Mono', monospace", fontSize: '0.85rem', fontWeight: 600,
    color: '#0f172a', background: '#FFFFFF', border: '1px solid #e2e8f0',
    borderRadius: '0.35rem', padding: '0.3rem 0.5rem', width: '8rem', outline: 'none'
  };

  function revDisplay() {
    if (editingRev) {
      return React.createElement('input', {
        type: 'number', autoFocus: true, defaultValue: revenue,
        style: inputStyle,
        onBlur: function(e) { setRevenue(parseFloat(e.target.value) || 0); setEditingRev(false); },
        onKeyDown: function(e) { if (e.key === 'Enter') { e.target.blur(); } }
      });
    }
    return React.createElement('span', {
      style: { fontFamily: "'JetBrains Mono', monospace", fontSize: '1.1rem', fontWeight: 700, color: '#0f172a', cursor: 'pointer' },
      onClick: function() { setEditingRev(true); }
    }, '$' + revenue.toLocaleString());
  }

  function tgtDisplay() {
    if (editingTgt) {
      return React.createElement('input', {
        type: 'number', autoFocus: true, defaultValue: target,
        style: inputStyle,
        onBlur: function(e) { setTarget(parseFloat(e.target.value) || 0); setEditingTgt(false); },
        onKeyDown: function(e) { if (e.key === 'Enter') { e.target.blur(); } }
      });
    }
    return React.createElement('span', {
      style: { fontFamily: "'JetBrains Mono', monospace", fontSize: '0.85rem', fontWeight: 600, color: '#64748b', cursor: 'pointer' },
      onClick: function() { setEditingTgt(true); }
    }, '$' + target.toLocaleString());
  }

  return React.createElement('div', {
    style: { background: '#FFFFFF', border: '1px solid rgba(226,232,240,0.5)', borderRadius: '0.75rem', padding: '1.25rem', marginBottom: '1.5rem' }
  },
    React.createElement('h3', { style: sectionLabel }, 'Revenue'),

    React.createElement('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: '0.6rem' } },
      React.createElement('div', null,
        React.createElement('div', { style: { fontSize: '0.68rem', color: '#94a3b8', fontWeight: 600, marginBottom: '0.15rem' } }, 'CURRENT MONTH'),
        revDisplay()
      ),
      React.createElement('div', { style: { textAlign: 'right' } },
        React.createElement('div', { style: { fontSize: '0.68rem', color: '#94a3b8', fontWeight: 600, marginBottom: '0.15rem' } }, 'TARGET'),
        tgtDisplay()
      )
    ),

    React.createElement('div', {
      style: { height: '0.5rem', background: '#f1f5f9', borderRadius: '9999px', overflow: 'hidden', marginBottom: '0.5rem' }
    },
      React.createElement('div', {
        style: { height: '100%', width: pct + '%', background: barColor, borderRadius: '9999px', transition: 'width 0.3s' }
      })
    ),

    React.createElement('div', { style: { display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', color: '#94a3b8' } },
      React.createElement('span', null, pct + '% of target'),
      gap > 0
        ? React.createElement('span', null, '$' + gap.toLocaleString() + ' remaining')
        : React.createElement('span', { style: { color: '#10b981', fontWeight: 600 } }, 'Target reached!')
    )
  );
}

function _businessOutputCard(tp, calls, fu, rel) {
  var items = [
    { label: 'Touchpoints Today', value: tp, accent: '#14b8a6' },
    { label: 'Calls / Meetings', value: calls, accent: '#3b82f6' },
    { label: 'Follow-ups Completed', value: fu, accent: '#f59e0b' },
    { label: 'Relationships Advanced', value: rel, accent: '#6366f1' }
  ];
  return React.createElement('div', {
    style: { background: '#FFFFFF', border: '1px solid rgba(226,232,240,0.5)', borderRadius: '0.75rem', padding: '1.25rem', marginBottom: '1.5rem' }
  },
    React.createElement('h3', {
      style: { fontSize: '0.72rem', color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', margin: '0 0 0.85rem', fontFamily: "'Inter', sans-serif" }
    }, 'Business Output'),
    React.createElement('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.6rem' } },
      items.map(function(it) {
        return React.createElement('div', {
          key: it.label,
          style: { padding: '0.65rem 0.75rem', background: '#F7F9FC', borderRadius: '0.5rem', border: '1px solid #e2e8f0' }
        },
          React.createElement('div', {
            style: { fontSize: '0.68rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.25rem', fontFamily: "'Inter', sans-serif" }
          }, it.label),
          React.createElement('div', {
            style: { fontFamily: "'JetBrains Mono', monospace", fontSize: '1.25rem', fontWeight: 700, color: it.value > 0 ? it.accent : '#cbd5e1' }
          }, it.value)
        );
      })
    )
  );
}

function _recoveryCard(score, tp, revPct, workout, squats, setWorkout, setSquats) {
  var show = score < 60 || tp < 4 || revPct < 0.3;
  if (!show) return null;

  var actions = [];
  if (!workout) actions.push({ label: 'Complete workout', icon: '+10 pts', fn: function() { setWorkout(true); } });
  if (squats < 50) actions.push({ label: 'Log 10 squats', icon: '+2 pts', fn: function() { setSquats(squats + 10); } });
  if (tp < 4) actions.push({ label: 'Add 3 touchpoints', icon: '+9 pts', fn: null });
  if (actions.length < 3 && revPct < 0.3) actions.push({ label: 'Log a deal or revenue', icon: 'up to +20 pts', fn: null });
  actions = actions.slice(0, 3);

  var btnStyle = {
    background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.25)',
    color: '#d97706', padding: '0.3rem 0.65rem', borderRadius: '0.35rem',
    fontSize: '0.72rem', fontWeight: 600, cursor: 'pointer', fontFamily: "'Inter', sans-serif"
  };

  return React.createElement('div', {
    style: { background: 'rgba(245,158,11,0.04)', border: '1px solid rgba(245,158,11,0.2)', borderRadius: '0.75rem', padding: '1.1rem 1.25rem', marginBottom: '1.5rem' }
  },
    React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.65rem' } },
      React.createElement('span', { style: { fontSize: '0.95rem' } }, '⚡'),
      React.createElement('span', {
        style: { fontSize: '0.82rem', fontWeight: 700, color: '#92400e', fontFamily: "'Inter', sans-serif" }
      }, 'You\'re behind pace — here\'s how to catch up')
    ),
    React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.45rem' } },
      actions.map(function(a, i) {
        return React.createElement('div', {
          key: i,
          style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.45rem 0.65rem', background: '#FFFFFF', borderRadius: '0.4rem', border: '1px solid rgba(245,158,11,0.15)' }
        },
          React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '0.5rem' } },
            React.createElement('span', { style: { fontSize: '0.82rem', fontWeight: 600, color: '#1e293b', fontFamily: "'Inter', sans-serif" } }, a.label),
            React.createElement('span', { style: { fontSize: '0.65rem', color: '#94a3b8', fontWeight: 500 } }, a.icon)
          ),
          a.fn
            ? React.createElement('button', { onClick: a.fn, style: btnStyle }, 'Do it')
            : React.createElement('span', { style: { fontSize: '0.65rem', color: '#d97706', fontWeight: 600 } }, 'Go')
        );
      })
    )
  );
}

function _weeklySummaryCard(weekTp, calls, workout, followups, weeklyScore, weeklyGoal) {
  var status = weeklyScore >= 80 ? 'STRONG' : weeklyScore >= 50 ? 'ON TRACK' : 'BEHIND';
  var statusColors = { STRONG: '#10b981', 'ON TRACK': '#f59e0b', BEHIND: '#ef4444' };
  var sc = statusColors[status];

  var items = [
    { label: 'Touchpoints', value: weekTp, sub: '/ ' + weeklyGoal + ' goal' },
    { label: 'Calls / Meetings', value: calls, sub: 'this week' },
    { label: 'Workouts', value: workout ? 1 : 0, sub: 'this week' },
    { label: 'Follow-ups', value: followups, sub: 'completed' }
  ];

  return React.createElement('div', {
    style: { background: '#FFFFFF', border: '1px solid rgba(226,232,240,0.5)', borderRadius: '0.75rem', padding: '1.25rem', marginBottom: '1.5rem' }
  },
    React.createElement('div', {
      style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem' }
    },
      React.createElement('h3', {
        style: { fontSize: '0.72rem', color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', margin: 0, fontFamily: "'Inter', sans-serif" }
      }, 'This Week'),
      React.createElement('span', {
        style: { fontSize: '0.7rem', fontWeight: 700, color: sc, background: sc + '12', padding: '0.2rem 0.55rem', borderRadius: '9999px', letterSpacing: '0.04em', fontFamily: "'Inter', sans-serif" }
      }, status)
    ),
    React.createElement('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.6rem' } },
      items.map(function(it) {
        return React.createElement('div', {
          key: it.label,
          style: { padding: '0.55rem 0.7rem', background: '#F7F9FC', borderRadius: '0.5rem', border: '1px solid #e2e8f0' }
        },
          React.createElement('div', {
            style: { fontSize: '0.68rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.2rem', fontFamily: "'Inter', sans-serif" }
          }, it.label),
          React.createElement('div', { style: { display: 'flex', alignItems: 'baseline', gap: '0.3rem' } },
            React.createElement('span', {
              style: { fontFamily: "'JetBrains Mono', monospace", fontSize: '1.15rem', fontWeight: 700, color: it.value > 0 ? '#0f172a' : '#cbd5e1' }
            }, it.value),
            React.createElement('span', { style: { fontSize: '0.65rem', color: '#94a3b8' } }, it.sub)
          )
        );
      })
    )
  );
}

function _perfScore(workout, squats, tp, fu, rel, revPct) {
  var s = 0;
  s += workout ? 10 : 0;                        // Workout: 10
  s += Math.min(10, Math.floor(squats / 5));     // Squats: 1pt per 5, max 10
  s += Math.min(30, tp * 3);                     // Touchpoints: 3pt each, max 30
  s += Math.min(15, fu * 5);                     // Follow-ups: 5pt each, max 15
  s += Math.min(15, rel * 5);                    // Relationships: 5pt each, max 15
  s += Math.min(20, Math.round(revPct * 20));    // Revenue %: proportional, max 20
  return Math.min(100, s);
}

function _extractNum(text) {
  var m = text.replace(/[$,]/g, '').match(/(\d+(?:\.\d+)?)/);
  return m ? parseFloat(m[1]) : 0;
}

function _checklistRow(label, count, accent) {
  return React.createElement('div', {
    style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.55rem 0.7rem', background: '#F7F9FC', borderRadius: '0.5rem', border: '1px solid #e2e8f0' }
  },
    React.createElement('span', {
      style: { fontSize: '0.85rem', fontWeight: 600, color: '#1e293b', fontFamily: "'Inter', sans-serif" }
    }, label),
    React.createElement('span', {
      style: { fontFamily: "'JetBrains Mono', monospace", fontSize: '0.95rem', fontWeight: 700, color: count > 0 ? accent : '#94a3b8' }
    }, count)
  );
}
