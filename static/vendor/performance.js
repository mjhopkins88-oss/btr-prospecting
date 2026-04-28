window.PerformancePage = function PerformancePage() {
  var useState = React.useState;

  var _wo = useState(false); var workout = _wo[0]; var setWorkout = _wo[1];
  var _sq = useState(0); var squats = _sq[0]; var setSquats = _sq[1];
  var touchpoints = 4;
  var followups = 2;
  var relActions = 1;

  var daily = 72;
  var weekly = 310;
  var streak = 5;
  var momentum = 'BUILDING';

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

  return React.createElement('div', { style: { padding: '0' } },
    React.createElement('h2', {
      style: {
        fontFamily: "'Orbitron', sans-serif",
        fontSize: '1.3rem',
        fontWeight: 700,
        color: '#0f172a',
        marginBottom: '1.25rem',
        letterSpacing: '0.03em'
      }
    }, 'Performance'),

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
    )
  );
};

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
