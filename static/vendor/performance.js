window.PerformancePage = function PerformancePage() {
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
    )
  );
};
