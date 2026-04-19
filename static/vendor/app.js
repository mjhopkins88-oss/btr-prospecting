const {
  useState,
  useEffect,
  useRef,
  useCallback,
  useMemo
} = React;

// Get API base URL (works both locally and on Railway)
const API_BASE = window.location.hostname === 'localhost' ? 'http://localhost:5000' : window.location.origin;

// Wrap native fetch to always include credentials for API calls
// This ensures session cookies are sent with every request
const _origFetch = window.fetch.bind(window);
window.fetch = function (url, opts = {}) {
  if (typeof url === 'string' && url.startsWith(API_BASE)) {
    opts = {
      ...opts,
      credentials: 'include'
    };
  }
  return _origFetch(url, opts);
};

// Trigger pill color mapping
function getTriggerStyle(trigger) {
  const t = trigger.toLowerCase();
  if (t.includes('capital') || t.includes('financing') || t.includes('institutional')) return {
    bg: 'rgba(168,85,247,0.15)',
    color: '#c4b5fd'
  };
  if (t.includes('builder') || t.includes('construction') || t.includes('property conversion')) return {
    bg: 'rgba(6,182,212,0.15)',
    color: '#67e8f9'
  };
  if (t.includes('expansion') || t.includes('state')) return {
    bg: 'rgba(20,184,166,0.15)',
    color: '#5eead4'
  };
  if (t.includes('refinance') || t.includes('debt')) return {
    bg: 'rgba(245,158,11,0.15)',
    color: '#fcd34d'
  };
  if (t.includes('jv') || t.includes('partner')) return {
    bg: 'rgba(236,72,153,0.15)',
    color: '#f9a8d4'
  };
  if (t.includes('lease')) return {
    bg: 'rgba(236,72,153,0.15)',
    color: '#f9a8d4'
  };
  if (t.includes('portfolio') || t.includes('blanket') || t.includes('scale')) return {
    bg: 'rgba(59,130,246,0.15)',
    color: '#3b82f6'
  };
  if (t.includes('lender') || t.includes('covenant')) return {
    bg: 'rgba(249,115,22,0.15)',
    color: '#fdba74'
  };
  return {
    bg: 'rgba(148,163,184,0.15)',
    color: '#64748b'
  };
}

// Generate stable prospect_key for CRM matching
function makeProspectKey(company, website, city, state) {
  const normCompany = (company || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  if (website) {
    const normDomain = (website || '').toLowerCase().replace(/^https?:\/\/(www\.)?/, '').replace(/\/$/, '');
    return normCompany + '|' + normDomain;
  }
  const normCity = (city || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const normState = (state || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  return normCompany + '|' + normCity + '|' + normState;
}

// CRM status color mapping
const CRM_STATUS_COLORS = {
  'New': {
    bg: 'rgba(99,102,241,0.15)',
    color: '#a5b4fc'
  },
  'Contacted': {
    bg: 'rgba(6,182,212,0.15)',
    color: '#67e8f9'
  },
  'InDiscussion': {
    bg: 'rgba(245,158,11,0.15)',
    color: '#fcd34d'
  },
  'Quoted': {
    bg: 'rgba(168,85,247,0.15)',
    color: '#c4b5fd'
  },
  'Won': {
    bg: 'rgba(20,184,166,0.1)',
    color: '#14b8a6'
  },
  'Lost': {
    bg: 'rgba(239,68,68,0.15)',
    color: '#f87171'
  },
  'Nurture': {
    bg: 'rgba(148,163,184,0.15)',
    color: '#64748b'
  }
};
const CRM_STATUSES = ['New', 'Contacted', 'InDiscussion', 'Quoted', 'Won', 'Lost', 'Nurture'];

// ============================================================
// SHARED UI COMPONENTS (BTR Command aesthetic upgrade pack)
// ============================================================

// cn() helper — joins className strings, filters falsy
const cn = (...args) => args.filter(Boolean).join(' ');

// Item 11 — Density context (localStorage-persisted)
const DensityContext = React.createContext({
  density: 'comfortable',
  toggle: () => {}
});
function DensityProvider({
  children
}) {
  const [density, setDensity] = useState(() => {
    try {
      return localStorage.getItem('btr_density') || 'comfortable';
    } catch {
      return 'comfortable';
    }
  });
  const toggle = () => {
    const next = density === 'comfortable' ? 'dense' : 'comfortable';
    setDensity(next);
    try {
      localStorage.setItem('btr_density', next);
    } catch {}
  };
  return React.createElement(DensityContext.Provider, {
    value: {
      density,
      toggle
    }
  }, React.createElement('div', {
    className: density === 'dense' ? 'density-dense' : ''
  }, children));
}
function useDensity() {
  return React.useContext(DensityContext);
}

// Item 11 — DensityToggle button
function DensityToggle() {
  const {
    density,
    toggle
  } = useDensity();
  return /*#__PURE__*/React.createElement("button", {
    onClick: toggle,
    className: "flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-300 transition-colors px-2 py-1 rounded-lg border border-slate-700/50 hover:border-slate-600",
    title: density === 'comfortable' ? 'Switch to dense' : 'Switch to comfortable'
  }, /*#__PURE__*/React.createElement("svg", {
    width: "14",
    height: "14",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M4 6h16M4 12h16M4 18h16"
  })), density === 'comfortable' ? 'Dense' : 'Comfy');
}

// Item 4 — Panel wrapper (outer container with standardized spacing/radius)
function Panel({
  children,
  className,
  style
}) {
  const {
    density
  } = useDensity();
  const pad = density === 'dense' ? 'p-3' : 'p-4';
  return /*#__PURE__*/React.createElement("div", {
    className: cn('ui-panel bg-slate-800/80 border border-slate-700/50 rounded-2xl', pad, className),
    style: style
  }, children);
}

// Item 4 — Section wrapper (consistent vertical spacing)
function Section({
  children,
  className
}) {
  const {
    density
  } = useDensity();
  const gap = density === 'dense' ? 'gap-4 mb-4' : 'gap-6 mb-6';
  return /*#__PURE__*/React.createElement("div", {
    className: cn('ui-section flex flex-col', gap, className)
  }, children);
}

// Item 4 — Card wrapper (inner elements)
function Card({
  children,
  className,
  style,
  hover,
  highPriority
}) {
  const {
    density
  } = useDensity();
  const pad = density === 'dense' ? 'p-3 gap-2' : 'p-4 gap-3';
  return /*#__PURE__*/React.createElement("div", {
    className: cn('ui-card bg-slate-800/80 border border-slate-700/50 rounded-2xl grid transition-all duration-200', pad, hover && 'hover:scale-[1.01] hover:shadow-xl hover:shadow-black/30', highPriority && 'hover:shadow-emerald-500/10', className),
    style: style
  }, children);
}

// Item 2 — SectionHeader (consistent typography hierarchy)
// Item 14 — adds optional icon
const SECTION_ICONS = {
  momentum: React.createElement('svg', {
    width: 16,
    height: 16,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 2,
    strokeLinecap: 'round',
    strokeLinejoin: 'round'
  }, React.createElement('polyline', {
    points: '22,7 13.5,15.5 8.5,10.5 2,17'
  }), React.createElement('polyline', {
    points: '16,7 22,7 22,13'
  })),
  signals: React.createElement('svg', {
    width: 16,
    height: 16,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 2,
    strokeLinecap: 'round',
    strokeLinejoin: 'round'
  }, React.createElement('circle', {
    cx: 12,
    cy: 12,
    r: 2
  }), React.createElement('path', {
    d: 'M16.24 7.76a6 6 0 010 8.49'
  }), React.createElement('path', {
    d: 'M19.07 4.93a10 10 0 010 14.14'
  }), React.createElement('path', {
    d: 'M7.76 16.24a6 6 0 010-8.49'
  }), React.createElement('path', {
    d: 'M4.93 19.07a10 10 0 010-14.14'
  })),
  rankings: React.createElement('svg', {
    width: 16,
    height: 16,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 2,
    strokeLinecap: 'round',
    strokeLinejoin: 'round'
  }, React.createElement('polygon', {
    points: '1,6 1,22 8,18 16,22 23,18 23,2 16,6 8,2 1,6'
  }), React.createElement('line', {
    x1: 8,
    y1: 2,
    x2: 8,
    y2: 18
  }), React.createElement('line', {
    x1: 16,
    y1: 6,
    x2: 16,
    y2: 22
  })),
  discovery: React.createElement('svg', {
    width: 16,
    height: 16,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 2,
    strokeLinecap: 'round',
    strokeLinejoin: 'round'
  }, React.createElement('polygon', {
    points: '13,2 3,14 12,14 11,22 21,10 12,10 13,2'
  })),
  search: React.createElement('svg', {
    width: 16,
    height: 16,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 2,
    strokeLinecap: 'round',
    strokeLinejoin: 'round'
  }, React.createElement('circle', {
    cx: 11,
    cy: 11,
    r: 8
  }), React.createElement('line', {
    x1: 21,
    y1: 21,
    x2: 16.65,
    y2: 16.65
  })),
  pipeline: React.createElement('svg', {
    width: 16,
    height: 16,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 2,
    strokeLinecap: 'round',
    strokeLinejoin: 'round'
  }, React.createElement('rect', {
    x: 3,
    y: 3,
    width: 7,
    height: 7
  }), React.createElement('rect', {
    x: 14,
    y: 3,
    width: 7,
    height: 7
  }), React.createElement('rect', {
    x: 14,
    y: 14,
    width: 7,
    height: 7
  }), React.createElement('rect', {
    x: 3,
    y: 14,
    width: 7,
    height: 7
  })),
  followups: React.createElement('svg', {
    width: 16,
    height: 16,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 2,
    strokeLinecap: 'round',
    strokeLinejoin: 'round'
  }, React.createElement('circle', {
    cx: 12,
    cy: 12,
    r: 10
  }), React.createElement('polyline', {
    points: '12,6 12,12 16,14'
  }))
};
function SectionHeader({
  title,
  subtitle,
  icon,
  updatedAt,
  children
}) {
  const iconEl = icon && SECTION_ICONS[icon] ? /*#__PURE__*/React.createElement("span", {
    className: "text-slate-400 flex-shrink-0"
  }, SECTION_ICONS[icon]) : null;
  const timeLabel = updatedAt ? timeAgo(updatedAt) : null;
  return /*#__PURE__*/React.createElement("div", {
    className: "flex items-start justify-between gap-4 mb-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-2"
  }, iconEl, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h2", {
    className: "text-xl font-semibold text-slate-100 font-orbitron"
  }, title), subtitle && /*#__PURE__*/React.createElement("p", {
    className: "text-sm text-slate-400 mt-0.5"
  }, subtitle))), /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-3 flex-shrink-0"
  }, timeLabel && /*#__PURE__*/React.createElement("span", {
    className: "text-xs text-slate-500"
  }, "Updated ", timeLabel), children));
}

// Item 2 — SectionLabel (small uppercase labels)
function SectionLabel({
  children,
  className
}) {
  return /*#__PURE__*/React.createElement("div", {
    className: cn('text-[11px] tracking-[0.22em] uppercase text-slate-500 font-semibold', className)
  }, children);
}

// Item 6 — Gradient Divider
function Divider({
  className
}) {
  return /*#__PURE__*/React.createElement("div", {
    className: cn('gradient-divider', className)
  });
}

// Item 7 + Item 5 — SignalPill with controlled accent colors
const SIGNAL_COLORS = {
  capital: {
    bg: 'bg-purple-500/15',
    text: 'text-purple-300',
    border: 'border-purple-400/20'
  },
  construction: {
    bg: 'bg-cyan-500/15',
    text: 'text-cyan-300',
    border: 'border-cyan-400/20'
  },
  expansion: {
    bg: 'bg-teal-500/15',
    text: 'text-teal-300',
    border: 'border-teal-400/20'
  },
  refinance: {
    bg: 'bg-amber-500/15',
    text: 'text-amber-300',
    border: 'border-amber-400/20'
  },
  jv: {
    bg: 'bg-pink-500/15',
    text: 'text-pink-300',
    border: 'border-pink-400/20'
  },
  permit: {
    bg: 'bg-orange-500/15',
    text: 'text-orange-300',
    border: 'border-orange-400/20'
  },
  filing: {
    bg: 'bg-blue-500/15',
    text: 'text-blue-300',
    border: 'border-blue-400/20'
  },
  news: {
    bg: 'bg-emerald-500/15',
    text: 'text-emerald-300',
    border: 'border-emerald-400/20'
  },
  press_release: {
    bg: 'bg-violet-500/15',
    text: 'text-violet-300',
    border: 'border-violet-400/20'
  },
  default: {
    bg: 'bg-slate-500/15',
    text: 'text-slate-300',
    border: 'border-slate-400/20'
  }
};
function getSignalCategory(label) {
  const l = (label || '').toLowerCase();
  if (l.includes('capital') || l.includes('jv') || l.includes('institutional')) return 'capital';
  if (l.includes('builder') || l.includes('construction') || l.includes('property')) return 'construction';
  if (l.includes('expansion') || l.includes('state')) return 'expansion';
  if (l.includes('refinanc') || l.includes('debt') || l.includes('lender')) return 'refinance';
  if (l.includes('jv') || l.includes('joint')) return 'jv';
  if (l.includes('permit')) return 'permit';
  if (l.includes('filing')) return 'filing';
  if (l.includes('news')) return 'news';
  if (l.includes('press')) return 'press_release';
  return 'default';
}
function SignalPill({
  label,
  category,
  glow
}) {
  const cat = category || getSignalCategory(label);
  const c = SIGNAL_COLORS[cat] || SIGNAL_COLORS.default;
  return /*#__PURE__*/React.createElement("span", {
    className: cn('text-xs font-medium px-3 py-1 rounded-full border whitespace-nowrap', c.bg, c.text, c.border, glow && 'shadow-[0_0_10px_rgba(168,85,247,0.2)]')
  }, label);
}

// Item 12 — Elevated Empty State
function EmptyState({
  icon,
  title,
  subtitle,
  children
}) {
  const defaultIcon = /*#__PURE__*/React.createElement("svg", {
    width: "36",
    height: "36",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "1.5",
    strokeLinecap: "round",
    strokeLinejoin: "round",
    className: "text-slate-600"
  }, /*#__PURE__*/React.createElement("circle", {
    cx: "12",
    cy: "12",
    r: "10"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M8 12h8"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M12 8v8"
  }));
  return /*#__PURE__*/React.createElement("div", {
    className: "bg-slate-900/50 border border-slate-800 rounded-2xl p-8 flex flex-col items-center justify-center text-center"
  }, /*#__PURE__*/React.createElement("div", {
    className: "mb-3 text-slate-600"
  }, icon || defaultIcon), /*#__PURE__*/React.createElement("h3", {
    className: "text-lg font-semibold text-slate-400 font-orbitron mb-1"
  }, title || 'No data found'), subtitle && /*#__PURE__*/React.createElement("p", {
    className: "text-sm text-slate-500"
  }, subtitle), children);
}

// Item 10 — Micro Sparkline
function Sparkline({
  values,
  width,
  height,
  color
}) {
  const w = width || 60;
  const h = height || 20;
  const clr = color || '#34d399';
  if (!values || !Array.isArray(values) || values.length < 2) {
    // Placeholder: faint dashed line
    return /*#__PURE__*/React.createElement("svg", {
      width: w,
      height: h,
      viewBox: `0 0 ${w} ${h}`
    }, /*#__PURE__*/React.createElement("line", {
      x1: "2",
      y1: h / 2,
      x2: w - 2,
      y2: h / 2,
      stroke: "#e2e8f0",
      strokeWidth: "1",
      strokeDasharray: "3 3"
    }));
  }
  const max = Math.max(...values);
  const min = Math.min(...values);
  const range = max - min || 1;
  const points = values.map((v, i) => {
    const x = i / (values.length - 1) * (w - 4) + 2;
    const y = h - 2 - (v - min) / range * (h - 4);
    return `${x},${y}`;
  }).join(' ');
  return /*#__PURE__*/React.createElement("svg", {
    width: w,
    height: h,
    viewBox: `0 0 ${w} ${h}`
  }, /*#__PURE__*/React.createElement("polyline", {
    points: points,
    fill: "none",
    stroke: clr,
    strokeWidth: "1.5",
    strokeLinecap: "round",
    strokeLinejoin: "round",
    opacity: "0.7"
  }));
}

// timeAgo helper (also used by SectionHeader)
function timeAgo(ts) {
  if (!ts) return null;
  try {
    const d = new Date(ts);
    const now = new Date();
    const diffMs = now - d;
    const mins = Math.floor(diffMs / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
  } catch {
    return null;
  }
}

// ============================================================
// END SHARED UI COMPONENTS
// ============================================================

// ======= ROOT: Auth Gate =======
function Root() {
  const [authState, setAuthState] = useState('loading'); // 'loading','bootstrap','login','authenticated'
  const [user, setUser] = useState(null);
  const [authError, setAuthError] = useState('');
  useEffect(() => {
    checkAuth();
  }, []);
  const checkAuth = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/auth/me`);
      const data = await res.json();
      if (data.needs_bootstrap) {
        setAuthState('bootstrap');
      } else if (data.success && data.user) {
        setUser(data.user);
        setAuthState('authenticated');
      } else {
        // 401 or no user — check if bootstrap needed vs login
        try {
          const huRes = await fetch(`${API_BASE}/api/auth/has-users`);
          const huData = await huRes.json();
          setAuthState(huData.has_users ? 'login' : 'bootstrap');
        } catch (e2) {
          setAuthState('login');
        }
      }
    } catch (e) {
      setAuthState('login');
    }
  };
  const handleBootstrap = async form => {
    setAuthError('');
    try {
      const res = await fetch(`${API_BASE}/api/auth/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(form)
      });
      const data = await res.json();
      if (data.success) {
        setUser(data.user);
        setAuthState('authenticated');
      } else {
        setAuthError(data.message || 'Bootstrap failed');
      }
    } catch (e) {
      setAuthError('Network error');
    }
  };
  const handleLogin = async (email, password) => {
    setAuthError('');
    try {
      const res = await fetch(`${API_BASE}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          email,
          password
        })
      });
      const data = await res.json();
      if (data.success) {
        setUser(data.user);
        setAuthState('authenticated');
      } else {
        setAuthError(data.message || 'Login failed');
      }
    } catch (e) {
      setAuthError('Network error');
    }
  };
  const handleLogout = async () => {
    await fetch(`${API_BASE}/api/auth/logout`, {
      method: 'POST'
    });
    setUser(null);
    setAuthState('login');
  };
  if (authState === 'loading') return /*#__PURE__*/React.createElement("div", {
    style: {
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "'Orbitron',sans-serif",
      color: '#14b8a6',
      fontSize: '1.2rem',
      animation: 'pulse 1.5s ease-in-out infinite'
    }
  }, "Loading..."));
  if (authState === 'bootstrap') return /*#__PURE__*/React.createElement(BootstrapPage, {
    onBootstrap: handleBootstrap,
    error: authError
  });
  if (authState === 'login') return /*#__PURE__*/React.createElement(LoginPage, {
    onLogin: handleLogin,
    error: authError
  });
  return /*#__PURE__*/React.createElement(App, {
    user: user,
    onLogout: handleLogout
  });
}

// ======= LOGIN PAGE =======
function LoginPage({
  onLogin,
  error
}) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const handleSubmit = async e => {
    e.preventDefault();
    setSubmitting(true);
    await onLogin(email, password);
    setSubmitting(false);
  };
  return /*#__PURE__*/React.createElement("div", {
    style: {
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '2rem'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      borderRadius: '16px',
      padding: '2.5rem',
      maxWidth: '400px',
      width: '100%'
    }
  }, /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "'Orbitron',sans-serif",
      fontSize: '1.5rem',
      fontWeight: 900,
      background: 'linear-gradient(135deg,#34d399 0%,#3b82f6 100%)',
      WebkitBackgroundClip: 'text',
      WebkitTextFillColor: 'transparent',
      marginBottom: '0.5rem',
      textAlign: 'center'
    }
  }, "BTR INTELLIGENCE"), /*#__PURE__*/React.createElement("p", {
    style: {
      color: '#64748b',
      textAlign: 'center',
      marginBottom: '1.5rem',
      fontSize: '0.9rem'
    }
  }, "Sign in to continue"), error && /*#__PURE__*/React.createElement("div", {
    style: {
      background: 'rgba(239,68,68,0.1)',
      border: '1px solid rgba(239,68,68,0.3)',
      borderRadius: '8px',
      padding: '0.75rem',
      marginBottom: '1rem',
      color: '#f87171',
      fontSize: '0.85rem',
      textAlign: 'center'
    }
  }, error), /*#__PURE__*/React.createElement("form", {
    onSubmit: handleSubmit,
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: '0.85rem'
    }
  }, /*#__PURE__*/React.createElement("input", {
    type: "email",
    required: true,
    placeholder: "Email",
    value: email,
    onChange: e => setEmail(e.target.value),
    style: {
      ...styles.input,
      width: '100%',
      minWidth: 0
    }
  }), /*#__PURE__*/React.createElement("input", {
    type: "password",
    required: true,
    placeholder: "Password",
    value: password,
    onChange: e => setPassword(e.target.value),
    style: {
      ...styles.input,
      width: '100%',
      minWidth: 0
    }
  }), /*#__PURE__*/React.createElement("button", {
    type: "submit",
    disabled: submitting,
    style: {
      ...styles.btnPrimary,
      width: '100%',
      padding: '0.75rem',
      fontSize: '1rem',
      ...(submitting ? {
        opacity: 0.5
      } : {})
    }
  }, submitting ? 'Signing in...' : 'Sign In'))));
}

// ======= BOOTSTRAP PAGE =======
function BootstrapPage({
  onBootstrap,
  error
}) {
  const [form, setForm] = useState({
    workspace_name: '',
    name: '',
    email: '',
    password: ''
  });
  const [submitting, setSubmitting] = useState(false);
  const update = (k, v) => setForm(f => ({
    ...f,
    [k]: v
  }));
  const handleSubmit = async e => {
    e.preventDefault();
    setSubmitting(true);
    await onBootstrap(form);
    setSubmitting(false);
  };
  return /*#__PURE__*/React.createElement("div", {
    style: {
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '2rem'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      borderRadius: '16px',
      padding: '2.5rem',
      maxWidth: '440px',
      width: '100%'
    }
  }, /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "'Orbitron',sans-serif",
      fontSize: '1.5rem',
      fontWeight: 900,
      background: 'linear-gradient(135deg,#34d399 0%,#3b82f6 100%)',
      WebkitBackgroundClip: 'text',
      WebkitTextFillColor: 'transparent',
      marginBottom: '0.5rem',
      textAlign: 'center'
    }
  }, "SETUP"), /*#__PURE__*/React.createElement("p", {
    style: {
      color: '#64748b',
      textAlign: 'center',
      marginBottom: '1.5rem',
      fontSize: '0.9rem'
    }
  }, "Create your workspace and admin account"), error && /*#__PURE__*/React.createElement("div", {
    style: {
      background: 'rgba(239,68,68,0.1)',
      border: '1px solid rgba(239,68,68,0.3)',
      borderRadius: '8px',
      padding: '0.75rem',
      marginBottom: '1rem',
      color: '#f87171',
      fontSize: '0.85rem',
      textAlign: 'center'
    }
  }, error), /*#__PURE__*/React.createElement("form", {
    onSubmit: handleSubmit,
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: '0.85rem'
    }
  }, /*#__PURE__*/React.createElement("input", {
    required: true,
    placeholder: "Workspace Name (e.g., BTR Agency)",
    value: form.workspace_name,
    onChange: e => update('workspace_name', e.target.value),
    style: {
      ...styles.input,
      width: '100%',
      minWidth: 0
    }
  }), /*#__PURE__*/React.createElement("input", {
    required: true,
    placeholder: "Your Name",
    value: form.name,
    onChange: e => update('name', e.target.value),
    style: {
      ...styles.input,
      width: '100%',
      minWidth: 0
    }
  }), /*#__PURE__*/React.createElement("input", {
    type: "email",
    required: true,
    placeholder: "Email",
    value: form.email,
    onChange: e => update('email', e.target.value),
    style: {
      ...styles.input,
      width: '100%',
      minWidth: 0
    }
  }), /*#__PURE__*/React.createElement("input", {
    type: "password",
    required: true,
    placeholder: "Password (8+ chars)",
    value: form.password,
    onChange: e => update('password', e.target.value),
    style: {
      ...styles.input,
      width: '100%',
      minWidth: 0
    }
  }), /*#__PURE__*/React.createElement("button", {
    type: "submit",
    disabled: submitting,
    style: {
      ...styles.btnPrimary,
      width: '100%',
      padding: '0.75rem',
      fontSize: '1rem',
      ...(submitting ? {
        opacity: 0.5
      } : {})
    }
  }, submitting ? 'Creating...' : 'Create Workspace'))));
}

// ======= LINKEDIN HELPERS =======
function validLinkedIn(v) {
  if (!v || typeof v !== 'string') return false;
  const s = v.trim().toLowerCase();
  if (!s) return false;
  if (s.includes('not mentioned') || s.includes('not available') || s === 'n/a' || s === 'none' || s === 'null') return false;
  return s.includes('linkedin.com/');
}
function normalizeLinkedIn(v) {
  const s = v.trim();
  if (/^https?:\/\//i.test(s)) return s;
  return 'https://' + s.replace(/^\/+/, '');
}

// ======= MAIN APP =======
function App({
  user,
  onLogout
}) {
  const [activeTab, setActiveTab] = useState('command');
  const [prospects, setProspects] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedProspect, setSelectedProspect] = useState(null);
  const [searchCity, setSearchCity] = useState('Texas');
  const [filterScore, setFilterScore] = useState('all');
  const [emailTemplate, setEmailTemplate] = useState({
    subject: '',
    body: ''
  });
  const [showEmailModal, setShowEmailModal] = useState(false);
  const [searchStatus, setSearchStatus] = useState('');
  const [cooldown, setCooldown] = useState(0);
  // CRM state
  const [crmStatuses, setCrmStatuses] = useState({});
  const [touchpointTarget, setTouchpointTarget] = useState(null); // {lead_id, company_name}

  useEffect(() => {
    loadProspects();
  }, []);
  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setTimeout(() => setCooldown(cooldown - 1), 1000);
    return () => clearTimeout(timer);
  }, [cooldown]);

  // Fetch CRM statuses for all visible prospects
  const loadCrmStatuses = useCallback(async prospectsList => {
    if (!user || !prospectsList || prospectsList.length === 0) return;
    const keys = prospectsList.map(p => makeProspectKey(p.company, null, p.city, p.state));
    const uniqueKeys = [...new Set(keys)].slice(0, 200);
    if (uniqueKeys.length === 0) return;
    try {
      const res = await fetch(`${API_BASE}/api/crm/leads/bulk-status?keys=${encodeURIComponent(uniqueKeys.join(','))}`);
      const data = await res.json();
      if (data.success) setCrmStatuses(data.statuses || {});
    } catch (e) {
      console.error('CRM bulk status error:', e);
    }
  }, [user]);
  const loadCallTimingScores = useCallback(async prospectsList => {
    if (!prospectsList || prospectsList.length === 0) return;
    const keys = prospectsList.map(p => {
      const nc = (p.company || '').toLowerCase().replace(/[^a-z0-9]/g, '');
      const nci = (p.city || '').toLowerCase().replace(/[^a-z0-9]/g, '');
      const ns = (p.state || '').toLowerCase().replace(/[^a-z0-9]/g, '');
      return nc + '|' + nci + '|' + ns;
    });
    const uniqueKeys = [...new Set(keys)].slice(0, 200);
    if (uniqueKeys.length === 0) return;
    try {
      const res = await fetch(`${API_BASE}/api/intelligence/call-timing/lookup?keys=${encodeURIComponent(uniqueKeys.join(','))}`);
      const data = await res.json();
      if (data.success) setCallTimingScores(data.scores || {});
    } catch (e) {
      console.error('Call timing lookup error:', e);
    }
  }, []);
  const loadProspects = async dateOpt => {
    try {
      const df = dateOpt || dateFilter;
      let url = `${API_BASE}/api/prospects`;
      const params = new URLSearchParams();
      const now = new Date();
      if (df === 'today') {
        params.set('start_date', now.toISOString().slice(0, 10) + 'T00:00:00');
        params.set('end_date', now.toISOString());
      } else if (df === '7days') {
        const d = new Date(now);
        d.setDate(d.getDate() - 7);
        params.set('start_date', d.toISOString());
        params.set('end_date', now.toISOString());
      } else if (df === '30days') {
        const d = new Date(now);
        d.setDate(d.getDate() - 30);
        params.set('start_date', d.toISOString());
        params.set('end_date', now.toISOString());
      } else if (df === 'custom' && customDateStart && customDateEnd) {
        params.set('start_date', customDateStart + 'T00:00:00');
        params.set('end_date', customDateEnd + 'T23:59:59');
      }
      const qs = params.toString();
      if (qs) url += '?' + qs;
      const response = await fetch(url);
      const data = await response.json();
      if (data.success) {
        setProspects(data.prospects);
        loadCrmStatuses(data.prospects);
        loadCallTimingScores(data.prospects);
      }
    } catch (error) {
      console.error('Error loading prospects:', error);
    }
  };
  const pollRef = useRef(null);
  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);
  const searchProspects = async () => {
    if (cooldown > 0) return;
    setLoading(true);
    setSearchStatus('Starting prospecting run...');
    setCooldown(30);
    try {
      const response = await fetch(`${API_BASE}/api/prospecting/run`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          cities: [{
            city: searchCity,
            state: ''
          }],
          maxProspectsPerCity: 25,
          maxTotalProspects: 300
        })
      });
      const data = await response.json();
      if (!data.success) {
        setSearchStatus(`Error: ${data.message}`);
        setLoading(false);
        setTimeout(() => setSearchStatus(''), 5000);
        return;
      }
      const runId = data.run_id;
      setSearchStatus('AI is searching CRE sources for BTR prospects...');
      if (pollRef.current) clearInterval(pollRef.current);
      pollRef.current = setInterval(async () => {
        try {
          const statusRes = await fetch(`${API_BASE}/api/prospecting/run/${runId}/status`);
          const statusData = await statusRes.json();
          if (statusData.total_prospects > 0) {
            setSearchStatus(`Found ${statusData.total_prospects} prospects so far...`);
          }
          if (statusData.status === 'completed') {
            clearInterval(pollRef.current);
            pollRef.current = null;
            setSearchStatus(`Found ${statusData.total_prospects} prospects!`);
            await loadProspects();
            setLoading(false);
            setTimeout(() => setSearchStatus(''), 5000);
          } else if (statusData.status === 'failed') {
            clearInterval(pollRef.current);
            pollRef.current = null;
            setSearchStatus(`Search failed: ${statusData.error || 'Unknown error'}`);
            setLoading(false);
            setTimeout(() => setSearchStatus(''), 8000);
          }
        } catch (e) {
          console.error('Poll error:', e);
        }
      }, 3000);
    } catch (error) {
      console.error('Search error:', error);
      setSearchStatus('Failed to start search. Check your connection.');
      setLoading(false);
      setTimeout(() => setSearchStatus(''), 5000);
    }
  };
  const generateEmail = async (prospect, options = {}) => {
    setLoading(true);
    setSearchStatus('AI is writing a personalized email...');
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch(`${API_BASE}/api/email/generate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          prospect: prospect,
          emailPurpose: options.emailPurpose || 'cold_outreach',
          tone: options.tone || 'professional_direct',
          offer: options.offer || '15_min_call',
          triggerEvent: options.triggerEvent || ''
        }),
        signal: controller.signal
      });
      clearTimeout(timeout);
      const text = await response.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch (e) {
        console.error('Email response not JSON:', text.substring(0, 200));
        setSearchStatus('Email generation returned an invalid response. Try again.');
        setTimeout(() => setSearchStatus(''), 5000);
        return;
      }
      if (data.success) {
        const subject = data.subject || '';
        const body = data.body || data.email || 'No email body returned. Try again.';
        setSelectedProspect(prospect);
        setEmailTemplate({
          subject,
          body
        });
        setShowEmailModal(true);
        setSearchStatus('');
      } else {
        setSearchStatus(`${data.message || 'Email generation failed.'}`);
        setTimeout(() => setSearchStatus(''), 5000);
      }
    } catch (error) {
      clearTimeout(timeout);
      console.error('Email generation error:', error);
      if (error.name === 'AbortError') {
        setSearchStatus('Email generation timed out. Try again.');
      } else {
        setSearchStatus(`Email generation failed: ${error.message}`);
      }
      setTimeout(() => setSearchStatus(''), 5000);
    } finally {
      setLoading(false);
    }
  };
  const exportToCSV = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/export`);
      if (response.ok) {
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `btr-prospects-master-${new Date().toISOString().split('T')[0]}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        setSearchStatus(`Master spreadsheet downloaded (${prospects.length} prospects)`);
        setTimeout(() => setSearchStatus(''), 3000);
      } else {
        const data = await response.json();
        setSearchStatus(`${data.message || 'Export failed'}`);
        setTimeout(() => setSearchStatus(''), 5000);
      }
    } catch (error) {
      console.error('Export error:', error);
      setSearchStatus('Export failed. Try again.');
      setTimeout(() => setSearchStatus(''), 5000);
    }
  };
  const deleteProspect = async prospectId => {
    if (!confirm('Delete this prospect?')) return;
    try {
      await fetch(`${API_BASE}/api/prospects/${prospectId}`, {
        method: 'DELETE'
      });
      await loadProspects();
    } catch (error) {
      console.error('Delete error:', error);
    }
  };
  const [filterTrigger, setFilterTrigger] = useState('all');
  const [filterSwimLane, setFilterSwimLane] = useState(false);
  const [sortBy, setSortBy] = useState('score');
  const [filterEightyPlus, setFilterEightyPlus] = useState(false);
  const [filterCapitalEvents, setFilterCapitalEvents] = useState(false);
  const [filterLowComp, setFilterLowComp] = useState(false);
  const [filterCallNow, setFilterCallNow] = useState(false);
  const [callTimingScores, setCallTimingScores] = useState({});
  const [dateFilter, setDateFilter] = useState('all');
  const [customDateStart, setCustomDateStart] = useState('');
  const [customDateEnd, setCustomDateEnd] = useState('');
  const filteredProspects = prospects.filter(p => {
    if (searchCity !== 'all' && searchCity !== 'Texas' && !p.city?.toLowerCase().includes(searchCity.toLowerCase())) return false;
    if (filterScore === '90+' && p.score < 90) return false;
    if (filterScore === '80+' && p.score < 80) return false;
    if (filterScore === '80-89' && (p.score < 80 || p.score >= 90)) return false;
    if (filterEightyPlus && p.score < 80) return false;
    if (filterTrigger !== 'all') {
      const triggers = p.insurance_triggers || [];
      if (!triggers.some(t => t.toLowerCase().includes(filterTrigger.toLowerCase()))) return false;
    }
    if (filterCapitalEvents) {
      const triggers = p.insurance_triggers || [];
      if (!triggers.some(t => t.toLowerCase().includes('capital') || t.toLowerCase().includes('jv'))) return false;
    }
    if (filterSwimLane) {
      const band = p.unit_band || '';
      if (band !== '40-150' && band !== '150-400') return false;
    }
    if (filterLowComp) {
      if ((p.competitive_difficulty || '') !== 'Low') return false;
    }
    if (filterCallNow) {
      const nc = (p.company || '').toLowerCase().replace(/[^a-z0-9]/g, '');
      const nci = (p.city || '').toLowerCase().replace(/[^a-z0-9]/g, '');
      const ns = (p.state || '').toLowerCase().replace(/[^a-z0-9]/g, '');
      const pk = nc + '|' + nci + '|' + ns;
      const timing = callTimingScores[pk];
      if (!timing || timing.timing_label !== 'Call Now') return false;
    }
    return true;
  }).sort((a, b) => {
    if (sortBy === 'call_timing') {
      const aKey = (a.company || '').toLowerCase().replace(/[^a-z0-9]/g, '') + '|' + (a.city || '').toLowerCase().replace(/[^a-z0-9]/g, '') + '|' + (a.state || '').toLowerCase().replace(/[^a-z0-9]/g, '');
      const bKey = (b.company || '').toLowerCase().replace(/[^a-z0-9]/g, '') + '|' + (b.city || '').toLowerCase().replace(/[^a-z0-9]/g, '') + '|' + (b.state || '').toLowerCase().replace(/[^a-z0-9]/g, '');
      return ((callTimingScores[bKey] || {}).call_timing_score || 0) - ((callTimingScores[aKey] || {}).call_timing_score || 0);
    }
    if (sortBy === 'swim_lane') return (b.swim_lane_fit_score || 0) - (a.swim_lane_fit_score || 0);
    return (b.score || 0) - (a.score || 0);
  });
  const saveToPipeline = async prospect => {
    const pk = makeProspectKey(prospect.company, null, prospect.city, prospect.state);
    try {
      const res = await fetch(`${API_BASE}/api/crm/lead/upsert`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          prospect_key: pk,
          company_name: prospect.company
        })
      });
      const data = await res.json();
      if (data.success) {
        setCrmStatuses(prev => ({
          ...prev,
          [pk]: {
            lead_id: data.lead.id,
            status: data.lead.status,
            owner_user_id: data.lead.owner_user_id
          }
        }));
      }
    } catch (e) {
      console.error('Save to pipeline error:', e);
    }
  };
  const openTouchpoint = (leadId, companyName) => {
    setTouchpointTarget({
      lead_id: leadId,
      company_name: companyName
    });
  };
  return /*#__PURE__*/React.createElement("div", {
    style: styles.container
  }, /*#__PURE__*/React.createElement(Header, {
    user: user,
    onLogout: onLogout
  }), /*#__PURE__*/React.createElement(CommandPalette, {
    activeTab: activeTab,
    setActiveTab: setActiveTab,
    user: user,
    prospects: prospects
  }), /*#__PURE__*/React.createElement(TopNav, {
    activeTab: activeTab,
    setActiveTab: setActiveTab,
    user: user
  }), /*#__PURE__*/React.createElement(SubNav, {
    activeTab: activeTab,
    setActiveTab: setActiveTab,
    user: user
  }), activeTab === 'command' && /*#__PURE__*/React.createElement(CommandCenter, {
    user: user,
    prospects: prospects,
    setActiveTab: setActiveTab
  }), activeTab === 'search' && /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement(Stats, {
    prospects: prospects
  }), /*#__PURE__*/React.createElement(Controls, {
    searchCity: searchCity,
    setSearchCity: setSearchCity,
    filterScore: filterScore,
    setFilterScore: setFilterScore,
    filterTrigger: filterTrigger,
    setFilterTrigger: setFilterTrigger,
    filterSwimLane: filterSwimLane,
    setFilterSwimLane: setFilterSwimLane,
    sortBy: sortBy,
    setSortBy: setSortBy,
    onSearch: searchProspects,
    onExport: exportToCSV,
    loading: loading,
    hasProspects: prospects.length > 0,
    cooldown: cooldown,
    filterEightyPlus: filterEightyPlus,
    setFilterEightyPlus: setFilterEightyPlus,
    filterCapitalEvents: filterCapitalEvents,
    setFilterCapitalEvents: setFilterCapitalEvents,
    filterLowComp: filterLowComp,
    setFilterLowComp: setFilterLowComp,
    filterCallNow: filterCallNow,
    setFilterCallNow: setFilterCallNow,
    dateFilter: dateFilter,
    setDateFilter: setDateFilter,
    customDateStart: customDateStart,
    setCustomDateStart: setCustomDateStart,
    customDateEnd: customDateEnd,
    setCustomDateEnd: setCustomDateEnd,
    onDateFilterChange: df => loadProspects(df)
  }), searchStatus && /*#__PURE__*/React.createElement(SearchStatus, {
    message: searchStatus
  }), loading && /*#__PURE__*/React.createElement(Loading, null), /*#__PURE__*/React.createElement(ProspectsList, {
    prospects: filteredProspects,
    onGenerateEmail: generateEmail,
    onDelete: deleteProspect,
    crmStatuses: crmStatuses,
    onSaveToPipeline: saveToPipeline,
    onLogTouchpoint: openTouchpoint,
    user: user,
    callTimingScores: callTimingScores
  })), activeTab === 'discovery' && user?.role !== 'broker' && /*#__PURE__*/React.createElement(DailyDiscovery, null), activeTab === 'pipeline' && user?.role !== 'broker' && /*#__PURE__*/React.createElement(PipelinePage, {
    user: user
  }), activeTab === 'followups' && user?.role !== 'broker' && /*#__PURE__*/React.createElement(FollowUpsPage, {
    user: user
  }), activeTab === 'statewide' && user?.role !== 'broker' && /*#__PURE__*/React.createElement(StatewideDiscovery, null), activeTab === 'intelligence' && /*#__PURE__*/React.createElement(SunbeltIntelligence, {
    user: user
  }), activeTab === 'feed' && /*#__PURE__*/React.createElement(LiveIntelligenceFeed, null), activeTab === 'intent' && /*#__PURE__*/React.createElement(DeveloperIntentPanel, null), activeTab === 'capital' && /*#__PURE__*/React.createElement(CapitalFlowPanel, null), activeTab === 'signal_quality' && /*#__PURE__*/React.createElement(SignalIntelligencePanel, null), activeTab === 'predictions' && user?.role !== 'broker' && /*#__PURE__*/React.createElement(PredictedDevelopments, null), activeTab === 'markets' && user?.role !== 'broker' && /*#__PURE__*/React.createElement(MarketExpansion, null), activeTab === 'dealboard' && /*#__PURE__*/React.createElement(DealBoardPage, {
    user: user
  }), activeTab === 'prospecting' && /*#__PURE__*/React.createElement(ProspectingPage, {
    user: user
  }), activeTab === 'capital_groups' && /*#__PURE__*/React.createElement(CapitalGroupsPage, {
    user: user
  }), activeTab === 'linkedinhub' && /*#__PURE__*/React.createElement(LinkedInHub, {
    user: user
  }), activeTab === 'admin' && user && user.is_super_admin && /*#__PURE__*/React.createElement(AdminPage, {
    user: user
  }), activeTab === 'quoting' && user && user.role === 'admin' && /*#__PURE__*/React.createElement(QuotingPage, {
    user: user
  }), activeTab === 'underwriting' && user && user.role === 'admin' && /*#__PURE__*/React.createElement(UnderwritingSheet, {
    user: user
  }), activeTab === 'dev_network' && /*#__PURE__*/React.createElement(DeveloperNetworkPanel, null), activeTab === 'corridors' && /*#__PURE__*/React.createElement(DevelopmentCorridorsPanel, null), activeTab === 'dev_momentum' && /*#__PURE__*/React.createElement(MomentumEnginePanel, null), activeTab === 'signal_discovery' && user && user.is_super_admin && /*#__PURE__*/React.createElement(SignalDiscoveryPanel, null), activeTab === 'quoting' && (!user || user.role !== 'admin') && (() => {
    setActiveTab(ROLE_DEFAULT_TAB[user?.role] || 'command');
    return null;
  })(), activeTab === 'underwriting' && (!user || user.role !== 'admin') && (() => {
    setActiveTab(ROLE_DEFAULT_TAB[user?.role] || 'command');
    return null;
  })(), user?.role === 'broker' && ['discovery', 'pipeline', 'followups', 'statewide', 'predictions', 'markets'].includes(activeTab) && (() => {
    setActiveTab('command');
    return null;
  })(), showEmailModal && /*#__PURE__*/React.createElement(EmailModal, {
    email: emailTemplate,
    prospect: selectedProspect,
    onClose: () => setShowEmailModal(false)
  }), touchpointTarget && /*#__PURE__*/React.createElement(TouchpointModal, {
    target: touchpointTarget,
    onClose: () => setTouchpointTarget(null),
    onSaved: () => {
      loadCrmStatuses(prospects);
    }
  }));
}
function Header({
  user,
  onLogout
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      ...styles.header,
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      textAlign: 'left'
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    style: {
      ...styles.title,
      fontSize: '1.8rem'
    }
  }, "BTR COMMAND"), /*#__PURE__*/React.createElement("p", {
    className: "text-sm text-slate-400 mt-0.5"
  }, "Real\u2011Time Operator & Capital Intelligence"), /*#__PURE__*/React.createElement("div", {
    className: "h-[2px] mt-2 w-48 bg-gradient-to-r from-emerald-400/90 via-emerald-400/30 to-transparent rounded-full"
  })), user && /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-3 flex-shrink-0"
  }, /*#__PURE__*/React.createElement(DensityToggle, null), /*#__PURE__*/React.createElement("span", {
    className: "text-sm text-slate-400"
  }, user.name), /*#__PURE__*/React.createElement("span", {
    className: cn('text-[0.65rem] px-2 py-0.5 rounded-lg font-semibold uppercase', user.role === 'admin' ? 'bg-purple-500/15 text-purple-300' : user.role === 'broker' ? 'bg-amber-500/15 text-amber-300' : 'bg-cyan-500/15 text-cyan-300')
  }, user.role), /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: {
      ...styles.actionBtn,
      fontSize: '0.75rem'
    },
    onClick: onLogout
  }, "Logout")));
}

// Default tab per role (for route guard redirects)
const ROLE_DEFAULT_TAB = {
  broker: 'command',
  producer: 'command',
  admin: 'command'
};

// Broker-mode label mappings
const BROKER_LABELS = {
  'Trigger Severity': 'Deal Heat',
  'Insurance Triggers': 'Growth Signals',
  'Competitive Difficulty': 'Deal Complexity'
};
function brokerLabel(label, role) {
  return role === 'broker' ? BROKER_LABELS[label] || label : label;
}
function LinkedInHub({
  user
}) {
  const [prospects, setProspects] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [query, setQuery] = useState('');
  const [sortBy, setSortBy] = useState('score');
  const [ssProspects, setSsProspects] = useState([]);
  const [copiedId, setCopiedId] = useState(null);
  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const [pRes, sRes] = await Promise.all([fetch(`${API_BASE}/api/prospects`).then(r => r.json()).catch(() => ({
          prospects: []
        })), fetch(`${API_BASE}/api/signalstack/prospects`).then(r => r.ok ? r.json() : {
          prospects: []
        }).catch(() => ({
          prospects: []
        }))]);
        if (cancelled) return;
        setProspects(Array.isArray(pRes?.prospects) ? pRes.prospects : []);
        setSsProspects(Array.isArray(sRes?.prospects) ? sRes.prospects : []);
      } catch (e) {
        if (!cancelled) setError(e.message || 'Failed to load');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, []);
  const linkedinProspects = useMemo(() => {
    const list = (prospects || []).filter(p => validLinkedIn(p.linkedin));
    const q = query.trim().toLowerCase();
    const filtered = q ? list.filter(p => (p.company || '').toLowerCase().includes(q) || (p.executive || '').toLowerCase().includes(q) || (p.title || '').toLowerCase().includes(q) || (p.city || '').toLowerCase().includes(q) || (p.state || '').toLowerCase().includes(q)) : list;
    const sorted = [...filtered];
    if (sortBy === 'score') sorted.sort((a, b) => (b.score || 0) - (a.score || 0));else if (sortBy === 'company') sorted.sort((a, b) => (a.company || '').localeCompare(b.company || ''));else if (sortBy === 'executive') sorted.sort((a, b) => (a.executive || '').localeCompare(b.executive || ''));
    return sorted;
  }, [prospects, query, sortBy]);
  const ssWithLinks = useMemo(() => (ssProspects || []).filter(p => p.linkedin_url && String(p.linkedin_url).includes('linkedin.com/')), [ssProspects]);
  const totalProspects = (prospects || []).length;
  const withLinks = linkedinProspects.length;
  const coverage = totalProspects > 0 ? Math.round(withLinks / totalProspects * 100) : 0;
  const uniqueCompanies = new Set(linkedinProspects.map(p => p.company)).size;
  const copyLink = (id, url) => {
    try {
      navigator.clipboard.writeText(normalizeLinkedIn(url));
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 1500);
    } catch {}
  };
  const cellStyle = {
    padding: '0.75rem',
    borderBottom: '1px solid #e2e8f0',
    fontSize: '0.85rem',
    color: '#1e293b',
    verticalAlign: 'top'
  };
  const headStyle = {
    ...cellStyle,
    color: '#64748b',
    fontWeight: 600,
    fontSize: '0.75rem',
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    borderBottom: '1px solid #e2e8f0',
    textAlign: 'left'
  };
  return /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '1.5rem 0'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      flexWrap: 'wrap',
      gap: '1rem',
      marginBottom: '1.25rem'
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '1.5rem',
      color: '#1e293b',
      margin: 0
    }
  }, "LinkedIn Hub"), /*#__PURE__*/React.createElement("p", {
    style: {
      color: '#64748b',
      fontSize: '0.9rem',
      margin: '0.35rem 0 0'
    }
  }, "Centralized view of every LinkedIn touchpoint across your prospects, pipeline, and SignalStack contacts.")), /*#__PURE__*/React.createElement("a", {
    href: "/signalstack",
    target: "_blank",
    rel: "noopener noreferrer",
    style: {
      ...styles.btnPrimary,
      textDecoration: 'none',
      display: 'inline-flex',
      alignItems: 'center'
    }
  }, "Open SignalStack \u2192")), /*#__PURE__*/React.createElement("div", {
    style: styles.statsBar
  }, /*#__PURE__*/React.createElement(StatCard, {
    label: "Prospects w/ LinkedIn",
    value: withLinks
  }), /*#__PURE__*/React.createElement(StatCard, {
    label: "Coverage",
    value: `${coverage}%`
  }), /*#__PURE__*/React.createElement(StatCard, {
    label: "Unique Companies",
    value: uniqueCompanies
  }), /*#__PURE__*/React.createElement(StatCard, {
    label: "SignalStack Contacts",
    value: ssWithLinks.length
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.75rem',
      flexWrap: 'wrap',
      margin: '1.25rem 0'
    }
  }, /*#__PURE__*/React.createElement("input", {
    type: "text",
    style: {
      ...styles.input,
      flex: '1 1 280px'
    },
    value: query,
    onChange: e => setQuery(e.target.value),
    placeholder: "Search company, executive, title, city\u2026"
  }), /*#__PURE__*/React.createElement("select", {
    style: styles.select,
    value: sortBy,
    onChange: e => setSortBy(e.target.value)
  }, /*#__PURE__*/React.createElement("option", {
    value: "score"
  }, "Sort: Score"), /*#__PURE__*/React.createElement("option", {
    value: "company"
  }, "Sort: Company"), /*#__PURE__*/React.createElement("option", {
    value: "executive"
  }, "Sort: Executive"))), loading && /*#__PURE__*/React.createElement("div", {
    style: {
      color: '#64748b',
      padding: '2rem',
      textAlign: 'center'
    }
  }, "Loading LinkedIn data\u2026"), error && /*#__PURE__*/React.createElement("div", {
    style: {
      color: '#f87171',
      padding: '1rem'
    }
  }, error), !loading && !error && /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#F1F5F9',
      border: '1px solid #e2e8f0',
      borderRadius: '0.75rem',
      overflow: 'hidden',
      marginBottom: '2rem'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '0.75rem 1rem',
      borderBottom: '1px solid #e2e8f0',
      color: '#334155',
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '0.9rem'
    }
  }, "Prospects with LinkedIn (", withLinks, ")"), withLinks === 0 ? /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '2rem',
      textAlign: 'center',
      color: '#64748b'
    }
  }, "No prospects with LinkedIn URLs yet. Run a Prospect Search to populate.") : /*#__PURE__*/React.createElement("div", {
    style: {
      overflowX: 'auto'
    }
  }, /*#__PURE__*/React.createElement("table", {
    style: {
      width: '100%',
      borderCollapse: 'collapse'
    }
  }, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", {
    style: headStyle
  }, "Company"), /*#__PURE__*/React.createElement("th", {
    style: headStyle
  }, "Executive"), /*#__PURE__*/React.createElement("th", {
    style: headStyle
  }, "Title"), /*#__PURE__*/React.createElement("th", {
    style: headStyle
  }, "Location"), /*#__PURE__*/React.createElement("th", {
    style: headStyle
  }, "Score"), /*#__PURE__*/React.createElement("th", {
    style: headStyle
  }, "LinkedIn"), /*#__PURE__*/React.createElement("th", {
    style: headStyle
  }, "Actions"))), /*#__PURE__*/React.createElement("tbody", null, linkedinProspects.map(p => {
    const url = normalizeLinkedIn(p.linkedin);
    return /*#__PURE__*/React.createElement("tr", {
      key: p.id
    }, /*#__PURE__*/React.createElement("td", {
      style: cellStyle
    }, /*#__PURE__*/React.createElement("strong", null, p.company || '—')), /*#__PURE__*/React.createElement("td", {
      style: cellStyle
    }, p.executive || '—'), /*#__PURE__*/React.createElement("td", {
      style: cellStyle
    }, p.title || '—'), /*#__PURE__*/React.createElement("td", {
      style: cellStyle
    }, [p.city, p.state].filter(Boolean).join(', ') || '—'), /*#__PURE__*/React.createElement("td", {
      style: cellStyle
    }, p.score ?? '—'), /*#__PURE__*/React.createElement("td", {
      style: {
        ...cellStyle,
        maxWidth: '260px',
        wordBreak: 'break-all'
      }
    }, /*#__PURE__*/React.createElement("a", {
      href: url,
      target: "_blank",
      rel: "noopener noreferrer",
      style: {
        color: '#3b82f6'
      }
    }, url)), /*#__PURE__*/React.createElement("td", {
      style: cellStyle
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: 'flex',
        gap: '0.5rem',
        flexWrap: 'wrap'
      }
    }, /*#__PURE__*/React.createElement("a", {
      href: url,
      target: "_blank",
      rel: "noopener noreferrer",
      style: {
        ...styles.actionBtn,
        textDecoration: 'none',
        display: 'inline-flex',
        alignItems: 'center'
      }
    }, "Open"), /*#__PURE__*/React.createElement("button", {
      style: styles.actionBtn,
      onClick: () => copyLink(p.id, p.linkedin)
    }, copiedId === p.id ? 'Copied!' : 'Copy'))));
  }))))), /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#F1F5F9',
      border: '1px solid #e2e8f0',
      borderRadius: '0.75rem',
      overflow: 'hidden'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '0.75rem 1rem',
      borderBottom: '1px solid #e2e8f0',
      color: '#334155',
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '0.9rem'
    }
  }, "SignalStack Contacts (", ssWithLinks.length, ")"), ssWithLinks.length === 0 ? /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '2rem',
      textAlign: 'center',
      color: '#64748b'
    }
  }, "No SignalStack contacts yet. ", /*#__PURE__*/React.createElement("a", {
    href: "/signalstack",
    target: "_blank",
    rel: "noopener noreferrer",
    style: {
      color: '#3b82f6'
    }
  }, "Add contacts in SignalStack \u2192")) : /*#__PURE__*/React.createElement("div", {
    style: {
      overflowX: 'auto'
    }
  }, /*#__PURE__*/React.createElement("table", {
    style: {
      width: '100%',
      borderCollapse: 'collapse'
    }
  }, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", {
    style: headStyle
  }, "Name"), /*#__PURE__*/React.createElement("th", {
    style: headStyle
  }, "Company"), /*#__PURE__*/React.createElement("th", {
    style: headStyle
  }, "Title"), /*#__PURE__*/React.createElement("th", {
    style: headStyle
  }, "LinkedIn"))), /*#__PURE__*/React.createElement("tbody", null, ssWithLinks.map(p => {
    const url = normalizeLinkedIn(p.linkedin_url);
    return /*#__PURE__*/React.createElement("tr", {
      key: p.id
    }, /*#__PURE__*/React.createElement("td", {
      style: cellStyle
    }, /*#__PURE__*/React.createElement("strong", null, p.full_name || '—')), /*#__PURE__*/React.createElement("td", {
      style: cellStyle
    }, p.company_name || '—'), /*#__PURE__*/React.createElement("td", {
      style: cellStyle
    }, p.title || '—'), /*#__PURE__*/React.createElement("td", {
      style: {
        ...cellStyle,
        maxWidth: '320px',
        wordBreak: 'break-all'
      }
    }, /*#__PURE__*/React.createElement("a", {
      href: url,
      target: "_blank",
      rel: "noopener noreferrer",
      style: {
        color: '#3b82f6'
      }
    }, url)));
  })))))));
}
// ===================================================================
// CAPITAL GROUPS — relationship tracking for repeat capital deployers
// ===================================================================

function CapitalGroupsPage({ user }) {
  const [groups, setGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [selectedGroup, setSelectedGroup] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [editingGroup, setEditingGroup] = useState(null);
  const [showTpForm, setShowTpForm] = useState(false);

  const [fName, setFName] = useState('');
  const [fType, setFType] = useState('developer');
  const [fMarkets, setFMarkets] = useState('');
  const [fStrategy, setFStrategy] = useState('');
  const [fNotes, setFNotes] = useState('');
  const [fStatus, setFStatus] = useState('prospect');
  const [fWarmth, setFWarmth] = useState(1);

  const [tpType, setTpType] = useState('call');
  const [tpOutcome, setTpOutcome] = useState('');
  const [tpNotes, setTpNotes] = useState('');
  const [tpContactId, setTpContactId] = useState('');
  const [tpDate, setTpDate] = useState(new Date().toISOString().slice(0, 10));

  const [showContactForm, setShowContactForm] = useState(false);
  const [cfFirst, setCfFirst] = useState('');
  const [cfLast, setCfLast] = useState('');
  const [cfTitle, setCfTitle] = useState('');
  const [cfEmail, setCfEmail] = useState('');
  const [cfPhone, setCfPhone] = useState('');
  const [cfNotes, setCfNotes] = useState('');
  const [editingContactId, setEditingContactId] = useState(null);
  const [editingContactNotes, setEditingContactNotes] = useState('');

  const typeLabels = { developer: 'Developer', capital_partner: 'Capital Partner', operator: 'Operator', broker: 'Broker' };
  const statusLabels = { prospect: 'Prospect', warm: 'Warm', engaged: 'Engaged', partner: 'Partner', dormant: 'Dormant', cold: 'Cold' };
  const statusColors = { prospect: '#94a3b8', warm: '#fbbf24', engaged: '#60a5fa', partner: '#34d399', dormant: '#a78bfa', cold: '#ef4444' };

  const loadGroups = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (search) params.set('q', search);
      if (typeFilter) params.set('type', typeFilter);
      if (statusFilter) params.set('status', statusFilter);
      const res = await fetch(`${API_BASE}/api/capital-groups?${params}`);
      const d = await res.json();
      setGroups(d.capital_groups || []);
    } catch (e) {
      console.error('Failed to load capital groups', e);
    }
    setLoading(false);
  };

  useEffect(() => { loadGroups(); }, [search, typeFilter, statusFilter]);

  const loadDetail = async (id) => {
    setDetailLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/capital-groups/${id}`);
      const d = await res.json();
      if (d.error) { alert(d.error); return; }
      setSelectedGroup(d);
    } catch (e) {
      console.error('Failed to load group detail', e);
    }
    setDetailLoading(false);
  };

  const openCreate = () => {
    setEditingGroup(null);
    setFName(''); setFType('developer'); setFMarkets(''); setFStrategy('');
    setFNotes(''); setFStatus('prospect'); setFWarmth(1);
    setShowForm(true);
  };

  const openEdit = (g) => {
    setEditingGroup(g);
    setFName(g.name || '');
    setFType(g.type || 'developer');
    setFMarkets(Array.isArray(g.markets) ? g.markets.join(', ') : '');
    setFStrategy(g.strategy || '');
    setFNotes(g.notes || '');
    setFStatus(g.relationship_status || 'prospect');
    setFWarmth(g.warmth_score || 1);
    setShowForm(true);
  };

  const saveForm = async () => {
    const payload = {
      name: fName, type: fType, markets: fMarkets, strategy: fStrategy,
      notes: fNotes, relationship_status: fStatus, warmth_score: fWarmth
    };
    try {
      const url = editingGroup
        ? `${API_BASE}/api/capital-groups/${editingGroup.id}`
        : `${API_BASE}/api/capital-groups`;
      const res = await fetch(url, {
        method: editingGroup ? 'PATCH' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const d = await res.json();
      if (d.error) { alert(d.error); return; }
      setShowForm(false);
      loadGroups();
      if (selectedGroup && editingGroup) loadDetail(editingGroup.id);
    } catch (e) {
      alert('Error saving group');
    }
  };

  const deleteGroup = async (id) => {
    if (!confirm('Delete this capital group? Properties will be unlinked, not deleted.')) return;
    try {
      await fetch(`${API_BASE}/api/capital-groups/${id}`, { method: 'DELETE' });
      if (selectedGroup?.id === id) setSelectedGroup(null);
      loadGroups();
    } catch (e) {
      alert('Error deleting group');
    }
  };

  const quickStatus = async (id, newStatus) => {
    try {
      await fetch(`${API_BASE}/api/capital-groups/${id}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ relationship_status: newStatus })
      });
      loadGroups();
      if (selectedGroup?.id === id) loadDetail(id);
    } catch (e) {
      console.error('Status update failed', e);
    }
  };

  const saveTouchpoint = async () => {
    if (!selectedGroup) return;
    try {
      var payload = { type: tpType, outcome: tpOutcome, notes: tpNotes };
      if (tpContactId) payload.contact_id = tpContactId;
      if (tpDate) payload.occurred_at = tpDate + 'T12:00:00';
      const res = await fetch(`${API_BASE}/api/capital-groups/${selectedGroup.id}/touchpoints`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const d = await res.json();
      if (d.error) { alert(d.error); return; }
      setShowTpForm(false);
      setTpType('call'); setTpOutcome(''); setTpNotes(''); setTpContactId(''); setTpDate(new Date().toISOString().slice(0, 10));
      loadDetail(selectedGroup.id);
      loadGroups();
    } catch (e) {
      alert('Error logging touchpoint');
    }
  };

  const saveContact = async () => {
    if (!selectedGroup) return;
    if (!cfFirst.trim() && !cfLast.trim()) { alert('First or last name required'); return; }
    try {
      const res = await fetch(`${API_BASE}/api/capital-groups/${selectedGroup.id}/contacts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ first_name: cfFirst, last_name: cfLast, title: cfTitle, email: cfEmail, phone: cfPhone, notes: cfNotes })
      });
      const d = await res.json();
      if (d.error) { alert(d.error); return; }
      setShowContactForm(false);
      setCfFirst(''); setCfLast(''); setCfTitle(''); setCfEmail(''); setCfPhone(''); setCfNotes('');
      loadDetail(selectedGroup.id);
    } catch (e) {
      alert('Error adding contact');
    }
  };

  const saveContactNotes = async (contactId, notes) => {
    if (!selectedGroup) return;
    try {
      await fetch(`${API_BASE}/api/capital-groups/${selectedGroup.id}/contacts/${contactId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ notes: notes })
      });
      setEditingContactId(null);
      loadDetail(selectedGroup.id);
    } catch (e) {
      alert('Error saving notes');
    }
  };

  const warmthBar = (score) => {
    const pct = (score / 10) * 100;
    const color = score >= 7 ? '#34d399' : score >= 4 ? '#fbbf24' : '#ef4444';
    return React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '0.5rem' } },
      React.createElement('div', { style: { flex: 1, height: '6px', background: '#e2e8f0', borderRadius: '3px', overflow: 'hidden', maxWidth: '80px' } },
        React.createElement('div', { style: { width: `${pct}%`, height: '100%', background: color, borderRadius: '3px', transition: 'width 0.3s' } })
      ),
      React.createElement('span', { style: { fontSize: '0.75rem', color, fontWeight: 600, fontFamily: "'JetBrains Mono', monospace" } }, score)
    );
  };

  const statusBadge = (status) => React.createElement('span', {
    style: {
      display: 'inline-block', fontSize: '0.7rem', fontWeight: 600,
      padding: '0.15rem 0.55rem', borderRadius: '9999px',
      background: `${statusColors[status] || '#94a3b8'}22`,
      color: statusColors[status] || '#94a3b8',
      textTransform: 'uppercase', letterSpacing: '0.04em'
    }
  }, statusLabels[status] || status);

  const typeBadge = (type) => React.createElement('span', {
    style: {
      display: 'inline-block', fontSize: '0.7rem', fontWeight: 500,
      padding: '0.15rem 0.5rem', borderRadius: '0.25rem',
      background: '#e2e8f0', color: '#64748b'
    }
  }, typeLabels[type] || type);

  const timeAgo = (dateStr) => {
    if (!dateStr) return 'never';
    const d = new Date(dateStr);
    const now = new Date();
    const days = Math.floor((now - d) / 86400000);
    if (days === 0) return 'today';
    if (days === 1) return 'yesterday';
    if (days < 30) return `${days}d ago`;
    if (days < 365) return `${Math.floor(days / 30)}mo ago`;
    return `${Math.floor(days / 365)}y ago`;
  };

  const renderFormModal = () => showForm && React.createElement('div', {
    style: { position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.25)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 },
    onClick: e => { if (e.target === e.currentTarget) setShowForm(false); }
  },
    React.createElement('div', {
      style: { background: '#FFFFFF', border: '1px solid #e2e8f0', borderRadius: '1rem', padding: '1.5rem', width: '480px', maxWidth: '95vw', maxHeight: '90vh', overflow: 'auto' }
    },
      React.createElement('h3', { style: { color: '#1e293b', fontSize: '1.1rem', fontFamily: "'Orbitron', sans-serif", margin: '0 0 1rem' } },
        editingGroup ? 'Edit Capital Group' : 'New Capital Group'
      ),
      React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.75rem' } },
        React.createElement('input', {
          value: fName, onChange: e => setFName(e.target.value),
          placeholder: 'Group name *',
          style: { ...styles.input, width: '100%', minWidth: 0, boxSizing: 'border-box' }
        }),
        React.createElement('div', { style: { display: 'flex', gap: '0.5rem' } },
          React.createElement('select', {
            value: fType, onChange: e => setFType(e.target.value),
            style: { ...styles.select, flex: 1 }
          },
            React.createElement('option', { value: 'developer' }, 'Developer'),
            React.createElement('option', { value: 'capital_partner' }, 'Capital Partner'),
            React.createElement('option', { value: 'operator' }, 'Operator'),
            React.createElement('option', { value: 'broker' }, 'Broker')
          ),
          React.createElement('select', {
            value: fStatus, onChange: e => setFStatus(e.target.value),
            style: { ...styles.select, flex: 1 }
          },
            React.createElement('option', { value: 'prospect' }, 'Prospect'),
            React.createElement('option', { value: 'warm' }, 'Warm'),
            React.createElement('option', { value: 'engaged' }, 'Engaged'),
            React.createElement('option', { value: 'partner' }, 'Partner'),
            React.createElement('option', { value: 'dormant' }, 'Dormant'),
            React.createElement('option', { value: 'cold' }, 'Cold')
          )
        ),
        React.createElement('input', {
          value: fMarkets, onChange: e => setFMarkets(e.target.value),
          placeholder: 'Markets (comma-separated, e.g. Dallas, Phoenix, Tampa)',
          style: { ...styles.input, width: '100%', minWidth: 0, boxSizing: 'border-box' }
        }),
        React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '0.75rem' } },
          React.createElement('label', { style: { color: '#64748b', fontSize: '0.85rem' } }, 'Warmth'),
          React.createElement('input', {
            type: 'range', min: 1, max: 10, value: fWarmth,
            onChange: e => setFWarmth(parseInt(e.target.value)),
            style: { flex: 1 }
          }),
          React.createElement('span', {
            style: { fontFamily: "'JetBrains Mono', monospace", fontSize: '0.85rem', color: fWarmth >= 7 ? '#34d399' : fWarmth >= 4 ? '#fbbf24' : '#ef4444', fontWeight: 600 }
          }, fWarmth)
        ),
        React.createElement('input', {
          value: fStrategy, onChange: e => setFStrategy(e.target.value),
          placeholder: 'Strategy (e.g. ground-up BTR, value-add, conversion)',
          style: { ...styles.input, width: '100%', minWidth: 0, boxSizing: 'border-box' }
        }),
        React.createElement('textarea', {
          value: fNotes, onChange: e => setFNotes(e.target.value),
          placeholder: 'Notes...',
          rows: 3,
          style: { ...styles.input, width: '100%', minWidth: 0, resize: 'vertical', boxSizing: 'border-box' }
        }),
        React.createElement('div', { style: { display: 'flex', gap: '0.5rem', justifyContent: 'flex-end', marginTop: '0.5rem' } },
          React.createElement('button', { onClick: () => setShowForm(false), style: styles.btn }, 'Cancel'),
          React.createElement('button', { onClick: saveForm, style: styles.btnPrimary },
            editingGroup ? 'Save Changes' : 'Create Group')
        )
      )
    )
  );

  // ---- DETAIL VIEW ----
  if (selectedGroup) {
    const g = selectedGroup;
    return React.createElement('div', null,
      React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem' } },
        React.createElement('button', {
          onClick: () => setSelectedGroup(null),
          style: { ...styles.btn, padding: '0.4rem 0.8rem', fontSize: '0.8rem' }
        }, '\u2190 Back'),
        React.createElement('div', { style: { flex: 1 } },
          React.createElement('h2', { style: { ...styles.sectionTitle, fontSize: '1.3rem', margin: 0 } }, g.name),
          React.createElement('div', { style: { display: 'flex', gap: '0.5rem', marginTop: '0.35rem', alignItems: 'center' } },
            typeBadge(g.type), statusBadge(g.relationship_status), warmthBar(g.warmth_score || 1)
          )
        ),
        React.createElement('div', { style: { display: 'flex', gap: '0.5rem' } },
          React.createElement('button', {
            onClick: () => openEdit(g),
            style: { ...styles.btn, borderColor: '#3b82f6', color: '#60a5fa', padding: '0.4rem 0.8rem', fontSize: '0.8rem' }
          }, 'Edit'),
          React.createElement('button', {
            onClick: () => deleteGroup(g.id),
            style: { ...styles.btn, borderColor: '#ef4444', color: '#f87171', padding: '0.4rem 0.8rem', fontSize: '0.8rem' }
          }, 'Delete')
        )
      ),

      detailLoading
        ? React.createElement('div', { style: { textAlign: 'center', padding: '2rem', color: '#64748b' } }, 'Loading...')
        : React.createElement('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' } },
          React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '1.25rem' } },
            React.createElement('div', { style: { ...styles.card, padding: '1.25rem' } },
              React.createElement('h3', { style: { color: '#1e293b', fontSize: '0.9rem', fontWeight: 600, margin: '0 0 0.75rem', fontFamily: "'Orbitron', sans-serif", letterSpacing: '0.04em' } }, 'DETAILS'),
              g.markets && g.markets.length > 0 && React.createElement('div', { style: { marginBottom: '0.5rem' } },
                React.createElement('span', { style: { color: '#64748b', fontSize: '0.75rem', textTransform: 'uppercase', fontWeight: 600 } }, 'Markets'),
                React.createElement('div', { style: { display: 'flex', gap: '0.35rem', flexWrap: 'wrap', marginTop: '0.25rem' } },
                  g.markets.map(m => React.createElement('span', {
                    key: m, style: { fontSize: '0.75rem', padding: '0.1rem 0.45rem', borderRadius: '0.25rem', background: '#F1F5F9', border: '1px solid #e2e8f0', color: '#64748b' }
                  }, m))
                )
              ),
              g.strategy && React.createElement('div', { style: { marginBottom: '0.5rem' } },
                React.createElement('span', { style: { color: '#64748b', fontSize: '0.75rem', textTransform: 'uppercase', fontWeight: 600 } }, 'Strategy'),
                React.createElement('p', { style: { color: '#1e293b', fontSize: '0.85rem', margin: '0.25rem 0 0', lineHeight: 1.5 } }, g.strategy)
              ),
              g.notes && React.createElement('div', { style: { marginBottom: '0.5rem' } },
                React.createElement('span', { style: { color: '#64748b', fontSize: '0.75rem', textTransform: 'uppercase', fontWeight: 600 } }, 'Notes'),
                React.createElement('p', { style: { color: '#1e293b', fontSize: '0.85rem', margin: '0.25rem 0 0', lineHeight: 1.5 } }, g.notes)
              ),
              React.createElement('div', { style: { display: 'flex', gap: '1.5rem', marginTop: '0.5rem', fontSize: '0.75rem', color: '#64748b' } },
                React.createElement('span', null, 'Last contacted: ', React.createElement('strong', { style: { color: '#64748b' } }, timeAgo(g.last_contacted_at))),
                React.createElement('span', null, 'Created: ', React.createElement('strong', { style: { color: '#64748b' } }, timeAgo(g.created_at)))
              )
            ),

            React.createElement('div', { style: { ...styles.card, padding: '1.25rem' } },
              React.createElement('h3', { style: { color: '#1e293b', fontSize: '0.9rem', fontWeight: 600, margin: '0 0 0.75rem', fontFamily: "'Orbitron', sans-serif", letterSpacing: '0.04em' } }, 'LINKED PROPERTIES'),
              (!g.properties || g.properties.length === 0)
                ? React.createElement('p', { style: { color: '#94a3b8', fontSize: '0.85rem' } }, 'No properties linked yet')
                : React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.5rem' } },
                    g.properties.map(p => React.createElement('div', {
                      key: p.id,
                      style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.5rem 0.75rem', background: '#F1F5F9', borderRadius: '0.5rem', border: '1px solid #e2e8f0' }
                    },
                      React.createElement('div', null,
                        React.createElement('div', { style: { color: '#1e293b', fontSize: '0.85rem', fontWeight: 500 } }, p.name || 'Unnamed'),
                        React.createElement('div', { style: { color: '#64748b', fontSize: '0.75rem' } },
                          [p.city, p.state].filter(Boolean).join(', '),
                          p.unit_count ? ` \u00b7 ${p.unit_count} units` : '',
                          p.project_type ? ` \u00b7 ${p.project_type}` : ''
                        )
                      ),
                      p.status && React.createElement('span', {
                        style: { fontSize: '0.7rem', padding: '0.1rem 0.4rem', borderRadius: '0.25rem', background: '#e2e8f0', color: '#64748b' }
                      }, p.status)
                    ))
                  )
            ),

            React.createElement('div', { style: { ...styles.card, padding: '1.25rem' } },
              React.createElement('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' } },
                React.createElement('h3', { style: { color: '#1e293b', fontSize: '0.9rem', fontWeight: 600, margin: 0, fontFamily: "'Orbitron', sans-serif", letterSpacing: '0.04em' } }, 'CONTACTS'),
                React.createElement('button', {
                  onClick: () => { setShowContactForm(true); setCfFirst(''); setCfLast(''); setCfTitle(''); setCfEmail(''); setCfPhone(''); setCfNotes(''); },
                  style: { ...styles.btnPrimary, padding: '0.35rem 0.75rem', fontSize: '0.75rem' }
                }, '+ Add Contact')
              ),

              showContactForm && React.createElement('div', {
                style: { background: '#F1F5F9', border: '1px solid #e2e8f0', borderRadius: '0.5rem', padding: '0.75rem', marginBottom: '0.75rem' }
              },
                React.createElement('div', { style: { display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' } },
                  React.createElement('input', {
                    value: cfFirst, onChange: e => setCfFirst(e.target.value),
                    placeholder: 'First name',
                    style: { ...styles.input, flex: 1, minWidth: 0 }
                  }),
                  React.createElement('input', {
                    value: cfLast, onChange: e => setCfLast(e.target.value),
                    placeholder: 'Last name',
                    style: { ...styles.input, flex: 1, minWidth: 0 }
                  })
                ),
                React.createElement('div', { style: { display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' } },
                  React.createElement('input', {
                    value: cfTitle, onChange: e => setCfTitle(e.target.value),
                    placeholder: 'Title (e.g. VP Acquisitions)',
                    style: { ...styles.input, flex: 1, minWidth: 0 }
                  })
                ),
                React.createElement('div', { style: { display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' } },
                  React.createElement('input', {
                    value: cfEmail, onChange: e => setCfEmail(e.target.value),
                    placeholder: 'Email',
                    style: { ...styles.input, flex: 1, minWidth: 0 }
                  }),
                  React.createElement('input', {
                    value: cfPhone, onChange: e => setCfPhone(e.target.value),
                    placeholder: 'Phone',
                    style: { ...styles.input, flex: 1, minWidth: 0 }
                  })
                ),
                React.createElement('textarea', {
                  value: cfNotes, onChange: e => setCfNotes(e.target.value),
                  placeholder: 'Notes about this contact...',
                  rows: 2,
                  style: { ...styles.input, width: '100%', minWidth: 0, resize: 'vertical', marginBottom: '0.5rem', boxSizing: 'border-box' }
                }),
                React.createElement('div', { style: { display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' } },
                  React.createElement('button', { onClick: () => setShowContactForm(false), style: { ...styles.btn, padding: '0.3rem 0.7rem', fontSize: '0.75rem' } }, 'Cancel'),
                  React.createElement('button', { onClick: saveContact, style: { ...styles.btnPrimary, padding: '0.3rem 0.7rem', fontSize: '0.75rem' } }, 'Save Contact')
                )
              ),

              (!g.contacts || g.contacts.length === 0)
                ? React.createElement('p', { style: { color: '#94a3b8', fontSize: '0.85rem' } }, 'No contacts added yet')
                : React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.5rem' } },
                    g.contacts.map(function(ct) {
                      var ctName = [ct.first_name, ct.last_name].filter(Boolean).join(' ');
                      var isEditing = editingContactId === ct.id;
                      return React.createElement('div', {
                        key: ct.id,
                        style: { padding: '0.6rem 0.75rem', background: '#F7F9FC', borderRadius: '0.5rem', border: '1px solid #e2e8f0' }
                      },
                        React.createElement('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' } },
                          React.createElement('div', { style: { minWidth: 0, flex: 1 } },
                            React.createElement('div', { style: { fontSize: '0.85rem', fontWeight: 600, color: '#1e293b' } }, ctName || 'Unnamed'),
                            ct.title && React.createElement('div', { style: { fontSize: '0.75rem', color: '#64748b', marginTop: '0.1rem' } }, ct.title),
                            React.createElement('div', { style: { display: 'flex', gap: '0.75rem', marginTop: '0.25rem', flexWrap: 'wrap' } },
                              ct.email && React.createElement('span', { style: { fontSize: '0.72rem', color: '#3b82f6' } }, ct.email),
                              ct.phone && React.createElement('span', { style: { fontSize: '0.72rem', color: '#64748b' } }, ct.phone)
                            ),
                            ct.last_touch_at && React.createElement('div', { style: { fontSize: '0.68rem', color: '#94a3b8', marginTop: '0.2rem' } },
                              'Last touch: ' + timeAgo(ct.last_touch_at))
                          ),
                          React.createElement('button', {
                            onClick: function() {
                              if (isEditing) { setEditingContactId(null); }
                              else { setEditingContactId(ct.id); setEditingContactNotes(ct.notes || ''); }
                            },
                            style: { ...styles.btn, padding: '0.2rem 0.5rem', fontSize: '0.68rem', flexShrink: 0 }
                          }, isEditing ? 'Cancel' : 'Notes')
                        ),
                        ct.notes && !isEditing && React.createElement('div', {
                          style: { fontSize: '0.75rem', color: '#64748b', marginTop: '0.35rem', padding: '0.35rem 0.5rem', background: '#FFFFFF', borderRadius: '0.35rem', border: '1px solid #f1f5f9', lineHeight: 1.4 }
                        }, ct.notes),
                        isEditing && React.createElement('div', { style: { marginTop: '0.4rem' } },
                          React.createElement('textarea', {
                            value: editingContactNotes,
                            onChange: function(e) { setEditingContactNotes(e.target.value); },
                            rows: 3,
                            placeholder: 'Add notes about this contact...',
                            style: { ...styles.input, width: '100%', minWidth: 0, resize: 'vertical', marginBottom: '0.4rem', boxSizing: 'border-box', fontSize: '0.78rem' }
                          }),
                          React.createElement('div', { style: { display: 'flex', justifyContent: 'flex-end' } },
                            React.createElement('button', {
                              onClick: function() { saveContactNotes(ct.id, editingContactNotes); },
                              style: { ...styles.btnPrimary, padding: '0.25rem 0.6rem', fontSize: '0.72rem' }
                            }, 'Save Notes')
                          )
                        )
                      );
                    })
                  )
            )
          ),

          React.createElement('div', { style: { ...styles.card, padding: '1.25rem' } },
            React.createElement('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' } },
              React.createElement('h3', { style: { color: '#1e293b', fontSize: '0.9rem', fontWeight: 600, margin: 0, fontFamily: "'Orbitron', sans-serif", letterSpacing: '0.04em' } }, 'ACTIVITY TIMELINE'),
              React.createElement('button', {
                onClick: () => { setShowTpForm(true); setTpType('call'); setTpOutcome(''); setTpNotes(''); setTpContactId(''); setTpDate(new Date().toISOString().slice(0, 10)); },
                style: { ...styles.btnPrimary, padding: '0.35rem 0.75rem', fontSize: '0.75rem' }
              }, '+ Log Touchpoint')
            ),

            showTpForm && React.createElement('div', {
              style: { background: '#F1F5F9', border: '1px solid #e2e8f0', borderRadius: '0.5rem', padding: '0.75rem', marginBottom: '0.75rem' }
            },
              React.createElement('div', { style: { display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' } },
                React.createElement('select', {
                  value: tpType, onChange: e => setTpType(e.target.value),
                  style: { ...styles.select, flex: 1, minWidth: 0 }
                },
                  React.createElement('option', { value: 'call' }, 'Call'),
                  React.createElement('option', { value: 'email' }, 'Email'),
                  React.createElement('option', { value: 'meeting' }, 'Meeting'),
                  React.createElement('option', { value: 'note' }, 'Note'),
                  React.createElement('option', { value: 'linkedin' }, 'LinkedIn'),
                  React.createElement('option', { value: 'referral' }, 'Referral')
                ),
                React.createElement('input', {
                  type: 'date', value: tpDate, onChange: e => setTpDate(e.target.value),
                  style: { ...styles.input, flex: 1, minWidth: 0 }
                })
              ),
              React.createElement('div', { style: { display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' } },
                React.createElement('select', {
                  value: tpContactId, onChange: e => setTpContactId(e.target.value),
                  style: { ...styles.select, flex: 1, minWidth: 0 }
                },
                  React.createElement('option', { value: '' },
                    g.contacts && g.contacts.length > 0 ? 'Contact (optional)' : 'No contacts yet'),
                  (g.contacts || []).map(function(c) {
                    return React.createElement('option', { key: c.id, value: c.id },
                      [c.first_name, c.last_name].filter(Boolean).join(' ') + (c.title ? ' \u2014 ' + c.title : ''));
                  })
                ),
                React.createElement('input', {
                  value: tpOutcome, onChange: e => setTpOutcome(e.target.value),
                  placeholder: 'Outcome (optional)',
                  style: { ...styles.input, flex: 1, minWidth: 0 }
                })
              ),
              React.createElement('textarea', {
                value: tpNotes, onChange: e => setTpNotes(e.target.value),
                placeholder: 'Notes...',
                rows: 2,
                style: { ...styles.input, width: '100%', minWidth: 0, resize: 'vertical', marginBottom: '0.5rem', boxSizing: 'border-box' }
              }),
              React.createElement('div', { style: { display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' } },
                React.createElement('button', { onClick: () => setShowTpForm(false), style: { ...styles.btn, padding: '0.3rem 0.7rem', fontSize: '0.75rem' } }, 'Cancel'),
                React.createElement('button', { onClick: saveTouchpoint, style: { ...styles.btnPrimary, padding: '0.3rem 0.7rem', fontSize: '0.75rem' } }, 'Save')
              )
            ),

            (!g.touchpoints || g.touchpoints.length === 0)
              ? React.createElement('p', { style: { color: '#94a3b8', fontSize: '0.85rem' } }, 'No touchpoints yet. Log your first interaction above.')
              : React.createElement('div', { style: { display: 'flex', flexDirection: 'column' } },
                  g.touchpoints.map((tp, i) => {
                    var contactName = [tp.contact_first, tp.contact_last].filter(Boolean).join(' ');
                    var tpDateStr = '';
                    try { tpDateStr = tp.occurred_at ? new Date(tp.occurred_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : ''; } catch(_) {}
                    return React.createElement('div', {
                      key: tp.id,
                      style: { display: 'flex', gap: '0.75rem', paddingBottom: i < g.touchpoints.length - 1 ? '0.75rem' : 0, borderLeft: '2px solid #e2e8f0', paddingLeft: '0.75rem', marginLeft: '0.35rem', position: 'relative' }
                    },
                      React.createElement('div', {
                        style: { position: 'absolute', left: '-5px', top: '2px', width: '8px', height: '8px', borderRadius: '50%', background: contactName ? '#14b8a6' : '#34d399' }
                      }),
                      React.createElement('div', { style: { flex: 1 } },
                        React.createElement('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem' } },
                          React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap', minWidth: 0 } },
                            React.createElement('span', { style: { fontSize: '0.8rem', fontWeight: 600, color: '#1e293b', textTransform: 'capitalize' } }, tp.type),
                            contactName && React.createElement('span', {
                              style: { fontSize: '0.72rem', fontWeight: 500, color: '#14b8a6', background: 'rgba(20,184,166,0.08)', padding: '0.05rem 0.4rem', borderRadius: '9999px' }
                            }, contactName)
                          ),
                          React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '0.4rem', flexShrink: 0 } },
                            tpDateStr && React.createElement('span', { style: { fontSize: '0.7rem', color: '#94a3b8', fontFamily: "'JetBrains Mono', monospace" } }, tpDateStr),
                            React.createElement('span', { style: { fontSize: '0.65rem', color: '#cbd5e1' } }, '\u00b7'),
                            React.createElement('span', { style: { fontSize: '0.7rem', color: '#64748b' } }, timeAgo(tp.occurred_at))
                          )
                        ),
                        tp.outcome && React.createElement('div', { style: { fontSize: '0.78rem', color: '#475569', marginTop: '0.15rem' } }, tp.outcome),
                        tp.notes && React.createElement('div', { style: { fontSize: '0.78rem', color: '#64748b', marginTop: '0.15rem', lineHeight: 1.4 } }, tp.notes)
                      )
                    );
                  })
                )
          )
        ),

      renderFormModal()
    );
  }

  // ---- LIST VIEW ----
  return React.createElement('div', null,
    React.createElement('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' } },
      React.createElement('div', null,
        React.createElement('h2', { style: { ...styles.sectionTitle, fontSize: '1.3rem', margin: 0 } }, 'Capital Groups'),
        React.createElement('p', { style: { color: '#64748b', fontSize: '0.85rem', margin: '0.25rem 0 0' } },
          `${groups.length} relationship${groups.length !== 1 ? 's' : ''} tracked`)
      ),
      React.createElement('button', { onClick: openCreate, style: styles.btnPrimary }, '+ New Group')
    ),

    React.createElement('div', { style: { display: 'flex', gap: '0.5rem', marginBottom: '1.25rem', flexWrap: 'wrap' } },
      React.createElement('input', {
        value: search, onChange: e => setSearch(e.target.value),
        placeholder: 'Search groups...',
        style: { ...styles.input, flex: 1, minWidth: '180px' }
      }),
      React.createElement('select', { value: typeFilter, onChange: e => setTypeFilter(e.target.value), style: styles.select },
        React.createElement('option', { value: '' }, 'All Types'),
        React.createElement('option', { value: 'developer' }, 'Developer'),
        React.createElement('option', { value: 'capital_partner' }, 'Capital Partner'),
        React.createElement('option', { value: 'operator' }, 'Operator'),
        React.createElement('option', { value: 'broker' }, 'Broker')
      ),
      React.createElement('select', { value: statusFilter, onChange: e => setStatusFilter(e.target.value), style: styles.select },
        React.createElement('option', { value: '' }, 'All Statuses'),
        React.createElement('option', { value: 'prospect' }, 'Prospect'),
        React.createElement('option', { value: 'warm' }, 'Warm'),
        React.createElement('option', { value: 'engaged' }, 'Engaged'),
        React.createElement('option', { value: 'partner' }, 'Partner'),
        React.createElement('option', { value: 'dormant' }, 'Dormant'),
        React.createElement('option', { value: 'cold' }, 'Cold')
      )
    ),

    loading
      ? React.createElement('div', { style: { textAlign: 'center', padding: '3rem', color: '#64748b' } }, 'Loading capital groups...')
      : groups.length === 0
        ? React.createElement('div', { style: styles.empty },
            React.createElement('div', { style: styles.emptyTitle }, 'No capital groups found'),
            React.createElement('p', { style: styles.emptyText },
              (search || typeFilter || statusFilter) ? 'Try adjusting your filters' : 'Add your first capital group to start tracking relationships'),
            !(search || typeFilter || statusFilter) && React.createElement('button', { onClick: openCreate, style: { ...styles.btnPrimary, marginTop: '1rem' } }, '+ New Group')
          )
        : React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.75rem' } },
            groups.map(g => React.createElement('div', {
              key: g.id,
              style: { ...styles.card, borderRadius: '0.75rem', padding: '1rem 1.25rem', cursor: 'pointer', transition: 'border-color 0.2s' },
              onClick: () => loadDetail(g.id)
            },
              React.createElement('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' } },
                React.createElement('div', { style: { flex: 1, minWidth: 0 } },
                  React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.35rem' } },
                    React.createElement('span', { style: { ...styles.companyName, fontSize: '1rem', marginBottom: 0 } }, g.name),
                    typeBadge(g.type),
                    statusBadge(g.relationship_status)
                  ),
                  g.markets && g.markets.length > 0 && React.createElement('div', { style: { color: '#64748b', fontSize: '0.8rem', marginBottom: '0.25rem' } },
                    g.markets.join(' \u00b7 ')
                  ),
                  g.strategy && React.createElement('div', { style: { color: '#64748b', fontSize: '0.8rem' } }, g.strategy)
                ),
                React.createElement('div', { style: { display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.35rem', flexShrink: 0 } },
                  warmthBar(g.warmth_score || 1),
                  React.createElement('span', { style: { fontSize: '0.7rem', color: '#64748b' } }, 'Last contact: ', timeAgo(g.last_contacted_at)),
                  React.createElement('select', {
                    value: g.relationship_status,
                    onClick: e => e.stopPropagation(),
                    onChange: e => quickStatus(g.id, e.target.value),
                    style: { ...styles.select, fontSize: '0.7rem', padding: '0.2rem 0.4rem', minWidth: 0 }
                  },
                    React.createElement('option', { value: 'prospect' }, 'Prospect'),
                    React.createElement('option', { value: 'warm' }, 'Warm'),
                    React.createElement('option', { value: 'engaged' }, 'Engaged'),
                    React.createElement('option', { value: 'partner' }, 'Partner'),
                    React.createElement('option', { value: 'dormant' }, 'Dormant'),
                    React.createElement('option', { value: 'cold' }, 'Cold')
                  )
                )
              )
            ))
          ),

    renderFormModal()
  );
}

// ===================================================================
// PROSPECTING PAGE
// ===================================================================

function ProspectingPage({ user }) {
  const [tab, setTab] = useState('summary');

  const tabs = [
    { id: 'summary', label: 'Summary' },
    { id: 'schedule', label: 'Schedule' },
    { id: 'feed', label: 'Feed' },
    { id: 'groups', label: 'Groups' },
    { id: 'contacts', label: 'Contacts' },
    { id: 'notices', label: 'Notices' },
    { id: 'sequences', label: 'Sequences' },
    { id: 'canvas', label: 'Canvas' }
  ];

  return React.createElement('div', null,
    React.createElement('div', { style: { marginBottom: '0.5rem' } },
      React.createElement('h2', {
        style: {
          fontFamily: "'Orbitron', sans-serif",
          fontSize: '1.3rem',
          fontWeight: 700,
          color: '#1e293b',
          margin: 0,
          letterSpacing: '0.04em'
        }
      }, 'Prospecting')
    ),

    React.createElement('div', {
      style: {
        display: 'flex',
        gap: 0,
        borderBottom: '1px solid #e2e8f0',
        marginTop: '1rem',
        marginBottom: '1.5rem'
      }
    },
      tabs.map(t => React.createElement('button', {
        key: t.id,
        onClick: () => setTab(t.id),
        style: {
          background: 'none',
          border: 'none',
          borderBottom: tab === t.id ? '2px solid #14b8a6' : '2px solid transparent',
          color: tab === t.id ? '#1e293b' : '#94a3b8',
          padding: '0.6rem 1.25rem',
          fontSize: '0.85rem',
          fontWeight: tab === t.id ? 600 : 400,
          cursor: 'pointer',
          fontFamily: "'Inter', sans-serif",
          transition: 'all 0.15s',
          marginBottom: '-1px'
        }
      }, t.label))
    ),

    tab === 'summary'
      ? React.createElement(ProspectingSummaryTab)
      : tab === 'groups'
        ? React.createElement(ProspectingGroupsTab)
      : tab === 'contacts'
        ? React.createElement(ProspectingContactsTab, { user: user })
      : tab === 'notices'
        ? React.createElement(ProspectingNoticesTab)
      : tab === 'sequences'
        ? React.createElement(ProspectingSequencesTab)
      : tab === 'schedule'
        ? React.createElement(ProspectingScheduleTab)
      : tab === 'feed'
        ? React.createElement(ProspectingFeedTab)
      : tab === 'canvas'
        ? React.createElement(ProspectingCanvasTab)
        : null
  );
}

// -- Prospecting tab components — backed by /api/prospecting endpoints --

const PROSP_TASK_TYPE_META = [
  { key: 'linkedin',      label: 'LinkedIn',   color: '#0a66c2' },
  { key: 'email',         label: 'Email',      color: '#f59e0b' },
  { key: 'call',          label: 'Calls',      color: '#14b8a6' },
  { key: 'meeting',       label: 'Meetings',   color: '#a78bfa' },
  { key: 'research',      label: 'Research',   color: '#60a5fa' },
  { key: 'check_in',      label: 'Check-ins',  color: '#fb923c' },
  { key: 'follow_up',     label: 'Follow-ups', color: '#fbbf24' },
  { key: 'sequence_step', label: 'Sequences',  color: '#a78bfa' }
];

function ProspectingSummaryTab() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(API_BASE + '/api/prospecting/summary')
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  if (loading) return React.createElement('div', { style: { color: '#64748b', padding: '2rem', textAlign: 'center' } }, 'Loading summary...');
  if (!data) return React.createElement('div', { style: { color: '#64748b', padding: '2rem', textAlign: 'center' } }, 'Unable to load summary data.');

  const snapshot = data.snapshot || [];
  const buckets = data.buckets || [];

  const sectionLabel = (text) => React.createElement('h3', {
    style: { fontSize: '0.78rem', color: '#64748b', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.06em', margin: '0 0 0.75rem' }
  }, text);

  const statCard = (s) => React.createElement('div', {
    key: s.label,
    style: { background: '#FFFFFF', border: '1px solid rgba(226,232,240,0.5)', borderRadius: '0.75rem', padding: '1rem 1.25rem', flex: 1, minWidth: '140px' }
  },
    React.createElement('div', { style: { fontSize: '0.68rem', color: '#64748b', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em', marginBottom: '0.35rem' } }, s.label),
    React.createElement('div', { style: { fontFamily: "'JetBrains Mono', monospace", fontSize: '1.6rem', fontWeight: 700, color: s.accent, lineHeight: 1.1 } }, s.value),
    React.createElement('div', { style: { fontSize: '0.72rem', color: '#94a3b8', marginTop: '0.2rem' } }, s.sub)
  );

  const bucketCard = (b) => React.createElement('div', {
    key: b.id,
    style: { background: '#FFFFFF', border: '1px solid rgba(226,232,240,0.5)', borderTop: '3px solid ' + b.accent, borderRadius: '0.75rem', padding: '1.25rem', flex: 1, minWidth: '220px' }
  },
    React.createElement('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem' } },
      React.createElement('span', { style: { fontSize: '0.9rem', fontWeight: 600, color: '#1e293b' } }, b.title),
      React.createElement('span', { style: { fontFamily: "'JetBrains Mono', monospace", fontSize: '1.4rem', fontWeight: 700, color: b.accent, lineHeight: 1 } }, b.total)
    ),
    React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.4rem' } },
      PROSP_TASK_TYPE_META.map(t => React.createElement('div', {
        key: t.key,
        style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between' }
      },
        React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '0.45rem' } },
          React.createElement('div', { style: { width: '8px', height: '8px', borderRadius: '2px', background: t.color } }),
          React.createElement('span', { style: { fontSize: '0.8rem', color: '#64748b' } }, t.label)
        ),
        React.createElement('span', {
          style: { fontSize: '0.85rem', fontWeight: 600, color: (b.counts[t.key] || 0) === 0 ? '#94a3b8' : '#1e293b', fontFamily: "'JetBrains Mono', monospace" }
        }, b.counts[t.key] || 0)
      ))
    )
  );

  return React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '1.75rem' } },
    React.createElement('div', null,
      sectionLabel('Relationship Snapshot'),
      React.createElement('div', { style: { display: 'flex', gap: '0.75rem', flexWrap: 'wrap' } }, snapshot.map(statCard))
    ),
    React.createElement('div', null,
      sectionLabel('Task Pipeline'),
      React.createElement('div', { style: { display: 'flex', gap: '0.75rem', flexWrap: 'wrap' } }, buckets.map(bucketCard))
    ),
    React.createElement(ProspectingOverviewPanel)
  );
}

function ProspectingOverviewPanel() {
  const [tasks, setTasks] = useState([]);
  const [notices, setNotices] = useState([]);
  const [staleGroups, setStaleGroups] = useState([]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    Promise.all([
      fetch(API_BASE + '/api/prospecting/tasks?status=pending').then(r => r.json()).catch(() => []),
      fetch(API_BASE + '/api/prospecting/notices?status=new').then(r => r.json()).catch(() => []),
      fetch(API_BASE + '/api/capital-groups?status=dormant&limit=100').then(r => r.json()).catch(() => ({ capital_groups: [] })),
      fetch(API_BASE + '/api/capital-groups?status=cold&limit=100').then(r => r.json()).catch(() => ({ capital_groups: [] }))
    ]).then(([t, n, dg, cg]) => {
      setTasks(Array.isArray(t) ? t : []);
      setNotices(Array.isArray(n) ? n : []);
      const dormant = (dg && dg.capital_groups) || [];
      const cold = (cg && cg.capital_groups) || [];
      setStaleGroups([...dormant, ...cold]);
      setLoaded(true);
    });
  }, []);

  if (!loaded) return null;

  const today = new Date().toISOString().slice(0, 10);
  const dueToday = tasks.filter(t => t.due_at && t.due_at.slice(0, 10) <= today);
  const overdue = tasks.filter(t => t.due_at && t.due_at.slice(0, 10) < today);
  const items = [];

  if (overdue.length > 0) {
    items.push({ icon: '\u26A0', color: '#f87171',
      text: overdue.length + ' overdue task' + (overdue.length !== 1 ? 's' : '') + ' need attention',
      sub: overdue.slice(0, 3).map(t => t.title).join(', ') + (overdue.length > 3 ? '...' : '') });
  }
  if (dueToday.length > overdue.length) {
    const todayOnly = dueToday.length - overdue.length;
    items.push({ icon: '\u23F0', color: '#fbbf24',
      text: todayOnly + ' task' + (todayOnly !== 1 ? 's' : '') + ' due today',
      sub: dueToday.filter(t => t.due_at && t.due_at.slice(0, 10) === today).slice(0, 3).map(t => t.title).join(', ') });
  }
  if (notices.length > 0) {
    items.push({ icon: '\u2709', color: '#60a5fa',
      text: notices.length + ' signal notice' + (notices.length !== 1 ? 's' : '') + ' awaiting review',
      sub: notices.slice(0, 3).map(n => n.title).join(', ') + (notices.length > 3 ? '...' : '') });
  }
  if (staleGroups.length > 0) {
    items.push({ icon: '\u2744', color: '#a78bfa',
      text: staleGroups.length + ' group' + (staleGroups.length !== 1 ? 's' : '') + ' dormant or cold',
      sub: staleGroups.slice(0, 4).map(g => g.name).join(', ') + (staleGroups.length > 4 ? '...' : '') });
  }

  if (items.length === 0 && tasks.length === 0) {
    return React.createElement('div', null,
      React.createElement('h3', {
        style: { fontSize: '0.78rem', color: '#64748b', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.06em', margin: '0 0 0.75rem' }
      }, 'Action Items'),
      React.createElement('div', {
        style: { background: '#FFFFFF', border: '1px solid rgba(226,232,240,0.5)', borderRadius: '0.75rem', padding: '1.5rem 1.25rem', textAlign: 'center' }
      },
        React.createElement('div', { style: { fontSize: '0.92rem', color: '#94a3b8', marginBottom: '0.3rem' } }, 'All clear'),
        React.createElement('div', { style: { fontSize: '0.8rem', color: '#64748b' } }, 'No overdue tasks, pending notices, or stale groups. Add contacts and groups to start prospecting.')
      )
    );
  }

  return React.createElement('div', null,
    React.createElement('h3', {
      style: { fontSize: '0.78rem', color: '#64748b', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.06em', margin: '0 0 0.75rem' }
    }, 'Action Items'),
    React.createElement('div', {
      style: { background: '#FFFFFF', border: '1px solid rgba(226,232,240,0.5)', borderRadius: '0.75rem', overflow: 'hidden' }
    },
      items.map((item, i) => React.createElement('div', {
        key: i,
        style: {
          display: 'flex', alignItems: 'flex-start', gap: '0.75rem',
          padding: '0.85rem 1.25rem',
          borderBottom: i < items.length - 1 ? '1px solid rgba(226,232,240,0.3)' : 'none'
        }
      },
        React.createElement('span', { style: { fontSize: '1rem', lineHeight: 1.3, flexShrink: 0 } }, item.icon),
        React.createElement('div', { style: { flex: 1, minWidth: 0 } },
          React.createElement('div', { style: { fontSize: '0.86rem', fontWeight: 600, color: item.color } }, item.text),
          item.sub ? React.createElement('div', {
            style: { fontSize: '0.76rem', color: '#64748b', marginTop: '0.2rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }
          }, item.sub) : null
        )
      ))
    )
  );
}

const PROSP_TYPE_LABELS = {
  developer: 'Developer',
  capital_partner: 'Capital Partner',
  operator: 'Operator',
  broker: 'Broker'
};

const PROSP_STATUS_META = {
  prospect: { label: 'Prospect', color: '#64748b' },
  warm:     { label: 'Warm',     color: '#fbbf24' },
  engaged:  { label: 'Engaged',  color: '#60a5fa' },
  partner:  { label: 'Partner',  color: '#14b8a6' },
  dormant:  { label: 'Dormant',  color: '#a78bfa' },
  cold:     { label: 'Cold',     color: '#ef4444' }
};

function ProspectingGroupsTab() {
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [sort, setSort] = useState('warmth');
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const params = new URLSearchParams();
    if (search) params.set('search', search);
    if (typeFilter) params.set('type', typeFilter);
    if (statusFilter) params.set('status', statusFilter);
    if (sort) params.set('sort', sort);
    fetch(API_BASE + '/api/prospecting/groups?' + params.toString())
      .then(r => r.json())
      .then(d => { setRows(Array.isArray(d) ? d : []); setLoading(false); })
      .catch(() => setLoading(false));
  }, [search, typeFilter, statusFilter, sort]);

  const inputStyle = {
    background: '#F1F5F9',
    border: '1px solid #e2e8f0',
    color: '#1e293b',
    padding: '0.5rem 0.75rem',
    borderRadius: '0.5rem',
    fontSize: '0.82rem',
    fontFamily: "'Inter', sans-serif",
    outline: 'none'
  };
  const selectStyle = { ...inputStyle, cursor: 'pointer' };
  const btnStyle = {
    background: 'transparent',
    border: '1px solid #e2e8f0',
    color: '#64748b',
    padding: '0.5rem 0.9rem',
    borderRadius: '0.5rem',
    fontSize: '0.8rem',
    cursor: 'pointer',
    fontFamily: "'Inter', sans-serif"
  };
  const btnPrimary = {
    ...btnStyle,
    background: '#14b8a6',
    border: 'none',
    color: '#0f172a',
    fontWeight: 600
  };

  const warmthBar = (score) => {
    const pct = (score / 10) * 100;
    const color = score >= 7 ? '#34d399' : score >= 4 ? '#fbbf24' : '#ef4444';
    return React.createElement('div', {
      style: { display: 'flex', alignItems: 'center', gap: '0.4rem' }
    },
      React.createElement('div', {
        style: { width: '50px', height: '5px', background: '#e2e8f0', borderRadius: '3px', overflow: 'hidden' }
      },
        React.createElement('div', {
          style: { width: `${pct}%`, height: '100%', background: color, borderRadius: '3px' }
        })
      ),
      React.createElement('span', {
        style: {
          fontSize: '0.72rem',
          color,
          fontWeight: 600,
          fontFamily: "'JetBrains Mono', monospace"
        }
      }, score)
    );
  };

  const COLS = '2fr 1.1fr 1.6fr 0.9fr 0.9fr 0.8fr 0.7fr 1.6fr';

  const headerCell = (label, extra) => React.createElement('span', {
    key: label,
    style: {
      fontSize: '0.68rem',
      color: '#64748b',
      textTransform: 'uppercase',
      fontWeight: 600,
      letterSpacing: '0.05em',
      ...(extra || {})
    }
  }, label);

  if (loading) return React.createElement('div', { style: { color: '#64748b', padding: '2rem', textAlign: 'center' } }, 'Loading groups...');

  return React.createElement('div', {
    style: { display: 'flex', flexDirection: 'column', gap: '1rem' }
  },
    React.createElement('div', {
      style: {
        display: 'flex',
        flexWrap: 'wrap',
        gap: '0.5rem',
        alignItems: 'center'
      }
    },
      React.createElement('input', {
        value: search,
        onChange: e => setSearch(e.target.value),
        placeholder: 'Search groups...',
        style: { ...inputStyle, flex: 1, minWidth: '200px' }
      }),
      React.createElement('select', {
        value: typeFilter,
        onChange: e => setTypeFilter(e.target.value),
        style: selectStyle
      },
        React.createElement('option', { value: '' }, 'All Types'),
        React.createElement('option', { value: 'developer' }, 'Developer'),
        React.createElement('option', { value: 'capital_partner' }, 'Capital Partner'),
        React.createElement('option', { value: 'operator' }, 'Operator'),
        React.createElement('option', { value: 'broker' }, 'Broker')
      ),
      React.createElement('select', {
        value: statusFilter,
        onChange: e => setStatusFilter(e.target.value),
        style: selectStyle
      },
        React.createElement('option', { value: '' }, 'All Statuses'),
        React.createElement('option', { value: 'prospect' }, 'Prospect'),
        React.createElement('option', { value: 'warm' }, 'Warm'),
        React.createElement('option', { value: 'engaged' }, 'Engaged'),
        React.createElement('option', { value: 'partner' }, 'Partner'),
        React.createElement('option', { value: 'dormant' }, 'Dormant'),
        React.createElement('option', { value: 'cold' }, 'Cold')
      ),
      React.createElement('select', {
        value: sort,
        onChange: e => setSort(e.target.value),
        style: selectStyle
      },
        React.createElement('option', { value: 'warmth' }, 'Sort: Warmth'),
        React.createElement('option', { value: 'name' }, 'Sort: Name'),
        React.createElement('option', { value: 'communities' }, 'Sort: Communities')
      ),
      React.createElement('div', { style: { flexGrow: 1 } })
    ),

    React.createElement('div', {
      style: {
        background: '#FFFFFF',
        border: '1px solid rgba(226,232,240,0.5)',
        borderRadius: '0.75rem',
        overflow: 'hidden'
      }
    },
      React.createElement('div', {
        style: {
          display: 'grid',
          gridTemplateColumns: COLS,
          gap: '0.5rem',
          padding: '0.65rem 1rem',
          borderBottom: '1px solid #e2e8f0',
          background: '#F1F5F9'
        }
      },
        headerCell('Group'),
        headerCell('Type'),
        headerCell('Markets'),
        headerCell('Status'),
        headerCell('Warmth'),
        headerCell('Last Touch'),
        headerCell('Communities', { textAlign: 'center' }),
        headerCell('Next Action')
      ),
      rows.length === 0
        ? React.createElement('div', {
            style: { padding: '2rem', textAlign: 'center', color: '#64748b', fontSize: '0.85rem' }
          }, 'No groups match current filters.')
        : rows.map(g => {
            const statusMeta = PROSP_STATUS_META[g.status] || { label: g.status, color: '#64748b' };
            return React.createElement('div', {
              key: g.id,
              style: {
                display: 'grid',
                gridTemplateColumns: COLS,
                gap: '0.5rem',
                padding: '0.7rem 1rem',
                borderBottom: '1px solid rgba(226,232,240,0.3)',
                alignItems: 'center'
              }
            },
              React.createElement('span', {
                style: { fontSize: '0.86rem', fontWeight: 600, color: '#1e293b' }
              }, g.name),
              React.createElement('span', {
                style: { fontSize: '0.78rem', color: '#64748b' }
              }, PROSP_TYPE_LABELS[g.type] || g.type),
              React.createElement('span', {
                style: { fontSize: '0.78rem', color: '#64748b' }
              }, g.markets.join(', ')),
              React.createElement('span', {
                style: {
                  fontSize: '0.7rem',
                  fontWeight: 600,
                  color: statusMeta.color,
                  textTransform: 'uppercase',
                  letterSpacing: '0.04em'
                }
              }, statusMeta.label),
              warmthBar(g.warmth),
              React.createElement('span', {
                style: { fontSize: '0.78rem', color: '#64748b' }
              }, g.lastTouch),
              React.createElement('span', {
                style: {
                  fontSize: '0.86rem',
                  fontWeight: 600,
                  color: g.communities === 0 ? '#94a3b8' : '#1e293b',
                  fontFamily: "'JetBrains Mono', monospace",
                  textAlign: 'center'
                }
              }, g.communities),
              React.createElement('span', {
                style: { fontSize: '0.78rem', color: '#64748b' }
              }, g.nextAction)
            );
          })
    )
  );
}

const CONTACT_STAGE_META = {
  cold:              { label: 'Cold',              color: '#ef4444' },
  initial_outreach:  { label: 'Initial Outreach',  color: '#fb923c' },
  light_conversation:{ label: 'Light Conversation', color: '#fbbf24' },
  active:            { label: 'Active',            color: '#60a5fa' },
  warm:              { label: 'Warm',              color: '#14b8a6' },
  strategic:         { label: 'Strategic',         color: '#a78bfa' },
  dormant:           { label: 'Dormant',           color: '#64748b' }
};

const NBA_TYPE_LABELS = {
  signal_company:    'Signal: Company',
  signal_industry:   'Signal: Industry',
  overdue_followup:  'Overdue Follow-up',
  stale_checkin:     'Check In',
  initial_outreach:  'Initial Outreach',
  none:              'No Action'
};

function _launchSignalStack(payload) {
  try { sessionStorage.setItem('signalstack_handoff', JSON.stringify(payload)); } catch(e) {}
  window.open('/signalstack#/generator', '_blank');
}

function _signalStackFromContact(contact) {
  fetch(API_BASE + '/api/prospecting/signalstack/contact/' + contact.id)
    .then(r => r.ok ? r.json() : null)
    .then(payload => {
      if (payload) return _launchSignalStack(payload);
      _launchSignalStack({
        contact: { first_name: contact.first_name, last_name: contact.last_name,
          title: contact.title, email: contact.email, linkedin_url: contact.linkedin_url },
        group: contact.group_name ? { name: contact.group_name } : null,
        relationship_stage: contact.relationship_stage,
        suggested_angle: (contact.next_best_action || {}).generated_reason || '',
        channel: 'email',
        title: 'Outreach — ' + [contact.first_name, contact.last_name].filter(Boolean).join(' ')
      });
    })
    .catch(() => {
      _launchSignalStack({
        contact: { first_name: contact.first_name, last_name: contact.last_name,
          title: contact.title, email: contact.email, linkedin_url: contact.linkedin_url },
        group: contact.group_name ? { name: contact.group_name } : null,
        relationship_stage: contact.relationship_stage,
        channel: 'email',
        title: 'Outreach — ' + [contact.first_name, contact.last_name].filter(Boolean).join(' ')
      });
    });
}

function ProspectingContactsTab({ user }) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [stageFilter, setStageFilter] = useState('');
  const [viewMode, setViewMode] = useState('board');
  const [showForm, setShowForm] = useState(false);
  const [groups, setGroups] = useState([]);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);
  const [dragId, setDragId] = useState(null);
  const [dragOver, setDragOver] = useState(null);
  const [assignId, setAssignId] = useState(null);

  const emptyForm = {
    first_name: '', last_name: '', title: '', group_id: '',
    linkedin_url: '', email: '', phone: '',
    first_reached_out_at: '', relationship_stage: 'cold', notes: ''
  };
  const [form, setForm] = useState(emptyForm);
  const setField = (k, v) => setForm(prev => ({ ...prev, [k]: v }));

  useEffect(() => {
    const params = new URLSearchParams();
    if (search) params.set('search', search);
    if (stageFilter) params.set('stage', stageFilter);
    setLoading(true);
    fetch(API_BASE + '/api/prospecting/contacts?' + params.toString())
      .then(r => r.json())
      .then(d => { setRows(Array.isArray(d) ? d : []); setLoading(false); })
      .catch(() => setLoading(false));
  }, [search, stageFilter, refreshKey]);

  useEffect(() => {
    fetch(API_BASE + '/api/capital-groups?limit=500')
      .then(r => r.json())
      .then(d => { setGroups((d && d.capital_groups) || []); })
      .catch(() => {});
  }, []);

  const handleSubmit = () => {
    if (!form.first_name.trim() && !form.last_name.trim()) {
      setFormError('First or last name is required.');
      return;
    }
    setSaving(true);
    setFormError('');
    const body = { ...form };
    if (!body.first_reached_out_at) delete body.first_reached_out_at;
    if (!body.group_id) delete body.group_id;
    fetch(API_BASE + '/api/prospecting/contacts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    })
      .then(r => { if (!r.ok) throw new Error('save failed'); return r.json(); })
      .then(() => {
        setForm(emptyForm);
        setShowForm(false);
        setSaving(false);
        setRefreshKey(k => k + 1);
      })
      .catch(() => { setFormError('Failed to save contact.'); setSaving(false); });
  };

  const inputStyle = {
    background: '#F1F5F9',
    border: '1px solid #e2e8f0',
    color: '#1e293b',
    padding: '0.5rem 0.75rem',
    borderRadius: '0.5rem',
    fontSize: '0.82rem',
    fontFamily: "'Inter', sans-serif",
    outline: 'none'
  };
  const selectStyle = { ...inputStyle, cursor: 'pointer' };
  const formInputStyle = { ...inputStyle, width: '100%', boxSizing: 'border-box' };
  const formSelectStyle = { ...formInputStyle, cursor: 'pointer' };
  const formLabel = (text) => React.createElement('label', {
    style: { fontSize: '0.72rem', color: '#64748b', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }
  }, text);

  const COLS = '1.6fr 1.1fr 1.3fr 1fr 0.9fr 0.9fr 1.3fr 0.8fr';

  const headerCell = (label) => React.createElement('span', {
    key: label,
    style: {
      fontSize: '0.68rem',
      color: '#64748b',
      textTransform: 'uppercase',
      fontWeight: 600,
      letterSpacing: '0.05em'
    }
  }, label);

  const ssBtn = (contact) => React.createElement('button', {
    onClick: (e) => { e.stopPropagation(); _signalStackFromContact(contact); },
    style: {
      background: 'transparent', border: '1px solid #e2e8f0', color: '#0d9488',
      padding: '0.25rem 0.5rem', borderRadius: '0.4rem', fontSize: '0.68rem',
      fontWeight: 600, cursor: 'pointer', fontFamily: "'Inter', sans-serif", whiteSpace: 'nowrap'
    }
  }, 'SignalStack');

  const createLeadFromContact = (contact) => {
    var name = (contact.group_name || [contact.first_name, contact.last_name].filter(Boolean).join(' ') || 'Unknown');
    fetch(API_BASE + '/api/crm/lead/from-prospecting', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        group_id: contact.group_id || null,
        contact_id: contact.id,
        company_name: name,
        website: contact.linkedin_url || null
      })
    }).then(function(r) { return r.json(); })
      .then(function(d) {
        if (d.success) {
          alert(d.already_exists ? 'Lead already exists in pipeline.' : 'Lead created in pipeline!');
        }
      }).catch(function() { alert('Failed to create lead.'); });
  };

  const pipeBtn = (contact) => React.createElement('button', {
    onClick: (e) => { e.stopPropagation(); createLeadFromContact(contact); },
    style: {
      background: 'transparent', border: '1px solid #e2e8f0', color: '#60a5fa',
      padding: '0.25rem 0.5rem', borderRadius: '0.4rem', fontSize: '0.68rem',
      fontWeight: 600, cursor: 'pointer', fontFamily: "'Inter', sans-serif", whiteSpace: 'nowrap'
    }
  }, 'Create Lead');

  const fmtDate = (d) => {
    if (!d) return '\u2014';
    try {
      const dt = new Date(d);
      if (isNaN(dt.getTime())) return '\u2014';
      return dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: '2-digit' });
    } catch(e) { return '\u2014'; }
  };

  const stageBadge = (stage) => {
    const meta = CONTACT_STAGE_META[stage] || { label: stage || 'Unknown', color: '#64748b' };
    return React.createElement('span', {
      style: {
        fontSize: '0.7rem',
        fontWeight: 600,
        color: meta.color,
        textTransform: 'uppercase',
        letterSpacing: '0.04em'
      }
    }, meta.label);
  };

  const nbaBadge = (nba) => {
    const nbaType = nba && (nba.next_best_action_type || nba.type);
    if (!nbaType || nbaType === 'none') {
      return React.createElement('span', { style: { fontSize: '0.78rem', color: '#94a3b8' } }, '\u2014');
    }
    const label = NBA_TYPE_LABELS[nbaType] || nbaType;
    return React.createElement('span', {
      style: { fontSize: '0.78rem', color: '#64748b' }
    }, label);
  };

  if (loading) return React.createElement('div', { style: { color: '#64748b', padding: '2rem', textAlign: 'center' } }, 'Loading contacts...');

  const formPanel = !showForm ? null : React.createElement('div', {
    style: {
      background: '#FFFFFF',
      border: '1px solid rgba(226,232,240,0.5)',
      borderRadius: '0.75rem',
      padding: '1.25rem',
      display: 'flex',
      flexDirection: 'column',
      gap: '0.85rem'
    }
  },
    React.createElement('div', {
      style: { fontSize: '0.92rem', fontWeight: 600, color: '#1e293b', marginBottom: '0.25rem' }
    }, 'New Contact'),
    React.createElement('div', {
      style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }
    },
      React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.3rem' } },
        formLabel('First Name'),
        React.createElement('input', { value: form.first_name, onChange: e => setField('first_name', e.target.value), style: formInputStyle, placeholder: 'Jane' })
      ),
      React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.3rem' } },
        formLabel('Last Name'),
        React.createElement('input', { value: form.last_name, onChange: e => setField('last_name', e.target.value), style: formInputStyle, placeholder: 'Smith' })
      ),
      React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.3rem' } },
        formLabel('Title'),
        React.createElement('input', { value: form.title, onChange: e => setField('title', e.target.value), style: formInputStyle, placeholder: 'VP of Acquisitions' })
      ),
      React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.3rem' } },
        formLabel('Group'),
        React.createElement('select', { value: form.group_id, onChange: e => setField('group_id', e.target.value), style: formSelectStyle },
          React.createElement('option', { value: '' }, 'No group'),
          ...groups.map(g => React.createElement('option', { key: g.id, value: g.id }, g.name))
        )
      ),
      React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.3rem' } },
        formLabel('Email'),
        React.createElement('input', { value: form.email, onChange: e => setField('email', e.target.value), style: formInputStyle, placeholder: 'jane@example.com', type: 'email' })
      ),
      React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.3rem' } },
        formLabel('Phone'),
        React.createElement('input', { value: form.phone, onChange: e => setField('phone', e.target.value), style: formInputStyle, placeholder: '(555) 123-4567' })
      ),
      React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.3rem' } },
        formLabel('LinkedIn URL'),
        React.createElement('input', { value: form.linkedin_url, onChange: e => setField('linkedin_url', e.target.value), style: formInputStyle, placeholder: 'https://linkedin.com/in/...' })
      ),
      React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.3rem' } },
        formLabel('First Reached Out'),
        React.createElement('input', { value: form.first_reached_out_at, onChange: e => setField('first_reached_out_at', e.target.value), style: formInputStyle, type: 'date' })
      ),
      React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.3rem' } },
        formLabel('Relationship Stage'),
        React.createElement('select', { value: form.relationship_stage, onChange: e => setField('relationship_stage', e.target.value), style: formSelectStyle },
          ...Object.entries(CONTACT_STAGE_META).map(([k, v]) =>
            React.createElement('option', { key: k, value: k }, v.label)
          )
        )
      )
    ),
    React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.3rem' } },
      formLabel('Notes'),
      React.createElement('textarea', {
        value: form.notes, onChange: e => setField('notes', e.target.value),
        style: { ...formInputStyle, minHeight: '60px', resize: 'vertical' },
        placeholder: 'Optional notes...'
      })
    ),
    formError ? React.createElement('div', { style: { color: '#ef4444', fontSize: '0.8rem' } }, formError) : null,
    React.createElement('div', { style: { display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' } },
      React.createElement('button', {
        onClick: () => { setShowForm(false); setForm(emptyForm); setFormError(''); },
        style: {
          background: 'transparent', border: '1px solid #e2e8f0', color: '#64748b',
          padding: '0.5rem 1rem', borderRadius: '0.5rem', fontSize: '0.82rem', cursor: 'pointer',
          fontFamily: "'Inter', sans-serif"
        }
      }, 'Cancel'),
      React.createElement('button', {
        onClick: handleSubmit,
        disabled: saving,
        style: {
          background: '#14b8a6', border: 'none', color: '#0f172a',
          padding: '0.5rem 1rem', borderRadius: '0.5rem', fontSize: '0.82rem', fontWeight: 600,
          cursor: saving ? 'not-allowed' : 'pointer', opacity: saving ? 0.6 : 1,
          fontFamily: "'Inter', sans-serif"
        }
      }, saving ? 'Saving...' : 'Save Contact')
    )
  );

  return React.createElement('div', {
    style: { display: 'flex', flexDirection: 'column', gap: '1rem' }
  },
    React.createElement('div', {
      style: { display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'center' }
    },
      React.createElement('input', {
        value: search,
        onChange: e => setSearch(e.target.value),
        placeholder: 'Search contacts...',
        style: { ...inputStyle, flex: 1, minWidth: '200px' }
      }),
      React.createElement('select', {
        value: stageFilter,
        onChange: e => setStageFilter(e.target.value),
        style: selectStyle
      },
        React.createElement('option', { value: '' }, 'All Stages'),
        ...Object.entries(CONTACT_STAGE_META).map(([k, v]) =>
          React.createElement('option', { key: k, value: k }, v.label)
        )
      ),
      React.createElement('div', {
        style: { display: 'inline-flex', border: '1px solid #e2e8f0', borderRadius: '0.5rem', overflow: 'hidden' }
      },
        ['board', 'table'].map(m => React.createElement('button', {
          key: m,
          onClick: () => setViewMode(m),
          style: {
            background: viewMode === m ? '#e2e8f0' : 'transparent',
            border: 'none',
            color: viewMode === m ? '#1e293b' : '#94a3b8',
            padding: '0.4rem 0.75rem',
            fontSize: '0.75rem',
            fontWeight: 600,
            cursor: 'pointer',
            fontFamily: "'Inter', sans-serif",
            textTransform: 'capitalize'
          }
        }, m))
      ),
      React.createElement('button', {
        onClick: () => setShowForm(f => !f),
        style: {
          background: showForm ? 'transparent' : '#14b8a6',
          border: showForm ? '1px solid #e2e8f0' : 'none',
          color: showForm ? '#94a3b8' : '#0f172a',
          padding: '0.5rem 0.9rem',
          borderRadius: '0.5rem',
          fontSize: '0.8rem',
          fontWeight: 600,
          cursor: 'pointer',
          fontFamily: "'Inter', sans-serif"
        }
      }, showForm ? 'Cancel' : '+ Add Contact')
    ),

    formPanel,

    viewMode === 'board'
      ? React.createElement('div', {
          style: {
            display: 'flex', gap: '0.6rem', overflowX: 'auto',
            paddingBottom: '0.5rem', minHeight: '60vh'
          }
        },
          [
            { key: 'cold',               label: 'New',              accent: '#64748b' },
            { key: 'initial_outreach',    label: 'Initial Outreach', accent: '#fb923c' },
            { key: 'light_conversation',  label: 'Follow-Up',        accent: '#fbbf24' },
            { key: 'active',             label: 'Conversation',     accent: '#60a5fa' },
            { key: 'warm',               label: 'Relationship',     accent: '#34d399' },
            { key: 'strategic',          label: 'Partner',           accent: '#a78bfa' },
            { key: 'dormant',            label: 'Dormant',           accent: '#94a3b8' }
          ].map(col => {
            var colRows = rows.filter(c => (c.relationship_stage || 'cold') === col.key);
            var isOver = dragOver === col.key && dragId;
            return React.createElement('div', {
              key: col.key,
              onDragOver: function(e) { e.preventDefault(); setDragOver(col.key); },
              onDragLeave: function() { setDragOver(null); },
              onDrop: function(e) {
                e.preventDefault();
                setDragOver(null);
                var cid = e.dataTransfer.getData('text/plain');
                if (!cid) return;
                var card = rows.find(function(r) { return String(r.id) === cid; });
                if (!card || (card.relationship_stage || 'cold') === col.key) { setDragId(null); return; }
                setRows(function(prev) { return prev.map(function(r) {
                  return String(r.id) === cid ? Object.assign({}, r, { relationship_stage: col.key }) : r;
                }); });
                setDragId(null);
                fetch(API_BASE + '/api/prospecting/contacts/' + cid, {
                  method: 'PATCH',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ relationship_stage: col.key })
                }).then(function(r) {
                  if (!r.ok) setRefreshKey(function(k) { return k + 1; });
                });
              },
              style: {
                flex: '1 0 180px', maxWidth: '240px', minWidth: '180px',
                background: isOver ? 'rgba(20,184,166,0.06)' : '#FFFFFF',
                border: isOver ? '1px solid ' + col.accent : '1px solid rgba(226,232,240,0.4)',
                borderTop: '2px solid ' + col.accent,
                borderRadius: '0.75rem',
                display: 'flex', flexDirection: 'column',
                overflow: 'hidden',
                transition: 'background 0.15s, border-color 0.15s'
              }
            },
              React.createElement('div', {
                style: {
                  padding: '0.65rem 0.75rem',
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  borderBottom: '1px solid rgba(226,232,240,0.3)'
                }
              },
                React.createElement('span', {
                  style: {
                    fontSize: '0.72rem', fontWeight: 700, color: col.accent,
                    textTransform: 'uppercase', letterSpacing: '0.06em'
                  }
                }, col.label),
                React.createElement('span', {
                  style: {
                    fontSize: '0.66rem', fontWeight: 600, color: '#94a3b8',
                    fontFamily: "'JetBrains Mono', monospace"
                  }
                }, String(colRows.length))
              ),
              React.createElement('div', {
                style: {
                  flex: 1, padding: '0.5rem', overflowY: 'auto',
                  display: 'flex', flexDirection: 'column', gap: '0.4rem'
                }
              },
                colRows.map(c => {
                  var nba = c.next_best_action || {};
                  var nbaLabel = NBA_TYPE_LABELS[nba.next_best_action_type || nba.type] || '';
                  var name = [c.first_name, c.last_name].filter(Boolean).join(' ') || 'Unnamed';
                  var lastTouch = c.last_touch_at ? c.last_touch_at.slice(0, 10) : '—';
                  var isDragging = dragId === String(c.id);
                  return React.createElement('div', {
                    key: c.id,
                    draggable: true,
                    onDragStart: function(e) {
                      e.dataTransfer.setData('text/plain', String(c.id));
                      e.dataTransfer.effectAllowed = 'move';
                      setDragId(String(c.id));
                    },
                    onDragEnd: function() { setDragId(null); setDragOver(null); },
                    style: {
                      background: '#FFFFFF',
                      border: '1px solid rgba(226,232,240,0.5)',
                      borderRadius: '0.5rem',
                      padding: '0.55rem 0.6rem',
                      cursor: 'grab',
                      opacity: isDragging ? 0.5 : 1,
                      transform: isDragging ? 'scale(1.03)' : 'none',
                      boxShadow: isDragging ? '0 4px 12px rgba(0,0,0,0.1)' : 'none',
                      transition: 'opacity 0.15s, transform 0.15s, box-shadow 0.15s'
                    }
                  },
                    React.createElement('div', {
                      style: { fontSize: '0.78rem', fontWeight: 600, color: '#1e293b', marginBottom: '0.2rem', lineHeight: 1.3 }
                    }, name),
                    c.title ? React.createElement('div', {
                      style: { fontSize: '0.68rem', color: '#64748b', marginBottom: '0.15rem', lineHeight: 1.25 }
                    }, c.title) : null,
                    c.group_name ? React.createElement('div', {
                      style: { fontSize: '0.68rem', color: '#64748b', marginBottom: '0.25rem', lineHeight: 1.25 }
                    }, c.group_name) : null,
                    React.createElement('div', {
                      style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.15rem' }
                    },
                      React.createElement('span', {
                        style: { fontSize: '0.62rem', color: '#94a3b8', fontFamily: "'JetBrains Mono', monospace" }
                      }, lastTouch),
                      nbaLabel ? React.createElement('span', {
                        style: {
                          fontSize: '0.58rem', fontWeight: 600, color: col.accent,
                          background: col.accent + '18', padding: '0.1rem 0.35rem',
                          borderRadius: '0.25rem', whiteSpace: 'nowrap'
                        }
                      }, nbaLabel) : null
                    ),
                    React.createElement('div', {
                      style: { marginTop: '0.3rem', borderTop: '1px solid rgba(226,232,240,0.3)', paddingTop: '0.3rem' }
                    },
                      assignId === c.id
                        ? React.createElement('select', {
                            autoFocus: true,
                            value: c.group_id || '',
                            onChange: function(e) {
                              var gid = e.target.value || null;
                              setAssignId(null);
                              setRows(function(prev) { return prev.map(function(r) {
                                if (r.id !== c.id) return r;
                                var g = groups.find(function(gr) { return gr.id === gid; });
                                return Object.assign({}, r, { group_id: gid, group_name: g ? g.entity_name : null });
                              }); });
                              fetch(API_BASE + '/api/prospecting/contacts/' + c.id, {
                                method: 'PATCH',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ group_id: gid })
                              }).then(function(r) {
                                if (!r.ok) setRefreshKey(function(k) { return k + 1; });
                              });
                            },
                            onBlur: function() { setAssignId(null); },
                            style: {
                              width: '100%', fontSize: '0.62rem', padding: '0.2rem 0.3rem',
                              background: '#F1F5F9', color: '#64748b',
                              border: '1px solid rgba(226,232,240,0.5)',
                              borderRadius: '0.3rem', fontFamily: "'Inter', sans-serif"
                            }
                          },
                            React.createElement('option', { value: '' }, '— None —'),
                            groups.map(function(g) {
                              return React.createElement('option', { key: g.id, value: g.id }, g.entity_name);
                            })
                          )
                        : React.createElement('div', {
                            style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' }
                          },
                            React.createElement('button', {
                              onClick: function(e) { e.stopPropagation(); setAssignId(c.id); },
                              style: {
                                background: 'transparent', border: 'none', color: '#94a3b8',
                                fontSize: '0.6rem', cursor: 'pointer', padding: 0,
                                fontFamily: "'Inter', sans-serif"
                              }
                            }, c.group_name ? 'Reassign' : 'Assign Group'),
                            React.createElement('button', {
                              onClick: function(e) { e.stopPropagation(); createLeadFromContact(c); },
                              style: {
                                background: 'transparent', border: 'none', color: '#60a5fa',
                                fontSize: '0.6rem', cursor: 'pointer', padding: 0,
                                fontFamily: "'Inter', sans-serif", fontWeight: 600
                              }
                            }, 'Create Lead')
                          )
                    )
                  );
                })
              )
            );
          })
        )
      : React.createElement('div', {
          style: {
            background: '#FFFFFF',
            border: '1px solid rgba(226,232,240,0.5)',
            borderRadius: '0.75rem',
            overflow: 'hidden'
          }
        },
          React.createElement('div', {
            style: {
              display: 'grid',
              gridTemplateColumns: COLS,
              gap: '0.5rem',
              padding: '0.65rem 1rem',
              borderBottom: '1px solid #e2e8f0',
              background: '#F1F5F9'
            }
          },
            headerCell('Name'),
            headerCell('Title'),
            headerCell('Group'),
            headerCell('Stage'),
            headerCell('First Reached'),
            headerCell('Last Touch'),
            headerCell('Next Best Action'),
            headerCell('')
          ),
          rows.length === 0
            ? React.createElement('div', {
                style: { padding: '3rem 2rem', textAlign: 'center', color: '#64748b' }
              },
                React.createElement('div', {
                  style: { fontSize: '1.1rem', marginBottom: '0.5rem', color: '#94a3b8' }
                }, 'No contacts yet'),
                React.createElement('div', {
                  style: { fontSize: '0.82rem' }
                }, 'Contacts will appear here as you add them through the system.')
              )
            : rows.map(c => React.createElement('div', {
                key: c.id,
                style: {
                  display: 'grid',
                  gridTemplateColumns: COLS,
                  gap: '0.5rem',
                  padding: '0.7rem 1rem',
                  borderBottom: '1px solid rgba(226,232,240,0.3)',
                  alignItems: 'center'
                }
              },
                React.createElement('span', {
                  style: { fontSize: '0.86rem', fontWeight: 600, color: '#1e293b' }
                }, [c.first_name, c.last_name].filter(Boolean).join(' ') || '\u2014'),
                React.createElement('span', {
                  style: { fontSize: '0.78rem', color: '#64748b' }
                }, c.title || '\u2014'),
                React.createElement('span', {
                  style: { fontSize: '0.78rem', color: '#64748b' }
                }, c.group_name || '\u2014'),
                stageBadge(c.relationship_stage),
                React.createElement('span', {
                  style: { fontSize: '0.78rem', color: '#64748b' }
                }, fmtDate(c.first_reached_out_at)),
                React.createElement('span', {
                  style: { fontSize: '0.78rem', color: '#64748b' }
                }, fmtDate(c.last_touch_at)),
                nbaBadge(c.next_best_action),
                React.createElement('div', { style: { display: 'flex', gap: '0.3rem' } },
                  pipeBtn(c),
                  ssBtn(c)
                )
              ))
        )
  );
}

function ProspectingNoticesTab() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('new');

  const load = () => {
    setLoading(true);
    fetch(API_BASE + '/api/prospecting/notices?status=' + encodeURIComponent(statusFilter))
      .then(r => r.json())
      .then(d => { setRows(Array.isArray(d) ? d : []); setLoading(false); })
      .catch(() => { setRows([]); setLoading(false); });
  };

  useEffect(() => { load(); }, [statusFilter]);

  const patchNotice = (nid, newStatus) => {
    fetch(API_BASE + '/api/prospecting/notices/' + nid, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus })
    }).then(() => {
      setRows(prev => prev.filter(r => r.id !== nid));
    }).catch(() => {});
  };

  const selectStyle = {
    background: '#F1F5F9',
    border: '1px solid #e2e8f0',
    color: '#1e293b',
    padding: '0.5rem 0.75rem',
    borderRadius: '0.5rem',
    fontSize: '0.82rem',
    fontFamily: "'Inter', sans-serif",
    outline: 'none',
    cursor: 'pointer'
  };

  const actionBtn = (label, onClick, accent) => React.createElement('button', {
    onClick: onClick,
    style: {
      background: accent ? 'rgba(20,184,166,0.12)' : 'transparent',
      border: '1px solid ' + (accent ? '#34d399' : '#e2e8f0'),
      color: accent ? '#34d399' : '#94a3b8',
      padding: '0.3rem 0.65rem',
      borderRadius: '0.4rem',
      fontSize: '0.72rem',
      fontWeight: 600,
      cursor: 'pointer',
      fontFamily: "'Inter', sans-serif",
      whiteSpace: 'nowrap'
    }
  }, label);

  const scopeBadge = (scope) => {
    const isCompany = scope === 'company';
    return React.createElement('span', {
      style: {
        fontSize: '0.66rem',
        fontWeight: 600,
        padding: '0.18rem 0.55rem',
        borderRadius: '9999px',
        background: isCompany ? 'rgba(96,165,250,0.12)' : 'rgba(251,191,36,0.12)',
        color: isCompany ? '#60a5fa' : '#fbbf24',
        textTransform: 'uppercase',
        letterSpacing: '0.05em'
      }
    }, isCompany ? 'Company' : 'Industry');
  };

  const fmtDate = (d) => {
    if (!d) return '\u2014';
    try {
      const dt = new Date(d);
      if (isNaN(dt.getTime())) return '\u2014';
      return dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: '2-digit' });
    } catch(e) { return '\u2014'; }
  };

  const COLS = '2.2fr 1fr 1.5fr 1.3fr 0.8fr 0.8fr 1.8fr';

  const headerCell = (label) => React.createElement('span', {
    key: label,
    style: {
      fontSize: '0.68rem',
      color: '#64748b',
      textTransform: 'uppercase',
      fontWeight: 600,
      letterSpacing: '0.05em'
    }
  }, label);

  if (loading) return React.createElement('div', { style: { color: '#64748b', padding: '2rem', textAlign: 'center' } }, 'Loading notices...');

  return React.createElement('div', {
    style: { display: 'flex', flexDirection: 'column', gap: '1rem' }
  },
    React.createElement('div', {
      style: { display: 'flex', gap: '0.5rem', alignItems: 'center' }
    },
      React.createElement('select', {
        value: statusFilter,
        onChange: e => setStatusFilter(e.target.value),
        style: selectStyle
      },
        React.createElement('option', { value: 'new' }, 'New'),
        React.createElement('option', { value: 'converted' }, 'Converted'),
        React.createElement('option', { value: 'dismissed' }, 'Dismissed')
      ),
      React.createElement('span', {
        style: { fontSize: '0.78rem', color: '#64748b', marginLeft: '0.5rem' }
      }, rows.length + ' notice' + (rows.length !== 1 ? 's' : ''))
    ),

    React.createElement('div', {
      style: {
        background: '#FFFFFF',
        border: '1px solid rgba(226,232,240,0.5)',
        borderRadius: '0.75rem',
        overflow: 'hidden'
      }
    },
      React.createElement('div', {
        style: {
          display: 'grid',
          gridTemplateColumns: COLS,
          gap: '0.5rem',
          padding: '0.65rem 1rem',
          borderBottom: '1px solid #e2e8f0',
          background: '#F1F5F9'
        }
      },
        headerCell('Title'),
        headerCell('Scope'),
        headerCell('Group / Contact'),
        headerCell('Summary'),
        headerCell('Importance'),
        headerCell('Date'),
        headerCell('Actions')
      ),
      rows.length === 0
        ? React.createElement('div', {
            style: { padding: '3rem 2rem', textAlign: 'center', color: '#64748b' }
          },
            React.createElement('div', {
              style: { fontSize: '1.1rem', marginBottom: '0.5rem', color: '#94a3b8' }
            }, statusFilter === 'new' ? 'No new notices' : 'No ' + statusFilter + ' notices'),
            React.createElement('div', {
              style: { fontSize: '0.82rem' }
            }, statusFilter === 'new'
              ? 'When Daily Discovery finds signals matching your groups, notices will appear here.'
              : 'Notices you have ' + statusFilter + ' will appear here.')
          )
        : rows.map(n => {
            const contactName = [n.first_name, n.last_name].filter(Boolean).join(' ');
            const relation = n.group_name
              ? (contactName ? n.group_name + ' \u00B7 ' + contactName : n.group_name)
              : (contactName || '\u2014');
            return React.createElement('div', {
              key: n.id,
              style: {
                display: 'grid',
                gridTemplateColumns: COLS,
                gap: '0.5rem',
                padding: '0.7rem 1rem',
                borderBottom: '1px solid rgba(226,232,240,0.3)',
                alignItems: 'center'
              }
            },
              React.createElement('div', { style: { minWidth: 0 } },
                React.createElement('div', {
                  style: { fontSize: '0.86rem', fontWeight: 600, color: '#1e293b', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }
                }, n.title || '\u2014'),
                n.source_url
                  ? React.createElement('a', {
                      href: n.source_url,
                      target: '_blank',
                      rel: 'noopener noreferrer',
                      style: { fontSize: '0.68rem', color: '#60a5fa', textDecoration: 'none' }
                    }, 'source')
                  : null
              ),
              scopeBadge(n.signal_scope),
              React.createElement('span', {
                style: { fontSize: '0.78rem', color: '#64748b', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }
              }, relation),
              React.createElement('span', {
                style: { fontSize: '0.76rem', color: '#64748b', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }
              }, n.summary || '\u2014'),
              React.createElement('span', {
                style: {
                  fontSize: '0.82rem',
                  fontWeight: 600,
                  color: (n.importance || 0) >= 7 ? '#34d399' : (n.importance || 0) >= 4 ? '#fbbf24' : '#94a3b8',
                  fontFamily: "'JetBrains Mono', monospace",
                  textAlign: 'center'
                }
              }, n.importance != null ? n.importance : '\u2014'),
              React.createElement('span', {
                style: { fontSize: '0.78rem', color: '#64748b' }
              }, fmtDate(n.created_at)),
              statusFilter === 'new'
                ? React.createElement('div', {
                    style: { display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }
                  },
                    actionBtn('Convert', () => patchNotice(n.id, 'converted'), true),
                    actionBtn('Dismiss', () => patchNotice(n.id, 'dismissed'), false),
                    actionBtn('SignalStack', () => {
                      _launchSignalStack({
                        contact: n.first_name || n.last_name
                          ? { first_name: n.first_name, last_name: n.last_name }
                          : null,
                        group: n.group_name ? { name: n.group_name } : null,
                        relationship_stage: null,
                        trigger: { title: n.title, summary: n.summary, source_url: n.source_url },
                        signal_scope: n.signal_scope,
                        suggested_angle: n.signal_scope === 'company'
                          ? 'Reference the company signal as a reason for reaching out.'
                          : 'Share the industry development and tie it to their portfolio.',
                        channel: 'email',
                        title: n.title
                      });
                    }, false)
                  )
                : React.createElement('span', {
                    style: { fontSize: '0.72rem', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 600 }
                  }, n.status)
            );
          })
    )
  );
}

function ProspectingSequencesTab() {
  const [seqs, setSeqs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(API_BASE + '/api/prospecting/sequences')
      .then(r => r.json())
      .then(d => { setSeqs(Array.isArray(d) ? d : []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  if (loading) return React.createElement('div', { style: { color: '#64748b', padding: '2rem', textAlign: 'center' } }, 'Loading sequences...');
  const statusBadge = (status) => {
    const meta = status === 'active'
      ? { label: 'Active', color: '#14b8a6', bg: 'rgba(20,184,166,0.12)' }
      : { label: 'Draft',  color: '#64748b', bg: 'rgba(148,163,184,0.12)' };
    return React.createElement('span', {
      style: {
        fontSize: '0.66rem',
        fontWeight: 600,
        padding: '0.18rem 0.55rem',
        borderRadius: '9999px',
        background: meta.bg,
        color: meta.color,
        textTransform: 'uppercase',
        letterSpacing: '0.05em'
      }
    }, meta.label);
  };

  const metricBlock = (label, value, accent) => React.createElement('div', {
    key: label,
    style: { display: 'flex', flexDirection: 'column', gap: '0.15rem', minWidth: '80px' }
  },
    React.createElement('div', {
      style: {
        fontSize: '0.64rem',
        color: '#64748b',
        textTransform: 'uppercase',
        fontWeight: 600,
        letterSpacing: '0.05em'
      }
    }, label),
    React.createElement('div', {
      style: {
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: '1.05rem',
        fontWeight: 700,
        color: accent || '#e2e8f0',
        lineHeight: 1.1
      }
    }, value)
  );

  const progressBar = (step, total) => {
    const pct = total > 0 ? (step / total) * 100 : 0;
    return React.createElement('div', {
      style: {
        height: '4px',
        background: '#e2e8f0',
        borderRadius: '2px',
        overflow: 'hidden',
        marginTop: '0.5rem'
      }
    },
      React.createElement('div', {
        style: {
          width: `${pct}%`,
          height: '100%',
          background: '#34d399',
          borderRadius: '2px'
        }
      })
    );
  };

  const sequenceCard = (seq) => React.createElement('div', {
    key: seq.id,
    style: {
      background: '#FFFFFF',
      border: '1px solid rgba(226,232,240,0.5)',
      borderRadius: '0.85rem',
      padding: '1.1rem 1.25rem',
      display: 'flex',
      flexDirection: 'column',
      gap: '0.65rem',
      flex: '1 1 320px',
      minWidth: '300px',
      opacity: seq.status === 'draft' ? 0.78 : 1
    }
  },
    React.createElement('div', {
      style: {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        gap: '0.75rem'
      }
    },
      React.createElement('div', { style: { flex: 1, minWidth: 0 } },
        React.createElement('div', {
          style: {
            fontSize: '0.98rem',
            fontWeight: 600,
            color: '#1e293b',
            fontFamily: "'Inter', sans-serif"
          }
        }, seq.name),
        React.createElement('div', {
          style: {
            fontSize: '0.76rem',
            color: '#64748b',
            marginTop: '0.2rem',
            lineHeight: 1.4
          }
        }, seq.description)
      ),
      statusBadge(seq.status)
    ),

    React.createElement('div', {
      style: {
        display: 'flex',
        flexWrap: 'wrap',
        gap: '1.25rem',
        paddingTop: '0.4rem',
        borderTop: '1px solid rgba(226,232,240,0.4)',
        marginTop: '0.15rem'
      }
    },
      metricBlock('Enrolled', seq.enrolled, '#3b82f6'),
      metricBlock('Step', `${seq.step}/${seq.totalSteps}`, '#e2e8f0'),
      metricBlock('Response', `${Math.round(seq.responseRate * 100)}%`, '#34d399'),
      metricBlock('Meetings', seq.meetings, '#a78bfa'),
      metricBlock('Updated', seq.lastUpdated, '#94a3b8')
    ),

    progressBar(seq.step, seq.totalSteps)
  );

  const activeSeqs = seqs.filter(s => s.status === 'active');
  const draftSeqs = seqs.filter(s => s.status === 'draft');

  const sectionLabel = (text) => React.createElement('h3', {
    style: {
      fontSize: '0.78rem',
      color: '#64748b',
      textTransform: 'uppercase',
      fontWeight: 600,
      letterSpacing: '0.06em',
      margin: '0 0 0.75rem'
    }
  }, text);

  if (seqs.length === 0) return React.createElement('div', {
    style: { background: '#FFFFFF', border: '1px solid rgba(226,232,240,0.5)', borderRadius: '0.85rem', padding: '2rem', textAlign: 'center', color: '#64748b' }
  }, 'No sequences yet. Create one from the API to get started.');

  return React.createElement('div', {
    style: { display: 'flex', flexDirection: 'column', gap: '1.75rem' }
  },
    React.createElement('div', null,
      sectionLabel(`Active Sequences (${activeSeqs.length})`),
      activeSeqs.length === 0
        ? React.createElement('div', { style: { color: '#64748b', fontSize: '0.85rem' } }, 'No active sequences.')
        : React.createElement('div', { style: { display: 'flex', flexWrap: 'wrap', gap: '0.85rem' } }, activeSeqs.map(sequenceCard))
    ),
    draftSeqs.length > 0 && React.createElement('div', null,
      sectionLabel(`Drafts (${draftSeqs.length})`),
      React.createElement('div', {
        style: { display: 'flex', flexWrap: 'wrap', gap: '0.85rem' }
      }, draftSeqs.map(sequenceCard))
    )
  );
}

const PROSP_SCHEDULE_TYPE_META = {
  follow_up:     { label: 'Follow-up',  color: '#fbbf24' },
  meeting:       { label: 'Meeting',    color: '#a78bfa' },
  sequence_step: { label: 'Sequence',   color: '#60a5fa' },
  check_in:      { label: 'Check-in',   color: '#fb923c' },
  research:      { label: 'Research',   color: '#3b82f6' },
  linkedin:      { label: 'LinkedIn',   color: '#0a66c2' },
  email:         { label: 'Email',      color: '#f59e0b' },
  call:          { label: 'Call',        color: '#14b8a6' }
};

function ProspectingScheduleTab() {
  const [schedule, setSchedule] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(API_BASE + '/api/prospecting/schedule?days=5')
      .then(r => r.json())
      .then(d => { setSchedule(Array.isArray(d) ? d : []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  if (loading) return React.createElement('div', { style: { color: '#64748b', padding: '2rem', textAlign: 'center' } }, 'Loading schedule...');
  const typeChip = (type) => {
    const meta = PROSP_SCHEDULE_TYPE_META[type] || { label: type, color: '#64748b' };
    return React.createElement('span', {
      style: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.35rem',
        fontSize: '0.7rem',
        fontWeight: 600,
        color: meta.color,
        textTransform: 'uppercase',
        letterSpacing: '0.04em',
        minWidth: '90px'
      }
    },
      React.createElement('span', {
        style: {
          width: '6px',
          height: '6px',
          borderRadius: '50%',
          background: meta.color,
          display: 'inline-block'
        }
      }),
      meta.label
    );
  };

  const scheduleRow = (item, isLast) => React.createElement('div', {
    key: item.id,
    style: {
      display: 'grid',
      gridTemplateColumns: '90px 110px 1fr 1.2fr 70px',
      gap: '0.75rem',
      alignItems: 'center',
      padding: '0.65rem 0.25rem',
      borderBottom: isLast ? 'none' : '1px solid rgba(226,232,240,0.3)'
    }
  },
    React.createElement('span', {
      style: {
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: '0.82rem',
        color: '#64748b'
      }
    }, item.time),
    typeChip(item.type),
    React.createElement('span', {
      style: { fontSize: '0.88rem', color: '#1e293b', fontWeight: 500 }
    }, item.title),
    React.createElement('span', {
      style: { fontSize: '0.8rem', color: '#64748b' }
    }, item.group),
    React.createElement('span', {
      style: {
        fontSize: '0.75rem',
        color: '#94a3b8',
        fontFamily: "'JetBrains Mono', monospace",
        textAlign: 'right'
      }
    }, item.duration)
  );

  const daySection = (day) => React.createElement('div', {
    key: day.id,
    style: {
      background: '#FFFFFF',
      border: '1px solid rgba(226,232,240,0.5)',
      borderRadius: '0.85rem',
      padding: '1.1rem 1.25rem'
    }
  },
    React.createElement('div', {
      style: {
        display: 'flex',
        alignItems: 'baseline',
        justifyContent: 'space-between',
        paddingBottom: '0.75rem',
        borderBottom: '1px solid rgba(226,232,240,0.4)',
        marginBottom: '0.25rem'
      }
    },
      React.createElement('div', {
        style: { display: 'flex', alignItems: 'baseline', gap: '0.6rem' }
      },
        React.createElement('h3', {
          style: {
            fontFamily: "'Orbitron', sans-serif",
            fontSize: '0.95rem',
            color: '#1e293b',
            margin: 0,
            letterSpacing: '0.04em',
            textTransform: 'uppercase'
          }
        }, day.day),
        day.date && React.createElement('span', {
          style: { fontSize: '0.78rem', color: '#64748b' }
        }, day.date)
      ),
      React.createElement('span', {
        style: {
          fontSize: '0.72rem',
          color: '#64748b',
          fontFamily: "'JetBrains Mono', monospace"
        }
      }, `${day.items.length} ${day.items.length === 1 ? 'item' : 'items'}`)
    ),
    React.createElement('div', {
      style: { display: 'flex', flexDirection: 'column' }
    }, day.items.map((it, i) => scheduleRow(it, i === day.items.length - 1)))
  );

  const totalItems = schedule.reduce((n, d) => n + d.items.length, 0);

  if (schedule.length === 0) return React.createElement('div', {
    style: { background: '#FFFFFF', border: '1px solid rgba(226,232,240,0.5)', borderRadius: '0.85rem', padding: '2rem', textAlign: 'center', color: '#64748b' }
  }, 'No tasks scheduled. Create capital groups and log touchpoints to generate tasks.');

  return React.createElement('div', {
    style: { display: 'flex', flexDirection: 'column', gap: '1rem' }
  },
    React.createElement('div', {
      style: {
        fontSize: '0.78rem',
        color: '#64748b',
        fontFamily: "'Inter', sans-serif"
      }
    }, `${totalItems} scheduled across ${schedule.length} days`),
    schedule.map(daySection)
  );
}

const PROSP_FEED_TYPE_META = {
  touchpoint:    { label: 'Touchpoint',   color: '#14b8a6' },
  note:          { label: 'Note',         color: '#60a5fa' },
  status_change: { label: 'Status',       color: '#fbbf24' },
  group_added:   { label: 'New Group',    color: '#3b82f6' },
  sequence:      { label: 'Sequence',     color: '#a78bfa' },
  signal:        { label: 'Market Signal', color: '#fb923c' }
};

function ProspectingFeedTab() {
  const [typeFilter, setTypeFilter] = useState('');
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const params = new URLSearchParams();
    if (typeFilter) params.set('type', typeFilter);
    fetch(API_BASE + '/api/prospecting/feed?' + params.toString())
      .then(r => r.json())
      .then(d => { setItems(Array.isArray(d) ? d : []); setLoading(false); })
      .catch(() => setLoading(false));
  }, [typeFilter]);

  if (loading) return React.createElement('div', { style: { color: '#64748b', padding: '2rem', textAlign: 'center' } }, 'Loading feed...');

  const filterChip = (value, label) => {
    const active = typeFilter === value;
    const color = value === '' ? '#94a3b8' : (PROSP_FEED_TYPE_META[value]?.color || '#94a3b8');
    return React.createElement('button', {
      key: value || 'all',
      onClick: () => setTypeFilter(value),
      style: {
        background: active ? `${color}22` : 'transparent',
        border: `1px solid ${active ? color : '#e2e8f0'}`,
        color: active ? color : '#94a3b8',
        padding: '0.3rem 0.7rem',
        borderRadius: '9999px',
        fontSize: '0.72rem',
        fontWeight: 600,
        cursor: 'pointer',
        fontFamily: "'Inter', sans-serif",
        textTransform: 'uppercase',
        letterSpacing: '0.04em'
      }
    }, label);
  };

  const feedRow = (item, isLast) => {
    const meta = PROSP_FEED_TYPE_META[item.type] || { label: item.type, color: '#64748b' };
    return React.createElement('div', {
      key: item.id,
      style: {
        display: 'grid',
        gridTemplateColumns: '14px 1fr auto',
        gap: '0.85rem',
        alignItems: 'flex-start',
        padding: '0.75rem 0',
        borderBottom: isLast ? 'none' : '1px solid rgba(226,232,240,0.3)'
      }
    },
      React.createElement('div', {
        style: {
          width: '8px',
          height: '8px',
          borderRadius: '50%',
          background: meta.color,
          marginTop: '7px'
        }
      }),
      React.createElement('div', null,
        React.createElement('div', {
          style: {
            display: 'flex',
            alignItems: 'baseline',
            gap: '0.5rem',
            flexWrap: 'wrap'
          }
        },
          React.createElement('span', {
            style: {
              fontSize: '0.62rem',
              fontWeight: 600,
              color: meta.color,
              textTransform: 'uppercase',
              letterSpacing: '0.05em'
            }
          }, meta.label),
          React.createElement('span', {
            style: { fontSize: '0.88rem', color: '#1e293b', fontWeight: 500 }
          }, item.action),
          React.createElement('span', {
            style: { fontSize: '0.78rem', color: '#94a3b8' }
          }, '\u2014'),
          React.createElement('span', {
            style: { fontSize: '0.82rem', color: '#14b8a6', fontWeight: 500 }
          }, item.group)
        ),
        React.createElement('div', {
          style: {
            fontSize: '0.78rem',
            color: '#64748b',
            marginTop: '0.2rem',
            lineHeight: 1.4
          }
        }, item.detail)
      ),
      React.createElement('span', {
        style: {
          fontSize: '0.72rem',
          color: '#64748b',
          fontFamily: "'JetBrains Mono', monospace",
          whiteSpace: 'nowrap',
          paddingTop: '2px'
        }
      }, item.ts)
    );
  };

  return React.createElement('div', {
    style: { display: 'flex', flexDirection: 'column', gap: '1rem' }
  },
    React.createElement('div', {
      style: { display: 'flex', gap: '0.4rem', flexWrap: 'wrap', alignItems: 'center' }
    },
      filterChip('', 'All'),
      filterChip('touchpoint', 'Touchpoints'),
      filterChip('note', 'Notes'),
      filterChip('status_change', 'Status'),
      filterChip('group_added', 'New Groups'),
      filterChip('sequence', 'Sequences'),
      filterChip('signal', 'Signals'),
      React.createElement('span', {
        style: {
          marginLeft: 'auto',
          fontSize: '0.72rem',
          color: '#64748b',
          fontFamily: "'JetBrains Mono', monospace"
        }
      }, `${items.length} ${items.length === 1 ? 'event' : 'events'}`)
    ),
    React.createElement('div', {
      style: {
        background: '#FFFFFF',
        border: '1px solid rgba(226,232,240,0.5)',
        borderRadius: '0.85rem',
        padding: '0.25rem 1.25rem'
      }
    },
      items.length === 0
        ? React.createElement('div', {
            style: {
              padding: '2rem',
              textAlign: 'center',
              color: '#64748b',
              fontSize: '0.85rem'
            }
          }, 'No activity matches this filter.')
        : items.map((it, i) => feedRow(it, i === items.length - 1))
    )
  );
}

function ProspectingCanvasTab() {
  const STORAGE_KEY = 'btr_canvas_template';
  const [imageUrl, setImageUrl] = useState('');
  const [loadedSrc, setLoadedSrc] = useState(null);
  const [imgError, setImgError] = useState(null);
  const [dotGrid, setDotGrid] = useState(null);
  const [stats, setStats] = useState(null);
  const canvasRef = useRef(null);

  const MIN_DOTS = 5000;

  const persist = (src) => {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify({ src: src || null })); } catch (_) {}
  };

  const loadImage = (src, skipPersist) => {
    if (!src) return;
    setImgError(null);
    setDotGrid(null);
    const img = new Image();
    img.crossOrigin = 'anonymous';
    img.onload = () => {
      setLoadedSrc(src);
      buildDotGrid(img);
      if (!skipPersist) persist(src);
    };
    img.onerror = () => setImgError('Could not load image. Check the URL or try another.');
    img.src = src;
  };

  const buildDotGrid = (img) => {
    const maxW = 960, maxH = 720;
    let w = img.width, h = img.height;
    if (w > maxW) { h = h * (maxW / w); w = maxW; }
    if (h > maxH) { w = w * (maxH / h); h = maxH; }
    w = Math.round(w); h = Math.round(h);

    const offscreen = document.createElement('canvas');
    offscreen.width = w; offscreen.height = h;
    const ctx = offscreen.getContext('2d');
    ctx.drawImage(img, 0, 0, w, h);
    const data = ctx.getImageData(0, 0, w, h).data;

    var bestDots = null;
    var bestRadius = 2.4;
    for (var sp = 6; sp >= 2.5; sp -= 0.5) {
      var dots = [];
      for (var y = sp; y < h; y += sp) {
        for (var x = sp; x < w; x += sp) {
          var ix = Math.round(x), iy = Math.round(y);
          var i = (iy * w + ix) * 4;
          var r = data[i], g = data[i + 1], b = data[i + 2], a = data[i + 3];
          if (a < 30) continue;
          dots.push({ x: ix, y: iy, r: r, g: g, b: b, a: a });
        }
      }
      bestDots = dots;
      bestRadius = Math.max(1.2, sp * 0.44);
      if (dots.length >= MIN_DOTS) break;
    }
    setDotGrid({ width: w, height: h, dots: bestDots, total: bestDots.length, dotRadius: bestRadius });
  };

  useEffect(() => {
    fetch(API_BASE + '/api/prospecting/canvas-stats')
      .then(r => r.json())
      .then(d => setStats(d))
      .catch(() => {});

    try {
      const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null');
      if (saved && saved.src) {
        if (!saved.src.startsWith('data:')) setImageUrl(saved.src);
        loadImage(saved.src, true);
      }
    } catch (_) {}
  }, []);

  const touchCount = stats ? stats.total_touchpoints : 0;

  useEffect(() => {
    if (!dotGrid || !canvasRef.current) return;
    const cvs = canvasRef.current;
    cvs.width = dotGrid.width;
    cvs.height = dotGrid.height;
    const ctx = cvs.getContext('2d');
    ctx.fillStyle = '#0f172a';
    ctx.fillRect(0, 0, cvs.width, cvs.height);
    const filled = Math.min(touchCount, dotGrid.total);
    var dr = dotGrid.dotRadius || 2.4;
    dotGrid.dots.forEach((d, i) => {
      ctx.beginPath();
      ctx.arc(d.x, d.y, dr, 0, Math.PI * 2);
      if (i < filled) {
        ctx.fillStyle = `rgba(${d.r},${d.g},${d.b},${(d.a / 255).toFixed(2)})`;
      } else {
        ctx.fillStyle = 'rgba(148,163,184,0.2)';
      }
      ctx.fill();
    });
  }, [dotGrid, touchCount]);

  const handleFile = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      setImageUrl('');
      loadImage(ev.target.result);
    };
    reader.readAsDataURL(file);
  };

  const pillStyle = {
    display: 'inline-block',
    fontSize: '0.68rem',
    fontWeight: 600,
    padding: '0.2rem 0.55rem',
    borderRadius: '9999px',
    fontFamily: "'JetBrains Mono', monospace",
    letterSpacing: '0.03em'
  };

  const inputStyle = {
    background: '#F1F5F9',
    border: '1px solid #e2e8f0',
    borderRadius: '0.5rem',
    color: '#1e293b',
    padding: '0.55rem 0.75rem',
    fontSize: '0.82rem',
    fontFamily: "'Inter', sans-serif",
    outline: 'none',
    boxSizing: 'border-box'
  };

  const pctFilled = dotGrid ? Math.min(100, Math.round((touchCount / dotGrid.total) * 100)) : 0;
  const filledDots = dotGrid ? Math.min(touchCount, dotGrid.total) : 0;
  const totalDots = dotGrid ? dotGrid.total : 0;
  const fmtDate = (d) => { if (!d) return '\u2014'; try { return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }); } catch(_) { return '\u2014'; } };

  var CHANNEL_COLORS = { email: '#3b82f6', linkedin: '#0ea5e9', call: '#14b8a6', meeting: '#8b5cf6', sms: '#f59e0b', other: '#94a3b8' };
  var channelColor = function(ch) { return CHANNEL_COLORS[ch] || CHANNEL_COLORS.other; };
  var channelLabel = function(ch) { return ch ? ch.charAt(0).toUpperCase() + ch.slice(1) : 'Other'; };

  var metricCard = function(icon, label, value, accent) {
    return React.createElement('div', { key: label, style: {
      background: '#FFFFFF', border: '1px solid #e2e8f0', borderRadius: '0.75rem',
      padding: '0.85rem 1rem', flex: '1 1 140px', minWidth: '130px',
      boxShadow: '0 1px 3px rgba(0,0,0,0.04)'
    }},
      React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.35rem' }},
        React.createElement('span', { style: { fontSize: '0.85rem', opacity: 0.7 }}, icon),
        React.createElement('span', { style: { fontSize: '0.65rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}, label)
      ),
      React.createElement('div', { style: { fontSize: '1.35rem', fontWeight: 700, color: accent || '#1e293b', fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.2 }},
        value != null ? value : '\u2014')
    );
  };

  var buildAreaChart = function(dailyData) {
    if (!dailyData || dailyData.length === 0) return null;
    var W = 400, H = 100, padL = 0, padR = 0, padT = 8, padB = 20;
    var cW = W - padL - padR, cH = H - padT - padB;
    var maxVal = Math.max.apply(null, dailyData.map(function(d){ return d.cnt; }));
    if (maxVal === 0) maxVal = 1;
    var pts = dailyData.map(function(d, i) {
      var x = padL + (i / Math.max(1, dailyData.length - 1)) * cW;
      var y = padT + cH - (d.cnt / maxVal) * cH;
      return { x: x, y: y, v: d.cnt, day: d.day };
    });
    var line = pts.map(function(p, i){ return (i === 0 ? 'M' : 'L') + p.x.toFixed(1) + ',' + p.y.toFixed(1); }).join(' ');
    var area = line + ' L' + pts[pts.length-1].x.toFixed(1) + ',' + (padT + cH) + ' L' + pts[0].x.toFixed(1) + ',' + (padT + cH) + ' Z';
    return React.createElement('svg', { viewBox: '0 0 ' + W + ' ' + H, style: { width: '100%', height: 'auto' }, preserveAspectRatio: 'xMidYMid meet' },
      React.createElement('defs', null,
        React.createElement('linearGradient', { id: 'areaGrad', x1: '0', y1: '0', x2: '0', y2: '1' },
          React.createElement('stop', { offset: '0%', stopColor: '#14b8a6', stopOpacity: '0.25' }),
          React.createElement('stop', { offset: '100%', stopColor: '#14b8a6', stopOpacity: '0.02' })
        )
      ),
      React.createElement('path', { d: area, fill: 'url(#areaGrad)', stroke: 'none' }),
      React.createElement('path', { d: line, fill: 'none', stroke: '#14b8a6', strokeWidth: '2', strokeLinecap: 'round', strokeLinejoin: 'round' }),
      pts.map(function(p, i) {
        return React.createElement('circle', { key: i, cx: p.x, cy: p.y, r: dailyData.length <= 15 ? 3 : 2, fill: '#FFFFFF', stroke: '#14b8a6', strokeWidth: '1.5' });
      }),
      pts.filter(function(_, i){ var step = Math.max(1, Math.floor(dailyData.length / 5)); return i % step === 0 || i === dailyData.length - 1; }).map(function(p, i) {
        var lbl = p.day ? p.day.slice(5) : '';
        return React.createElement('text', { key: 'l'+i, x: p.x, y: H - 2, textAnchor: 'middle', fill: '#94a3b8', fontSize: '8', fontFamily: 'Inter, sans-serif' }, lbl);
      })
    );
  };

  var buildDonut = function(channelData) {
    if (!channelData || channelData.length === 0) return null;
    var total = channelData.reduce(function(s, d){ return s + d.cnt; }, 0);
    if (total === 0) return null;
    var R = 42, cx = 55, cy = 55, sw = 12;
    var circ = 2 * Math.PI * R;
    var offset = 0;
    var segs = channelData.slice(0, 6).map(function(d, i) {
      var frac = d.cnt / total;
      var dash = frac * circ;
      var gap = circ - dash;
      var el = React.createElement('circle', {
        key: i, cx: cx, cy: cy, r: R, fill: 'none',
        stroke: channelColor(d.channel), strokeWidth: sw,
        strokeDasharray: dash.toFixed(1) + ' ' + gap.toFixed(1),
        strokeDashoffset: (-offset).toFixed(1),
        strokeLinecap: 'butt',
        style: { transition: 'stroke-dasharray 0.4s' }
      });
      offset += dash;
      return el;
    });
    return React.createElement('svg', { viewBox: '0 0 110 110', style: { width: '110px', height: '110px' }},
      React.createElement('circle', { cx: cx, cy: cy, r: R, fill: 'none', stroke: '#f1f5f9', strokeWidth: sw }),
      segs,
      React.createElement('text', { x: cx, y: cy - 4, textAnchor: 'middle', fill: '#1e293b', fontSize: '16', fontWeight: '700', fontFamily: "'JetBrains Mono', monospace" }, total),
      React.createElement('text', { x: cx, y: cy + 10, textAnchor: 'middle', fill: '#94a3b8', fontSize: '7', fontWeight: '500' }, 'total')
    );
  };

  var buildRadialProgress = function(pct) {
    var R = 42, cx = 55, cy = 55, sw = 10;
    var circ = 2 * Math.PI * R;
    var dash = (pct / 100) * circ;
    var progressColor = pct >= 100 ? '#10b981' : pct >= 50 ? '#14b8a6' : '#3b82f6';
    return React.createElement('svg', { viewBox: '0 0 110 110', style: { width: '110px', height: '110px' }},
      React.createElement('circle', { cx: cx, cy: cy, r: R, fill: 'none', stroke: '#f1f5f9', strokeWidth: sw }),
      React.createElement('circle', { cx: cx, cy: cy, r: R, fill: 'none', stroke: progressColor, strokeWidth: sw,
        strokeDasharray: dash.toFixed(1) + ' ' + (circ - dash).toFixed(1),
        strokeDashoffset: (circ * 0.25).toFixed(1), strokeLinecap: 'round',
        style: { transition: 'stroke-dasharray 0.6s ease' }
      }),
      React.createElement('text', { x: cx, y: cy - 2, textAnchor: 'middle', fill: '#1e293b', fontSize: '18', fontWeight: '700', fontFamily: "'JetBrains Mono', monospace" }, pct + '%'),
      React.createElement('text', { x: cx, y: cy + 12, textAnchor: 'middle', fill: '#94a3b8', fontSize: '7', fontWeight: '500' }, 'complete')
    );
  };

  var buildWeeklyBars = function(weeklyData) {
    if (!weeklyData || weeklyData.length === 0) return null;
    var maxVal = Math.max.apply(null, weeklyData.map(function(d){ return d.cnt; }));
    if (maxVal === 0) maxVal = 1;
    var barW = 32, gap = 8, H = 56;
    var totalW = weeklyData.length * (barW + gap) - gap;
    return React.createElement('svg', { viewBox: '0 0 ' + totalW + ' ' + (H + 14), style: { width: '100%', maxWidth: totalW + 'px', height: 'auto' }, preserveAspectRatio: 'xMidYMid meet' },
      weeklyData.map(function(d, i) {
        var bH = Math.max(2, (d.cnt / maxVal) * H);
        var x = i * (barW + gap);
        var lbl = d.week ? d.week.slice(5) : 'W' + (i + 1);
        return React.createElement('g', { key: i },
          React.createElement('rect', { x: x, y: H - bH, width: barW, height: bH, rx: 4, fill: i === weeklyData.length - 1 ? '#14b8a6' : '#e2e8f0' }),
          React.createElement('text', { x: x + barW / 2, y: H - bH - 4, textAnchor: 'middle', fill: '#64748b', fontSize: '8', fontWeight: '600', fontFamily: "'JetBrains Mono', monospace" }, d.cnt),
          React.createElement('text', { x: x + barW / 2, y: H + 12, textAnchor: 'middle', fill: '#94a3b8', fontSize: '7', fontFamily: 'Inter, sans-serif' }, lbl)
        );
      })
    );
  };

  var donutLegend = function(channelData) {
    if (!channelData || channelData.length === 0) return null;
    var total = channelData.reduce(function(s,d){ return s + d.cnt; }, 0);
    return React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.3rem' }},
      channelData.slice(0, 6).map(function(d) {
        var pct = total > 0 ? Math.round((d.cnt / total) * 100) : 0;
        return React.createElement('div', { key: d.channel, style: { display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.72rem' }},
          React.createElement('div', { style: { width: '8px', height: '8px', borderRadius: '2px', background: channelColor(d.channel), flexShrink: 0 }}),
          React.createElement('span', { style: { color: '#475569', fontWeight: 500 }}, channelLabel(d.channel)),
          React.createElement('span', { style: { color: '#94a3b8', fontFamily: "'JetBrains Mono', monospace", marginLeft: 'auto' }}, pct + '%')
        );
      })
    );
  };

  var chartCard = function(title, children, extraStyle) {
    return React.createElement('div', { style: Object.assign({
      background: '#FFFFFF', border: '1px solid #e2e8f0', borderRadius: '0.75rem',
      padding: '1rem', boxShadow: '0 1px 3px rgba(0,0,0,0.04)'
    }, extraStyle || {}) },
      React.createElement('div', { style: { fontSize: '0.7rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, marginBottom: '0.75rem' }}, title),
      children
    );
  };

  var emptyChart = function(msg) {
    return React.createElement('div', { style: { textAlign: 'center', padding: '1.5rem 0', color: '#cbd5e1', fontSize: '0.78rem' }}, msg || 'No data yet');
  };

  return React.createElement('div', {
    style: { display: 'flex', flexDirection: 'column', gap: '1rem' }
  },
    React.createElement('div', {
      style: {
        background: '#FFFFFF',
        border: '1px solid rgba(226,232,240,0.5)',
        borderRadius: '0.85rem',
        padding: '1rem 1.25rem'
      }
    },
      React.createElement('div', {
        style: { display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.75rem' }
      },
        React.createElement('span', { style: { fontSize: '1.1rem' } }, '\u{1F3A8}'),
        React.createElement('span', {
          style: {
            fontFamily: "'Orbitron', sans-serif",
            fontSize: '0.95rem',
            fontWeight: 700,
            color: '#1e293b',
            letterSpacing: '0.04em'
          }
        }, 'Relationship Canvas'),
        React.createElement('span', {
          style: { ...pillStyle, background: 'rgba(20,184,166,0.12)', color: '#14b8a6' }
        }, 'PORTFOLIO')
      ),

      React.createElement('div', {
        style: { display: 'flex', gap: '0.75rem', alignItems: 'flex-end', flexWrap: 'wrap' }
      },
        React.createElement('div', { style: { flex: '1 1 300px' } },
          React.createElement('label', {
            style: { fontSize: '0.68rem', color: '#64748b', display: 'block', marginBottom: '0.3rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }
          }, 'Image URL'),
          React.createElement('input', {
            type: 'text',
            placeholder: 'https://example.com/photo.jpg',
            value: imageUrl,
            onChange: (e) => setImageUrl(e.target.value),
            onKeyDown: (e) => { if (e.key === 'Enter') loadImage(imageUrl); },
            style: { ...inputStyle, width: '100%' }
          })
        ),
        React.createElement('button', {
          onClick: () => loadImage(imageUrl),
          disabled: !imageUrl.trim(),
          style: {
            background: imageUrl.trim() ? '#34d399' : '#e2e8f0',
            color: imageUrl.trim() ? '#0f172a' : '#64748b',
            border: 'none',
            borderRadius: '0.5rem',
            padding: '0.55rem 1rem',
            fontSize: '0.82rem',
            fontWeight: 600,
            cursor: imageUrl.trim() ? 'pointer' : 'default',
            fontFamily: "'Inter', sans-serif",
            whiteSpace: 'nowrap'
          }
        }, 'Load'),
        React.createElement('div', {
          style: { display: 'flex', flexDirection: 'column', gap: '0.2rem' }
        },
          React.createElement('label', {
            style: { fontSize: '0.68rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }
          }, 'Upload'),
          React.createElement('input', {
            type: 'file',
            accept: 'image/*',
            onChange: handleFile,
            style: { fontSize: '0.72rem', color: '#64748b', fontFamily: "'Inter', sans-serif" }
          })
        )
      ),
      imgError ? React.createElement('div', {
        style: { color: '#f87171', fontSize: '0.78rem', marginTop: '0.5rem' }
      }, imgError) : null
    ),

    React.createElement('div', {
      style: {
        background: '#FFFFFF',
        border: '1px solid rgba(226,232,240,0.5)',
        borderRadius: '0.85rem',
        padding: '1.25rem',
        minHeight: '520px',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: dotGrid ? 'flex-start' : 'center',
        flex: '1 1 auto'
      }
    },
      dotGrid
        ? React.createElement('div', {
            style: { display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.75rem', width: '100%' }
          },
            React.createElement('div', {
              style: { display: 'flex', alignItems: 'center', gap: '0.75rem', width: '100%', justifyContent: 'space-between', flexWrap: 'wrap' }
            },
              React.createElement('span', {
                style: { fontSize: '0.78rem', color: '#64748b' }
              }, `${filledDots.toLocaleString()} / ${totalDots.toLocaleString()} dots filled`),
              React.createElement('div', {
                style: { display: 'flex', alignItems: 'center', gap: '0.5rem' }
              },
                React.createElement('div', {
                  style: { width: '120px', height: '6px', background: '#FFFFFF', borderRadius: '3px', border: '1px solid #e2e8f0', overflow: 'hidden' }
                },
                  React.createElement('div', {
                    style: { width: `${pctFilled}%`, height: '100%', background: pctFilled >= 100 ? '#34d399' : '#60a5fa', borderRadius: '3px', transition: 'width 0.4s' }
                  })
                ),
                React.createElement('span', {
                  style: { ...pillStyle, background: pctFilled >= 100 ? 'rgba(20,184,166,0.15)' : 'rgba(96,165,250,0.12)', color: pctFilled >= 100 ? '#34d399' : '#60a5fa' }
                }, `${pctFilled}%`)
              ),
              React.createElement('span', {
                style: { fontSize: '0.72rem', color: '#64748b', fontFamily: "'JetBrains Mono', monospace" }
              }, `${dotGrid.width}\u00D7${dotGrid.height}px`)
            ),
            React.createElement('canvas', {
              ref: canvasRef,
              style: {
                borderRadius: '0.5rem',
                border: '1px solid #e2e8f0',
                maxWidth: '100%',
                width: '100%',
                height: 'auto'
              }
            }),
            React.createElement('p', {
              style: { fontSize: '0.75rem', color: '#64748b', textAlign: 'center', margin: 0, lineHeight: 1.5 }
            }, `${touchCount} touchpoint${touchCount === 1 ? '' : 's'} across all contacts. Every interaction fills the next dot.`)
          )
        : React.createElement('div', {
            style: { textAlign: 'center', padding: '3rem' }
          },
            React.createElement('div', {
              style: { fontSize: '3rem', marginBottom: '1rem', opacity: 0.3 }
            }, '\u25CC'),
            React.createElement('div', {
              style: { fontSize: '0.92rem', color: '#64748b', marginBottom: '0.4rem' }
            }, 'No image loaded'),
            React.createElement('div', {
              style: { fontSize: '0.82rem', color: '#94a3b8' }
            }, 'Paste a URL or upload a photo above to generate a dot template')
          )
    ),

    React.createElement('div', {
      style: {
        background: '#FFFFFF',
        border: '1px solid rgba(226,232,240,0.5)',
        borderRadius: '0.85rem',
        padding: '1.25rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '1rem'
      }
    },
      React.createElement('div', {
        style: { display: 'flex', alignItems: 'center', gap: '0.5rem' }
      },
        React.createElement('span', { style: { fontSize: '1rem' } }, '\u{1F4CA}'),
        React.createElement('span', {
          style: { fontFamily: "'Orbitron', sans-serif", fontSize: '0.85rem', fontWeight: 700, color: '#1e293b', letterSpacing: '0.04em' }
        }, 'Relationship Progress'),
        React.createElement('span', {
          style: { ...pillStyle, background: 'rgba(20,184,166,0.12)', color: '#14b8a6', marginLeft: 'auto' }
        }, 'ANALYTICS')
      ),

      React.createElement('div', {
        style: { display: 'flex', flexWrap: 'wrap', gap: '0.65rem' }
      },
        metricCard('\u{1F4E8}', 'Total Touches', stats ? stats.total_touchpoints : 0, '#1e293b'),
        metricCard('\u{1F465}', 'Contacts', stats ? stats.contacts_touched : 0, '#14b8a6'),
        metricCard('\u{1F3E2}', 'Groups', stats ? stats.groups_engaged : 0, '#3b82f6'),
        metricCard('\u{21A9}\uFE0F', 'Replies', stats ? stats.replies : 0, stats && stats.replies > 0 ? '#10b981' : '#94a3b8'),
        metricCard('\u{1F91D}', 'Meetings', stats ? stats.meetings : 0, stats && stats.meetings > 0 ? '#8b5cf6' : '#94a3b8'),
        metricCard('\u2705', 'Completion', dotGrid ? pctFilled + '%' : '\u2014', pctFilled >= 100 ? '#10b981' : pctFilled >= 50 ? '#14b8a6' : '#3b82f6')
      ),

      React.createElement('div', {
        style: { display: 'grid', gridTemplateColumns: '1fr auto auto', gap: '0.75rem', alignItems: 'start' }
      },
        chartCard('Activity \u2014 Last 30 Days',
          stats && stats.daily_activity && stats.daily_activity.length > 0
            ? buildAreaChart(stats.daily_activity)
            : emptyChart('Log touchpoints to see activity trends'),
          { flex: '1 1 auto' }
        ),

        chartCard('Channel Mix',
          React.createElement('div', { style: { display: 'flex', gap: '0.75rem', alignItems: 'center' }},
            stats && stats.channel_mix && stats.channel_mix.length > 0
              ? buildDonut(stats.channel_mix)
              : null,
            stats && stats.channel_mix && stats.channel_mix.length > 0
              ? donutLegend(stats.channel_mix)
              : emptyChart('No channels')
          ),
          { minWidth: '220px' }
        ),

        chartCard('Canvas Progress',
          dotGrid
            ? React.createElement('div', { style: { display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.3rem' }},
                buildRadialProgress(pctFilled),
                React.createElement('div', { style: { fontSize: '0.7rem', color: '#64748b', fontFamily: "'JetBrains Mono', monospace", textAlign: 'center' }},
                  filledDots.toLocaleString() + ' / ' + totalDots.toLocaleString() + ' dots')
              )
            : emptyChart('Load an image'),
          { minWidth: '150px' }
        )
      ),

      stats && stats.weekly_activity && stats.weekly_activity.length > 0
        ? chartCard('Weekly Activity',
            buildWeeklyBars(stats.weekly_activity),
            { width: '100%' }
          )
        : null
    )
  );
}

// ===================================================================
// COMMAND CENTER NAVIGATION — workflow-based 5-section top nav
// ===================================================================

// Top-level sections and their child routes. Section order = display order.
// Child `id` values must match the existing `activeTab` route ids so that all
// pre-existing page renderings continue to work unchanged.
const NAV_SECTIONS = [
  {
    id: 'command',
    label: 'Command Center',
    icon: '\u25C8', // ◈
    children: [
      { id: 'command', label: 'Overview' },
      { id: 'followups', label: 'Follow-ups Due' }
    ]
  },
  {
    id: 'deals',
    label: 'Prospecting',
    icon: '\u25B2', // ▲
    children: [
      { id: 'prospecting', label: 'Dashboard' },
      { id: 'search', label: 'Properties' },
      { id: 'capital_groups', label: 'Capital Groups' },
      { id: 'linkedinhub', label: 'LinkedIn Hub' },
      { id: 'dealboard', label: 'Saved Prospects' }
    ]
  },
  {
    id: 'intel',
    label: 'Market Intel',
    icon: '\u25C9', // ◉
    children: [
      { id: 'discovery', label: 'Daily Discovery' },
      { id: 'statewide', label: 'Statewide' },
      { id: 'intelligence', label: 'Sunbelt Intelligence' },
      { id: 'predictions', label: 'Predicted Devs' },
      { id: 'markets', label: 'Market Expansion' }
    ]
  },
  {
    id: 'pipeline_section',
    label: 'Pipeline',
    icon: '\u25B3', // △
    children: [
      { id: 'pipeline', label: 'My Pipeline' },
      { id: 'quoting', label: 'Quoting' },
      { id: 'underwriting', label: 'Underwriting Sheet' }
    ]
  },
  {
    id: 'admin_section',
    label: 'Admin',
    icon: '\u2699', // ⚙
    children: [{ id: 'admin', label: 'Admin' }]
  }
];

// Role-aware hiding: filter both sections and their children by role
function getNavForUser(user) {
  const role = user?.role || 'producer';
  const isSuperAdmin = !!user?.is_super_admin;

  // Per-role hidden child tab ids
  const hiddenTabs = new Set();
  if (role === 'broker') {
    ['discovery', 'statewide', 'predictions', 'markets', 'pipeline', 'followups', 'quoting', 'underwriting'].forEach(t => hiddenTabs.add(t));
  } else if (role === 'producer') {
    ['quoting', 'underwriting'].forEach(t => hiddenTabs.add(t));
  }

  // Per-role hidden sections
  const hiddenSections = new Set();
  if (!isSuperAdmin) hiddenSections.add('admin_section');
  if (role === 'broker') hiddenSections.add('pipeline_section');

  return NAV_SECTIONS
    .filter(s => !hiddenSections.has(s.id))
    .map(s => ({ ...s, children: s.children.filter(c => !hiddenTabs.has(c.id)) }))
    .filter(s => s.children.length > 0);
}

// Find which section a given tab id belongs to
function findSectionForTab(tabId, sections) {
  for (const s of sections) {
    if (s.children.some(c => c.id === tabId)) return s.id;
  }
  return sections[0]?.id || 'command';
}

// ------- TopNav: 5-section command-center navigation with CTA -------
function TopNav({ activeTab, setActiveTab, user }) {
  const sections = getNavForUser(user);
  const activeSectionId = findSectionForTab(activeTab, sections);

  const rowStyle = {
    display: 'flex',
    alignItems: 'center',
    gap: '0.4rem',
    padding: '0.5rem 0 0.85rem',
    marginBottom: '1.25rem',
    borderBottom: '1px solid rgba(226,232,240,0.5)',
    flexWrap: 'wrap'
  };
  const btnStyle = (isActive) => ({
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.5rem',
    padding: '0.6rem 1.1rem',
    background: isActive ? 'rgba(20,184,166,0.08)' : 'transparent',
    border: '1px solid ' + (isActive ? 'rgba(20,184,166,0.3)' : 'rgba(226,232,240,0.4)'),
    color: isActive ? '#34d399' : '#94a3b8',
    borderRadius: '0.75rem',
    cursor: 'pointer',
    fontFamily: "'Orbitron', sans-serif",
    fontSize: '0.82rem',
    fontWeight: 700,
    letterSpacing: '0.03em',
    transition: 'all 0.2s',
    boxShadow: isActive ? '0 2px 8px rgba(20,184,166,0.08)' : 'none'
  });

  return /*#__PURE__*/React.createElement('div', { style: rowStyle },
    sections.map(s => /*#__PURE__*/React.createElement('button', {
      key: s.id,
      style: btnStyle(s.id === activeSectionId),
      onClick: () => {
        if (s.children.length > 0) setActiveTab(s.children[0].id);
      },
      onMouseEnter: (e) => {
        if (s.id !== activeSectionId) {
          e.currentTarget.style.color = '#1e293b';
          e.currentTarget.style.borderColor = 'rgba(20,184,166,0.4)';
        }
      },
      onMouseLeave: (e) => {
        if (s.id !== activeSectionId) {
          e.currentTarget.style.color = '#94a3b8';
          e.currentTarget.style.borderColor = '#e2e8f0';
        }
      }
    },
      /*#__PURE__*/React.createElement('span', { style: { fontSize: '0.95rem', opacity: 0.85 } }, s.icon),
      s.label
    )),
    // Primary CTA — anchored on the right
    /*#__PURE__*/React.createElement('div', { style: { marginLeft: 'auto', display: 'flex', gap: '0.5rem' } },
      /*#__PURE__*/React.createElement('button', {
        style: {
          ...styles.btnPrimary,
          padding: '0.6rem 1.1rem',
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.35rem',
          boxShadow: '0 2px 8px rgba(20,184,166,0.15)'
        },
        onClick: () => setActiveTab('search')
      }, '+ Run Prospect Search')
    )
  );
}

// ------- SubNav: secondary tab strip for the active section -------
function SubNav({ activeTab, setActiveTab, user }) {
  const sections = getNavForUser(user);
  const activeSectionId = findSectionForTab(activeTab, sections);
  const section = sections.find(s => s.id === activeSectionId);
  if (!section || section.children.length <= 1) return null;

  const rowStyle = {
    display: 'flex',
    alignItems: 'center',
    gap: '0.25rem',
    marginBottom: '1.5rem',
    borderBottom: '1px solid rgba(226,232,240,0.35)',
    flexWrap: 'wrap'
  };
  const itemStyle = (isActive) => ({
    background: 'transparent',
    border: 'none',
    color: isActive ? '#34d399' : '#64748b',
    padding: '0.5rem 0.95rem',
    fontSize: '0.8rem',
    fontWeight: 600,
    cursor: 'pointer',
    borderBottom: isActive ? '2px solid #14b8a6' : '2px solid transparent',
    marginBottom: '-1px',
    fontFamily: "'Inter', sans-serif",
    letterSpacing: '0.01em',
    transition: 'color 0.2s, border-color 0.2s'
  });

  // Breadcrumb pill
  const crumbStyle = {
    fontFamily: "'Orbitron', sans-serif",
    fontSize: '0.68rem',
    color: '#64748b',
    textTransform: 'uppercase',
    letterSpacing: '0.12em',
    padding: '0.25rem 0.7rem 0.25rem 0',
    borderRight: '1px solid rgba(226,232,240,0.4)',
    marginRight: '0.5rem'
  };

  return /*#__PURE__*/React.createElement('div', { style: rowStyle },
    /*#__PURE__*/React.createElement('span', { style: crumbStyle }, section.label),
    section.children.map(c => /*#__PURE__*/React.createElement('button', {
      key: c.id,
      style: itemStyle(c.id === activeTab),
      onClick: () => setActiveTab(c.id),
      onMouseEnter: (e) => {
        if (c.id !== activeTab) e.currentTarget.style.color = '#1e293b';
      },
      onMouseLeave: (e) => {
        if (c.id !== activeTab) e.currentTarget.style.color = '#64748b';
      }
    }, c.label))
  );
}

// ------- Command Center landing page -------
function CommandCenter({ user, prospects, setActiveTab }) {
  const [dueLeads, setDueLeads] = useState([]);
  const [dueLoading, setDueLoading] = useState(true);
  const [clockTime, setClockTime] = useState(new Date());
  const [weather, setWeather] = useState(null);

  useEffect(() => {
    let cancelled = false;
    fetch(`${API_BASE}/api/crm/leads?due=1`)
      .then(r => r.json())
      .then(d => {
        if (cancelled) return;
        if (d && d.success) setDueLeads(Array.isArray(d.leads) ? d.leads : []);
      })
      .catch(() => {})
      .finally(() => { if (!cancelled) setDueLoading(false); });

    fetch(API_BASE + '/api/dashboard/weather')
      .then(function(r) { return r.ok ? r.json() : null; })
      .then(function(d) { if (!cancelled && d && !d.error) setWeather(d); })
      .catch(function() {});

    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    var tick = setInterval(function() { setClockTime(new Date()); }, 60000);
    return function() { clearInterval(tick); };
  }, []);

  const total = (prospects || []).length;
  const hot = (prospects || []).filter(p => (p.score || 0) >= 80).length;
  const withLinkedIn = (prospects || []).filter(p => validLinkedIn(p.linkedin)).length;
  const dueCount = dueLeads.length;

  const greeting = (() => {
    const h = new Date().getHours();
    if (h < 12) return 'Good morning';
    if (h < 18) return 'Good afternoon';
    return 'Good evening';
  })();
  const firstName = user?.name ? String(user.name).split(' ')[0] : '';

  var alerts = [
    { color: '#10b981', bg: 'rgba(16,185,129,0.06)', border: 'rgba(16,185,129,0.18)', icon: '\u{1F4CB}', label: 'PERMITS', text: 'Permit surge detected \u2014 Phoenix metro' },
    { color: '#8b5cf6', bg: 'rgba(139,92,246,0.06)', border: 'rgba(139,92,246,0.18)', icon: '\u{1F4B0}', label: 'CAPITAL', text: 'Capital raise detected \u2014 Tampa' },
    { color: '#f59e0b', bg: 'rgba(245,158,11,0.06)', border: 'rgba(245,158,11,0.18)', icon: '\u26A0\uFE0F', label: 'ZONING', text: 'Zoning change alert \u2014 Charlotte' },
    { color: '#3b82f6', bg: 'rgba(59,130,246,0.06)', border: 'rgba(59,130,246,0.18)', icon: '\u{1F3D7}\uFE0F', label: 'BUILD', text: 'Construction start signal \u2014 Austin' }
  ];

  var role = user?.role || 'producer';
  var quickActions = [
    { id: 'search', label: 'Run Prospect Search', icon: '\u{1F50D}', roles: ['broker', 'producer', 'admin'] },
    { id: 'discovery', label: 'Daily Discovery', icon: '\u{1F4E1}', roles: ['producer', 'admin'] },
    { id: 'intelligence', label: 'Sunbelt Intelligence', icon: '\u{1F4CA}', roles: ['broker', 'producer', 'admin'] },
    { id: 'pipeline', label: 'Open Pipeline', icon: '\u{1F4C8}', roles: ['producer', 'admin'] },
    { id: 'followups', label: 'Follow-ups Due', icon: '\u23F0', roles: ['producer', 'admin'] },
    { id: 'linkedinhub', label: 'LinkedIn Hub', icon: '\u{1F517}', roles: ['broker', 'producer', 'admin'] },
    { id: 'dealboard', label: 'Saved Prospects', icon: '\u2B50', roles: ['broker', 'producer', 'admin'] }
  ].filter(function(a) { return a.roles.includes(role); });

  var sectionCard = {
    background: '#FFFFFF',
    border: '1px solid #e2e8f0',
    borderRadius: '0.85rem',
    padding: '1.25rem',
    boxShadow: '0 1px 3px rgba(0,0,0,0.04), 0 1px 2px rgba(0,0,0,0.03)'
  };
  var panelHeader = {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '0.85rem'
  };
  var panelTitle = {
    fontFamily: "'Orbitron', sans-serif",
    fontSize: '0.85rem',
    color: '#1e293b',
    margin: 0,
    letterSpacing: '0.03em',
    fontWeight: 700
  };

  var hotPct = total > 0 ? Math.round((hot / total) * 100) : 0;
  var liPct = total > 0 ? Math.round((withLinkedIn / total) * 100) : 0;

  var kpiCard = function(icon, label, value, accent, sub) {
    return React.createElement('div', {
      style: {
        background: '#FFFFFF', border: '1px solid #e2e8f0', borderRadius: '0.85rem',
        padding: '1.15rem 1.25rem', boxShadow: '0 1px 3px rgba(0,0,0,0.04)',
        display: 'flex', flexDirection: 'column', gap: '0.15rem', position: 'relative', overflow: 'hidden'
      }
    },
      React.createElement('div', { style: { position: 'absolute', top: 0, left: 0, right: 0, height: '3px', background: accent, opacity: 0.5, borderRadius: '0.85rem 0.85rem 0 0' } }),
      React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.15rem' } },
        React.createElement('span', { style: { fontSize: '0.85rem', opacity: 0.7 } }, icon),
        React.createElement('span', {
          style: { fontSize: '0.68rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }
        }, label)
      ),
      React.createElement('div', {
        style: { fontFamily: "'JetBrains Mono', monospace", fontSize: '1.75rem', fontWeight: 700, color: '#1e293b', lineHeight: 1.2 }
      }, String(value)),
      sub ? React.createElement('div', { style: { fontSize: '0.72rem', color: '#94a3b8', marginTop: '0.1rem' } }, sub) : null
    );
  };

  var fmtTime = clockTime.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true });
  var fmtDay = clockTime.toLocaleDateString('en-US', { weekday: 'long', month: 'short', day: 'numeric' });

  var miniBar = function(pct, color) {
    return React.createElement('div', { style: { width: '100%', height: '4px', background: '#f1f5f9', borderRadius: '2px', marginTop: '0.35rem', overflow: 'hidden' } },
      React.createElement('div', { style: { width: Math.min(100, pct) + '%', height: '100%', background: color, borderRadius: '2px', transition: 'width 0.4s' } })
    );
  };

  return React.createElement('div', null,
    React.createElement('div', {
      style: {
        display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
        gap: '1rem', marginBottom: '1.75rem', flexWrap: 'wrap'
      }
    },
      React.createElement('div', null,
        React.createElement('h2', {
          style: {
            fontFamily: "'Orbitron', sans-serif", fontSize: '1.8rem', fontWeight: 900, margin: 0,
            background: 'linear-gradient(135deg, #14b8a6 0%, #3b82f6 100%)',
            WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', letterSpacing: '0.03em'
          }
        }, 'Command Center'),
        React.createElement('p', {
          style: { color: '#64748b', margin: '0.35rem 0 0', fontSize: '0.9rem' }
        }, greeting + (firstName ? ', ' + firstName : '') + '. Here\u2019s where your day starts.')
      ),

      React.createElement('div', {
        style: {
          display: 'flex', alignItems: 'center', gap: '1rem',
          background: '#FFFFFF', border: '1px solid #e2e8f0', borderRadius: '0.75rem',
          padding: '0.6rem 1rem', boxShadow: '0 1px 3px rgba(0,0,0,0.04)'
        }
      },
        React.createElement('div', { style: { textAlign: 'right' } },
          React.createElement('div', {
            style: { fontFamily: "'JetBrains Mono', monospace", fontSize: '1.05rem', fontWeight: 600, color: '#1e293b', lineHeight: 1.2 }
          }, fmtTime),
          React.createElement('div', {
            style: { fontSize: '0.72rem', color: '#94a3b8', marginTop: '0.1rem' }
          }, fmtDay)
        ),
        React.createElement('div', {
          style: { width: '1px', height: '28px', background: '#e2e8f0' }
        }),
        weather
          ? React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '0.5rem' } },
              weather.icon
                ? React.createElement('img', {
                    src: weather.icon.startsWith('//') ? 'https:' + weather.icon : weather.icon,
                    alt: weather.condition || '',
                    style: { width: '28px', height: '28px' }
                  })
                : null,
              React.createElement('div', null,
                React.createElement('div', {
                  style: { fontSize: '0.82rem', fontWeight: 600, color: '#1e293b', lineHeight: 1.2 }
                }, weather.location + (weather.temp != null ? ' \u00b7 ' + Math.round(weather.temp) + '\u00b0F' : '')),
                React.createElement('div', {
                  style: { fontSize: '0.68rem', color: '#94a3b8' }
                }, weather.condition || '')
              )
            )
          : React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '0.4rem' } },
              React.createElement('span', { style: { fontSize: '0.85rem', opacity: 0.4 } }, '\u2600\uFE0F'),
              React.createElement('span', { style: { fontSize: '0.72rem', color: '#cbd5e1' } }, 'Loading weather\u2026')
            )
      )
    ),

    React.createElement('div', {
      style: {
        display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
        gap: '0.85rem', marginBottom: '1.5rem'
      }
    },
      kpiCard('\u{1F3AF}', 'Total Prospects', total, '#14b8a6', total > 0 ? 'in your database' : null),
      kpiCard('\u{1F525}', 'Hot Leads', hot, '#ef4444', hot > 0 ? hotPct + '% of total' : null),
      kpiCard('\u{1F4CB}', 'Follow-ups Due', dueCount, dueCount > 0 ? '#f59e0b' : '#94a3b8', dueCount > 0 ? 'action needed' : 'all clear'),
      kpiCard('\u{1F517}', 'LinkedIn', withLinkedIn, '#3b82f6', withLinkedIn > 0 ? liPct + '% coverage' : null)
    ),

    total > 0 ? React.createElement('div', {
      style: {
        display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
        gap: '0.85rem', marginBottom: '1.5rem'
      }
    },
      React.createElement('div', { style: { ...sectionCard, padding: '0.85rem 1rem' } },
        React.createElement('div', { style: { fontSize: '0.68rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600, marginBottom: '0.4rem' } }, 'Hot Lead Rate'),
        miniBar(hotPct, '#ef4444'),
        React.createElement('div', { style: { fontSize: '0.72rem', color: '#64748b', marginTop: '0.25rem', fontFamily: "'JetBrains Mono', monospace" } }, hotPct + '%')
      ),
      React.createElement('div', { style: { ...sectionCard, padding: '0.85rem 1rem' } },
        React.createElement('div', { style: { fontSize: '0.68rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600, marginBottom: '0.4rem' } }, 'LinkedIn Coverage'),
        miniBar(liPct, '#3b82f6'),
        React.createElement('div', { style: { fontSize: '0.72rem', color: '#64748b', marginTop: '0.25rem', fontFamily: "'JetBrains Mono', monospace" } }, liPct + '%')
      ),
      React.createElement('div', { style: { ...sectionCard, padding: '0.85rem 1rem' } },
        React.createElement('div', { style: { fontSize: '0.68rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600, marginBottom: '0.4rem' } }, 'Follow-up Rate'),
        miniBar(total > 0 ? Math.round((dueCount / total) * 100) : 0, '#f59e0b'),
        React.createElement('div', { style: { fontSize: '0.72rem', color: '#64748b', marginTop: '0.25rem', fontFamily: "'JetBrains Mono', monospace" } },
          (total > 0 ? Math.round((dueCount / total) * 100) : 0) + '%')
      ),
      React.createElement('div', { style: { ...sectionCard, padding: '0.85rem 1rem' } },
        React.createElement('div', { style: { fontSize: '0.68rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600, marginBottom: '0.4rem' } }, 'Database Health'),
        miniBar(Math.min(100, Math.round(((hot + withLinkedIn) / Math.max(1, total * 2)) * 100)), '#14b8a6'),
        React.createElement('div', { style: { fontSize: '0.72rem', color: '#64748b', marginTop: '0.25rem', fontFamily: "'JetBrains Mono', monospace" } },
          Math.min(100, Math.round(((hot + withLinkedIn) / Math.max(1, total * 2)) * 100)) + '%')
      )
    ) : null,

    React.createElement('div', {
      style: {
        display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))',
        gap: '1rem', marginBottom: '1.25rem'
      }
    },
      React.createElement('div', { style: sectionCard },
        React.createElement('div', { style: panelHeader },
          React.createElement('h3', { style: panelTitle }, 'Key Signals & Alerts'),
          React.createElement('button', {
            style: { ...styles.actionBtn, fontSize: '0.7rem' },
            onClick: function() { setActiveTab('intelligence'); }
          }, 'View all \u2192')
        ),
        React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.5rem' } },
          alerts.map(function(a, i) {
            return React.createElement('div', {
              key: i,
              style: {
                display: 'flex', alignItems: 'center', gap: '0.65rem',
                padding: '0.65rem 0.85rem', background: a.bg,
                border: '1px solid ' + a.border, borderRadius: '0.5rem',
                transition: 'box-shadow 0.15s',
                cursor: 'pointer'
              }
            },
              React.createElement('span', { style: { fontSize: '0.9rem', flexShrink: 0 } }, a.icon),
              React.createElement('div', { style: { flex: 1, minWidth: 0 } },
                React.createElement('div', {
                  style: { fontSize: '0.65rem', fontWeight: 700, color: a.color, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '0.1rem' }
                }, a.label),
                React.createElement('div', {
                  style: { fontSize: '0.82rem', color: '#334155', fontWeight: 500, lineHeight: 1.35 }
                }, a.text)
              ),
              React.createElement('div', {
                style: { width: '6px', height: '6px', borderRadius: '50%', background: a.color, flexShrink: 0, boxShadow: '0 0 6px ' + a.color }
              })
            );
          })
        )
      ),

      React.createElement('div', { style: sectionCard },
        React.createElement('div', { style: panelHeader },
          React.createElement('h3', { style: panelTitle }, 'Follow-ups Due (' + dueCount + ')'),
          React.createElement('button', {
            style: { ...styles.actionBtn, fontSize: '0.7rem' },
            onClick: function() { setActiveTab('followups'); }
          }, 'Open \u2192')
        ),
        dueLoading
          ? React.createElement('div', {
              style: { color: '#94a3b8', fontSize: '0.85rem', padding: '1.5rem 0', textAlign: 'center' }
            },
              React.createElement('div', { style: { fontSize: '1.2rem', marginBottom: '0.35rem', opacity: 0.4 } }, '\u23F3'),
              'Loading\u2026'
            )
          : dueLeads.length === 0
            ? React.createElement('div', {
                style: { textAlign: 'center', padding: '1.5rem 0' }
              },
                React.createElement('div', { style: { fontSize: '1.5rem', marginBottom: '0.4rem', opacity: 0.3 } }, '\u2705'),
                React.createElement('div', { style: { fontSize: '0.85rem', fontWeight: 600, color: '#10b981', marginBottom: '0.15rem' } }, 'All caught up'),
                React.createElement('div', { style: { fontSize: '0.75rem', color: '#94a3b8' } }, 'No follow-ups overdue right now')
              )
            : React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '0.4rem' } },
                dueLeads.slice(0, 5).map(function(l) {
                  return React.createElement('div', {
                    key: l.id,
                    style: {
                      display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                      gap: '0.6rem', padding: '0.55rem 0.8rem',
                      background: '#F7F9FC', border: '1px solid #e2e8f0',
                      borderRadius: '0.5rem', fontSize: '0.82rem',
                      cursor: 'pointer', transition: 'background 0.15s'
                    },
                    onClick: function() { setActiveTab('followups'); }
                  },
                    React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '0.5rem', minWidth: 0 } },
                      React.createElement('div', {
                        style: { width: '6px', height: '6px', borderRadius: '50%', background: '#f59e0b', flexShrink: 0 }
                      }),
                      React.createElement('span', { style: { color: '#1e293b', fontWeight: 600 } }, l.company_name || '\u2014')
                    ),
                    React.createElement('span', {
                      style: { fontSize: '0.7rem', color: '#94a3b8', padding: '0.1rem 0.45rem', background: '#f1f5f9', borderRadius: '0.25rem', flexShrink: 0 }
                    }, l.status || 'due')
                  );
                }),
                dueCount > 5 ? React.createElement('div', {
                  style: { textAlign: 'center', fontSize: '0.72rem', color: '#94a3b8', padding: '0.25rem 0', cursor: 'pointer' },
                  onClick: function() { setActiveTab('followups'); }
                }, '+' + (dueCount - 5) + ' more') : null
              )
      )
    ),

    React.createElement('div', { style: sectionCard },
      React.createElement('h3', { style: { ...panelTitle, marginBottom: '0.85rem' } }, 'Quick Actions'),
      React.createElement('div', { style: { display: 'flex', gap: '0.5rem', flexWrap: 'wrap' } },
        quickActions.map(function(a) {
          return React.createElement('button', {
            key: a.id,
            className: 'action-btn',
            style: {
              display: 'inline-flex', alignItems: 'center', gap: '0.4rem',
              padding: '0.5rem 0.9rem', fontSize: '0.78rem', fontWeight: 500,
              color: '#475569', background: '#FFFFFF', border: '1px solid #e2e8f0',
              borderRadius: '0.5rem', cursor: 'pointer', transition: 'all 0.15s',
              fontFamily: "'Inter', sans-serif"
            },
            onClick: function() { setActiveTab(a.id); }
          },
            React.createElement('span', { style: { fontSize: '0.85rem' } }, a.icon),
            a.label
          );
        })
      )
    )
  );
}

// ===================================================================
// COMMAND PALETTE (Cmd+K / Ctrl+K)
// ===================================================================
function CommandPalette({
  activeTab,
  setActiveTab,
  user,
  prospects
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef(null);
  const resultsRef = useRef(null);
  const debounceRef = useRef(null);
  const [debouncedQuery, setDebouncedQuery] = useState('');

  // Global Cmd+K / Ctrl+K listener
  useEffect(() => {
    const handler = e => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setOpen(prev => !prev);
        setQuery('');
        setDebouncedQuery('');
        setSelectedIndex(0);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // Focus input when opened
  useEffect(() => {
    if (open && inputRef.current) inputRef.current.focus();
  }, [open]);

  // Debounce search at 120ms
  useEffect(() => {
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => setDebouncedQuery(query), 120);
    return () => clearTimeout(debounceRef.current);
  }, [query]);

  // Build searchable items
  const allItems = React.useMemo(() => {
    const items = [];
    const role = user?.role || 'producer';

    // Pages
    const pages = [{
      id: 'search',
      label: 'Prospect Search'
    }, {
      id: 'discovery',
      label: 'Daily Discovery'
    }, {
      id: 'statewide',
      label: 'Statewide'
    }, {
      id: 'intelligence',
      label: 'Sunbelt Intelligence'
    }, {
      id: 'predictions',
      label: 'Predicted Devs'
    }, {
      id: 'markets',
      label: 'Market Expansion'
    }, {
      id: 'feed',
      label: 'Live Intelligence Feed'
    }, {
      id: 'pipeline',
      label: 'My Pipeline'
    }, {
      id: 'followups',
      label: 'Follow-ups Due'
    }];
    if (role === 'admin') {
      pages.push({
        id: 'quoting',
        label: 'Quoting'
      });
      pages.push({
        id: 'underwriting',
        label: 'Underwriting Sheet'
      });
    }
    if (user && user.is_super_admin) {
      pages.push({
        id: 'admin',
        label: 'Admin'
      });
    }
    // Filter pages by role for brokers
    const brokerHidden = ['discovery', 'pipeline', 'followups', 'statewide', 'predictions', 'markets'];
    pages.forEach(p => {
      if (role === 'broker' && brokerHidden.includes(p.id)) return;
      items.push({
        ...p,
        category: 'pages',
        icon: '\uD83D\uDCC4'
      });
    });

    // Developers (from loaded prospects)
    const devSet = new Set();
    (prospects || []).forEach(p => {
      if (p.company && !devSet.has(p.company)) {
        devSet.add(p.company);
        items.push({
          id: 'dev-' + p.company,
          label: p.company,
          category: 'developers',
          icon: '\uD83C\uDFD7',
          tabId: 'search'
        });
      }
    });

    // Cities / Markets (from loaded prospects)
    const citySet = new Set();
    (prospects || []).forEach(p => {
      const city = p.city && p.state ? p.city + ', ' + p.state : p.city || '';
      if (city && !citySet.has(city)) {
        citySet.add(city);
        items.push({
          id: 'city-' + city,
          label: city,
          category: 'cities',
          icon: '\uD83C\uDF06',
          tabId: 'markets'
        });
      }
    });

    // Static seed data for Projects, Parcels, Signals when no live data
    const staticProjects = ['Greenville BTR Project', 'Austin Townhome Development', 'Phoenix Mesa BTR', 'Charlotte SFR Expansion', 'Dallas Fort Worth BTR Portfolio'];
    staticProjects.forEach(name => {
      items.push({
        id: 'proj-' + name,
        label: name,
        category: 'projects',
        icon: '\uD83D\uDCCD',
        tabId: 'predictions'
      });
    });
    const staticParcels = ['APN 301-42-109 (Mesa, AZ)', 'APN 127-08-055 (Charlotte, NC)', 'APN 442-19-320 (Dallas, TX)', 'APN 085-33-210 (Phoenix, AZ)'];
    staticParcels.forEach(name => {
      items.push({
        id: 'parcel-' + name,
        label: name,
        category: 'parcels',
        icon: '\uD83D\uDCD0',
        tabId: 'statewide'
      });
    });
    const staticSignals = ['Permit surge detected — Phoenix', 'Land acquisition cluster — Dallas', 'Zoning change alert — Charlotte', 'Construction start signal — Austin', 'Capital raise detected — Tampa'];
    staticSignals.forEach(name => {
      items.push({
        id: 'sig-' + name,
        label: name,
        category: 'signals',
        icon: '\uD83D\uDCE1',
        tabId: 'intelligence'
      });
    });

    // Tools (quick actions)
    const tools = [{
      id: 'tool-create-prospect',
      label: 'Create Prospect',
      tabId: 'search'
    }, {
      id: 'tool-open-pipeline',
      label: 'Open Pipeline',
      tabId: 'pipeline'
    }, {
      id: 'tool-run-discovery',
      label: 'Run Discovery Scan',
      tabId: 'discovery'
    }, {
      id: 'tool-intel-brief',
      label: 'Generate Intelligence Brief',
      tabId: 'intelligence'
    }];
    tools.forEach(t => {
      items.push({
        ...t,
        category: 'tools',
        icon: '\u26A1'
      });
    });
    return items;
  }, [prospects, user]);

  // Filter results
  const q = debouncedQuery.toLowerCase();
  const filtered = q ? allItems.filter(item => item.label.toLowerCase().includes(q)) : allItems.slice(0, 20);

  // Group by category (maintain order)
  const categoryOrder = ['pages', 'developers', 'cities', 'projects', 'parcels', 'signals', 'tools'];
  const categoryLabels = {
    pages: 'Pages',
    developers: 'Developers',
    cities: 'Cities / Markets',
    projects: 'Projects',
    parcels: 'Parcels',
    signals: 'Signals',
    tools: 'Tools'
  };
  const grouped = {};
  categoryOrder.forEach(cat => {
    const items = filtered.filter(i => i.category === cat);
    if (items.length > 0) grouped[cat] = items;
  });
  const flatResults = categoryOrder.reduce((acc, cat) => acc.concat(grouped[cat] || []), []);

  // Scroll selected into view
  useEffect(() => {
    if (resultsRef.current) {
      const el = resultsRef.current.querySelector('[data-selected="true"]');
      if (el) el.scrollIntoView({
        block: 'nearest'
      });
    }
  }, [selectedIndex]);

  // Keyboard navigation
  const handleKeyDown = e => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex(i => Math.min(i + 1, flatResults.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex(i => Math.max(i - 1, 0));
    } else if (e.key === 'Enter' && flatResults[selectedIndex]) {
      e.preventDefault();
      const item = flatResults[selectedIndex];
      setActiveTab(item.tabId || item.id);
      setOpen(false);
    } else if (e.key === 'Escape') {
      setOpen(false);
    }
  };
  if (!open) return null;
  const kbdStyle = {
    background: 'rgba(255,255,255,0.06)',
    border: '1px solid rgba(255,255,255,0.08)',
    borderRadius: '4px',
    padding: '0.1rem 0.35rem',
    fontSize: '0.65rem',
    color: '#64748b',
    fontFamily: 'monospace'
  };
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: 'rgba(0,0,0,0.25)',
      backdropFilter: 'blur(4px)',
      WebkitBackdropFilter: 'blur(4px)',
      display: 'flex',
      alignItems: 'flex-start',
      justifyContent: 'center',
      paddingTop: '15vh',
      zIndex: 9999,
      animation: 'cmdPaletteOverlayIn 180ms ease-out forwards'
    },
    onClick: () => setOpen(false),
    role: "dialog",
    "aria-modal": "true",
    "aria-label": "Command palette"
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: 'rgba(15,22,36,0.95)',
      backdropFilter: 'blur(16px)',
      WebkitBackdropFilter: 'blur(16px)',
      border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: '12px',
      boxShadow: '0 30px 80px rgba(0,0,0,0.12)',
      width: '720px',
      maxWidth: '92vw',
      maxHeight: '70vh',
      display: 'flex',
      flexDirection: 'column',
      animation: 'cmdPaletteIn 180ms ease-out forwards',
      overflow: 'hidden'
    },
    onClick: e => e.stopPropagation(),
    onKeyDown: handleKeyDown
  }, /*#__PURE__*/React.createElement("input", {
    ref: inputRef,
    type: "text",
    value: query,
    onChange: e => {
      setQuery(e.target.value);
      setSelectedIndex(0);
    },
    placeholder: "Search developers, markets, parcels, tools\\u2026",
    style: {
      background: 'transparent',
      border: 'none',
      borderBottom: '1px solid rgba(255,255,255,0.06)',
      color: '#0f172a',
      padding: '1rem 1.25rem',
      fontSize: '1.05rem',
      fontFamily: "'Inter', sans-serif",
      outline: 'none',
      width: '100%'
    },
    "aria-label": "Search command palette"
  }), /*#__PURE__*/React.createElement("div", {
    ref: resultsRef,
    style: {
      overflowY: 'auto',
      padding: '0.5rem 0',
      flex: 1
    },
    role: "listbox"
  }, categoryOrder.map(cat => {
    const items = grouped[cat];
    if (!items) return null;
    return /*#__PURE__*/React.createElement("div", {
      key: cat
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        padding: '0.5rem 1.25rem 0.25rem',
        fontSize: '0.65rem',
        color: '#64748b',
        textTransform: 'uppercase',
        letterSpacing: '0.1em',
        fontWeight: 700,
        fontFamily: "'Orbitron', sans-serif"
      }
    }, items[0].icon, " ", categoryLabels[cat]), items.map(item => {
      const idx = flatResults.indexOf(item);
      const isSelected = idx === selectedIndex;
      return /*#__PURE__*/React.createElement("button", {
        key: item.id,
        role: "option",
        "aria-selected": isSelected,
        "data-selected": isSelected,
        style: {
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem',
          padding: '0.55rem 1.25rem',
          cursor: 'pointer',
          fontSize: '0.9rem',
          color: isSelected ? '#00FFC6' : '#cbd5e1',
          fontFamily: "'Inter', sans-serif",
          transition: 'background 0.1s, color 0.1s',
          border: 'none',
          width: '100%',
          textAlign: 'left',
          background: isSelected ? 'rgba(0,255,180,0.08)' : 'transparent'
        },
        onClick: () => {
          setActiveTab(item.tabId || item.id);
          setOpen(false);
        },
        onMouseEnter: () => setSelectedIndex(idx)
      }, item.label);
    }));
  }), flatResults.length === 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '2rem',
      textAlign: 'center',
      color: '#94a3b8',
      fontSize: '0.9rem'
    }
  }, "No results found")), /*#__PURE__*/React.createElement("div", {
    style: {
      borderTop: '1px solid rgba(255,255,255,0.06)',
      padding: '0.5rem 1.25rem',
      display: 'flex',
      gap: '1rem',
      fontSize: '0.7rem',
      color: '#94a3b8',
      fontFamily: "'Inter', sans-serif"
    }
  }, /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("span", {
    style: kbdStyle
  }, "\\u2191\\u2193"), " navigate"), /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("span", {
    style: kbdStyle
  }, "Enter"), " select"), /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("span", {
    style: kbdStyle
  }, "Esc"), " close"))));
}

// ===================================================================
// LIVE INTELLIGENCE FEED
// ===================================================================
const FEED_EVENT_COLORS = {
  SIGNAL: {
    accent: '#3b82f6',
    bg: 'rgba(6,182,212,0.08)',
    border: 'rgba(6,182,212,0.2)'
  },
  PERMIT: {
    accent: '#3b82f6',
    bg: 'rgba(59,130,246,0.08)',
    border: 'rgba(59,130,246,0.2)'
  },
  PATTERN: {
    accent: '#a78bfa',
    bg: 'rgba(167,139,250,0.08)',
    border: 'rgba(167,139,250,0.2)'
  },
  DEVELOPER_EXPANSION: {
    accent: '#34d399',
    bg: 'rgba(20,184,166,0.08)',
    border: 'rgba(20,184,166,0.2)'
  },
  CONTRACTOR_ACTIVITY: {
    accent: '#f97316',
    bg: 'rgba(249,115,22,0.08)',
    border: 'rgba(249,115,22,0.2)'
  },
  PARCEL_ALERT: {
    accent: '#facc15',
    bg: 'rgba(250,204,21,0.08)',
    border: 'rgba(250,204,21,0.2)'
  },
  DEVELOPER_INTENT: {
    accent: '#a855f7',
    bg: 'rgba(168,85,247,0.08)',
    border: 'rgba(168,85,247,0.2)'
  },
  CAPITAL_FLOW: {
    accent: '#eab308',
    bg: 'rgba(234,179,8,0.08)',
    border: 'rgba(234,179,8,0.2)'
  },
  SIGNAL_QUALITY: {
    accent: '#06b6d4',
    bg: 'rgba(6,182,212,0.08)',
    border: 'rgba(6,182,212,0.2)'
  },
  PLANNING_SIGNAL: {
    accent: '#3b82f6',
    bg: 'rgba(59,130,246,0.08)',
    border: 'rgba(59,130,246,0.2)'
  },
  PERMIT_SIGNAL: {
    accent: '#22c55e',
    bg: 'rgba(34,197,94,0.08)',
    border: 'rgba(34,197,94,0.2)'
  },
  LAND_TRANSACTION: {
    accent: '#ef4444',
    bg: 'rgba(239,68,68,0.08)',
    border: 'rgba(239,68,68,0.2)'
  },
  PLAT_FILING: {
    accent: '#a855f7',
    bg: 'rgba(168,85,247,0.08)',
    border: 'rgba(168,85,247,0.2)'
  },
  CONSTRUCTION_FINANCING: {
    accent: '#eab308',
    bg: 'rgba(234,179,8,0.08)',
    border: 'rgba(234,179,8,0.2)'
  }
};
const FEED_EVENT_LABELS = {
  SIGNAL: 'SIGNAL',
  PERMIT: 'PERMIT',
  PATTERN: 'PATTERN',
  DEVELOPER_EXPANSION: 'EXPANSION',
  CONTRACTOR_ACTIVITY: 'CONTRACTOR',
  PARCEL_ALERT: 'PARCEL',
  DEVELOPER_INTENT: 'INTENT',
  CAPITAL_FLOW: 'CAPITAL',
  SIGNAL_QUALITY: 'QUALITY',
  PLANNING_SIGNAL: 'PLANNING',
  PERMIT_SIGNAL: 'PERMIT',
  LAND_TRANSACTION: 'LAND',
  PLAT_FILING: 'PLAT',
  CONSTRUCTION_FINANCING: 'FINANCING'
};
function FeedEventCard({
  event,
  isNew
}) {
  const colors = FEED_EVENT_COLORS[event.event_type] || FEED_EVENT_COLORS.SIGNAL;
  const label = FEED_EVENT_LABELS[event.event_type] || event.event_type;
  return /*#__PURE__*/React.createElement("div", {
    style: {
      background: 'rgba(15,22,36,0.95)',
      border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: '8px',
      padding: '12px 16px',
      marginBottom: '8px',
      borderLeft: '3px solid ' + colors.accent,
      animation: isNew ? 'feedSlideIn 200ms ease-out' : 'none'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '4px'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '8px'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      background: colors.bg,
      border: '1px solid ' + colors.border,
      borderRadius: '4px',
      padding: '2px 8px',
      fontSize: '0.6rem',
      fontWeight: 700,
      color: colors.accent,
      fontFamily: "'Orbitron', sans-serif",
      textTransform: 'uppercase',
      letterSpacing: '0.05em'
    }
  }, label), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.95rem',
      fontWeight: 600,
      color: '#0f172a',
      fontFamily: "'Inter', sans-serif"
    }
  }, event.title)), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.7rem',
      color: '#94a3b8',
      fontFamily: "'Inter', sans-serif",
      whiteSpace: 'nowrap'
    }
  }, timeAgo(event.created_at))), event.description && /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '0.82rem',
      color: '#64748b',
      fontFamily: "'Inter', sans-serif",
      marginTop: '2px'
    }
  }, event.description), (event.city || event.related_entity) && /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '12px',
      marginTop: '6px',
      fontSize: '0.72rem',
      color: '#64748b'
    }
  }, event.city && /*#__PURE__*/React.createElement("span", null, event.city, event.state ? ', ' + event.state : ''), event.related_entity && /*#__PURE__*/React.createElement("span", null, event.related_entity)));
}

// ===================================================================
// CAPITAL FLOW PANEL
// ===================================================================
// ===================================================================
// SIGNAL INTELLIGENCE PANEL
// ===================================================================
function SignalIntelligencePanel() {
  const e = React.createElement;
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activePanel, setActivePanel] = useState('sources');
  const fetchData = useCallback(async () => {
    try {
      const res = await fetch('/api/signal-intelligence?limit=20');
      const json = await res.json();
      if (json.success) setData(json);
    } catch (e) {
      console.error('[SignalIntelligence]', e);
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    fetchData();
    const iv = setInterval(fetchData, 60000);
    return () => clearInterval(iv);
  }, [fetchData]);
  function accColor(pct) {
    return pct >= 70 ? '#34d399' : pct >= 50 ? '#facc15' : pct >= 30 ? '#f97316' : '#ef4444';
  }
  function prioColor(s) {
    return s > 0.7 ? '#34d399' : s >= 0.4 ? '#facc15' : '#64748b';
  }
  if (loading && !data) return e('div', {
    style: {
      textAlign: 'center',
      padding: '3rem',
      color: '#14b8a6',
      fontFamily: "'Orbitron', sans-serif"
    }
  }, 'LOADING SIGNAL INTELLIGENCE...');
  if (!data) return e('div', {
    style: {
      textAlign: 'center',
      padding: '3rem',
      color: '#64748b'
    }
  }, 'No signal intelligence data available yet.');
  const {
    top_sources,
    type_rankings,
    city_rankings,
    priority_index,
    stats
  } = data;
  const panels = [{
    key: 'sources',
    label: 'TOP SOURCES'
  }, {
    key: 'types',
    label: 'SIGNAL TYPES'
  }, {
    key: 'cities',
    label: 'CITIES'
  }, {
    key: 'priority',
    label: 'PRIORITY INDEX'
  }];
  return e('div', {
    style: {
      maxWidth: '1000px',
      margin: '0 auto'
    }
  },
  // Header
  e('div', {
    style: {
      marginBottom: '1.5rem'
    }
  }, e('h2', {
    style: {
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '1.3rem',
      fontWeight: 900,
      background: 'linear-gradient(135deg, #a78bfa 0%, #3b82f6 100%)',
      WebkitBackgroundClip: 'text',
      WebkitTextFillColor: 'transparent',
      margin: 0
    }
  }, 'SIGNAL INTELLIGENCE'), e('p', {
    style: {
      color: '#64748b',
      fontSize: '0.8rem',
      margin: '0.25rem 0 0'
    }
  }, 'Signal quality rankings and source accuracy analytics')),
  // Stats row
  e('div', {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
      gap: '12px',
      marginBottom: '1.5rem'
    }
  }, [{
    label: 'TRACKED SOURCES',
    value: stats.total_sources
  }, {
    label: 'AVG ACCURACY',
    value: stats.avg_accuracy_pct + '%',
    color: accColor(stats.avg_accuracy_pct)
  }, {
    label: 'SIGNALS TRACKED',
    value: stats.total_signals_tracked
  }, {
    label: 'CONFIRMED',
    value: stats.total_confirmed,
    color: '#14b8a6'
  }].map(c => e('div', {
    key: c.label,
    style: {
      background: 'rgba(15,22,36,0.95)',
      border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: '8px',
      padding: '14px 16px',
      textAlign: 'center'
    }
  }, e('div', {
    style: {
      fontSize: '0.6rem',
      color: '#64748b',
      fontFamily: "'Orbitron', sans-serif",
      marginBottom: '6px',
      letterSpacing: '0.05em'
    }
  }, c.label), e('div', {
    style: {
      fontSize: '1.4rem',
      fontWeight: 700,
      color: c.color || '#f1f5f9',
      fontFamily: "'Orbitron', sans-serif"
    }
  }, c.value)))),
  // Tab bar
  e('div', {
    style: {
      display: 'flex',
      gap: '0.35rem',
      marginBottom: '1rem',
      flexWrap: 'wrap'
    }
  }, panels.map(tab => e('button', {
    key: tab.key,
    onClick: () => setActivePanel(tab.key),
    style: {
      background: activePanel === tab.key ? 'rgba(167,139,250,0.08)' : 'transparent',
      border: '1px solid ' + (activePanel === tab.key ? 'rgba(167,139,250,0.3)' : 'rgba(255,255,255,0.06)'),
      color: activePanel === tab.key ? '#a78bfa' : '#64748b',
      padding: '0.35rem 0.75rem',
      borderRadius: '4px',
      cursor: 'pointer',
      fontSize: '0.65rem',
      fontWeight: 600,
      fontFamily: "'Orbitron', sans-serif"
    }
  }, tab.label))),
  // Content
  e('div', {
    style: {
      maxHeight: '55vh',
      overflowY: 'auto'
    }
  },
  // SOURCES tab
  activePanel === 'sources' && (top_sources.length === 0 ? e('div', {
    style: {
      textAlign: 'center',
      padding: '2rem',
      color: '#94a3b8'
    }
  }, 'No signal sources tracked yet.') : top_sources.map((src, i) => e('div', {
    key: src.source_name,
    style: {
      background: 'rgba(15,22,36,0.95)',
      border: '1px solid rgba(255,255,255,0.08)',
      borderLeft: '3px solid ' + accColor(src.accuracy_pct),
      borderRadius: '8px',
      padding: '12px 16px',
      marginBottom: '8px',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center'
    }
  }, e('div', null, e('div', {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '8px'
    }
  }, e('span', {
    style: {
      fontSize: '0.7rem',
      color: '#94a3b8',
      fontWeight: 700
    }
  }, '#' + (i + 1)), e('span', {
    style: {
      fontSize: '0.95rem',
      fontWeight: 600,
      color: '#0f172a'
    }
  }, src.source_name), e('span', {
    style: {
      fontSize: '0.55rem',
      fontFamily: "'Orbitron', sans-serif",
      background: 'rgba(167,139,250,0.08)',
      border: '1px solid rgba(167,139,250,0.2)',
      borderRadius: '4px',
      padding: '2px 6px',
      color: '#a78bfa'
    }
  }, src.source_type)), e('div', {
    style: {
      fontSize: '0.75rem',
      color: '#64748b',
      marginTop: '4px'
    }
  }, src.signals_confirmed + '/' + src.signals_generated + ' signals confirmed' + (src.city ? ' \u00B7 ' + src.city + (src.state ? ', ' + src.state : '') : ''))), e('div', {
    style: {
      textAlign: 'right'
    }
  }, e('div', {
    style: {
      fontSize: '1.2rem',
      fontWeight: 700,
      color: accColor(src.accuracy_pct),
      fontFamily: "'Orbitron', sans-serif"
    }
  }, src.accuracy_pct + '%'), e('div', {
    style: {
      fontSize: '0.6rem',
      color: '#94a3b8'
    }
  }, 'ACCURACY'))))),
  // TYPES tab
  activePanel === 'types' && (type_rankings.length === 0 ? e('div', {
    style: {
      textAlign: 'center',
      padding: '2rem',
      color: '#94a3b8'
    }
  }, 'No signal type data available yet.') : type_rankings.map(t => e('div', {
    key: t.signal_type,
    style: {
      background: 'rgba(15,22,36,0.95)',
      border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: '8px',
      padding: '12px 16px',
      marginBottom: '8px',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center'
    }
  }, e('div', null, e('div', {
    style: {
      fontSize: '0.95rem',
      fontWeight: 600,
      color: '#0f172a'
    }
  }, t.signal_type), e('div', {
    style: {
      fontSize: '0.75rem',
      color: '#64748b',
      marginTop: '2px'
    }
  }, t.signals_confirmed + '/' + t.signals_generated + ' confirmed')), e('div', {
    style: {
      width: '60px',
      height: '60px',
      borderRadius: '50%',
      border: '3px solid ' + accColor(t.accuracy_pct),
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center'
    }
  }, e('div', {
    style: {
      fontSize: '0.9rem',
      fontWeight: 700,
      color: accColor(t.accuracy_pct),
      fontFamily: "'Orbitron', sans-serif"
    }
  }, t.accuracy_pct + '%'))))),
  // CITIES tab
  activePanel === 'cities' && (city_rankings.length === 0 ? e('div', {
    style: {
      textAlign: 'center',
      padding: '2rem',
      color: '#94a3b8'
    }
  }, 'No city data available yet.') : city_rankings.map(c => e('div', {
    key: c.city + '-' + c.state,
    style: {
      background: 'rgba(15,22,36,0.95)',
      border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: '8px',
      padding: '12px 16px',
      marginBottom: '8px',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center'
    }
  }, e('div', null, e('div', {
    style: {
      fontSize: '0.95rem',
      fontWeight: 600,
      color: '#0f172a'
    }
  }, c.city + ', ' + c.state), e('div', {
    style: {
      fontSize: '0.75rem',
      color: '#64748b',
      marginTop: '2px'
    }
  }, c.source_count + ' sources \u00B7 ' + c.total_confirmed + '/' + c.total_signals + ' confirmed')), e('div', {
    style: {
      textAlign: 'right'
    }
  }, e('div', {
    style: {
      fontSize: '1.2rem',
      fontWeight: 700,
      color: accColor(c.avg_accuracy_pct),
      fontFamily: "'Orbitron', sans-serif"
    }
  }, c.avg_accuracy_pct + '%'), e('div', {
    style: {
      fontSize: '0.6rem',
      color: '#94a3b8'
    }
  }, 'AVG ACCURACY'))))),
  // PRIORITY tab
  activePanel === 'priority' && (priority_index.length === 0 ? e('div', {
    style: {
      textAlign: 'center',
      padding: '2rem',
      color: '#94a3b8'
    }
  }, 'No priority data available yet.') : priority_index.map(p => e('div', {
    key: p.source_name,
    style: {
      background: 'rgba(15,22,36,0.95)',
      border: '1px solid rgba(255,255,255,0.08)',
      borderLeft: '3px solid ' + prioColor(p.priority_score),
      borderRadius: '8px',
      padding: '12px 16px',
      marginBottom: '8px',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center'
    }
  }, e('div', null, e('div', {
    style: {
      fontSize: '0.95rem',
      fontWeight: 600,
      color: '#0f172a'
    }
  }, p.source_name), e('div', {
    style: {
      fontSize: '0.75rem',
      color: '#64748b',
      marginTop: '2px'
    }
  }, p.signals_last_30_days + ' signals (30d) \u00B7 Accuracy: ' + p.accuracy_pct + '%')), e('div', {
    style: {
      textAlign: 'right'
    }
  }, e('div', {
    style: {
      fontSize: '0.9rem',
      fontWeight: 700,
      color: prioColor(p.priority_score),
      fontFamily: "'Orbitron', sans-serif"
    }
  }, p.schedule_interval), e('div', {
    style: {
      fontSize: '0.6rem',
      color: '#94a3b8'
    }
  }, 'PRIORITY: ' + (p.priority_score * 100).toFixed(0))))))));
}
function CapitalFlowPanel() {
  const [predictions, setPredictions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedPrediction, setSelectedPrediction] = useState(null);
  const [filterState, setFilterState] = useState('');
  useEffect(() => {
    loadPredictions();
  }, [filterState]);
  const loadPredictions = async () => {
    setLoading(true);
    try {
      let url = '/api/capital-flow?limit=100';
      if (filterState) url += '&state=' + encodeURIComponent(filterState);
      const res = await fetch(url);
      const data = await res.json();
      setPredictions(data.predictions || []);
    } catch (e) {
      console.error('Failed to load capital predictions:', e);
    }
    setLoading(false);
  };
  const loadDetail = async id => {
    try {
      const res = await fetch('/api/capital-flow/' + id);
      const data = await res.json();
      setSelectedPrediction(data);
    } catch (e) {
      console.error('Failed to load capital detail:', e);
    }
  };
  const eventTypeLabels = {
    CONSTRUCTION_LOAN: 'Construction Loan',
    LAND_ACQUISITION_LOAN: 'Land Acquisition Loan',
    DEBT_PLACEMENT: 'Debt Placement',
    EQUITY_INVESTMENT: 'Equity Investment',
    JOINT_VENTURE: 'Joint Venture',
    FUND_DEPLOYMENT: 'Fund Deployment'
  };
  const eventTypeColors = {
    CONSTRUCTION_LOAN: '#eab308',
    LAND_ACQUISITION_LOAN: '#f59e0b',
    DEBT_PLACEMENT: '#3b82f6',
    EQUITY_INVESTMENT: '#14b8a6',
    JOINT_VENTURE: '#a855f7',
    FUND_DEPLOYMENT: '#ef4444'
  };
  const confidenceColor = score => {
    if (score >= 80) return '#14b8a6';
    if (score >= 60) return '#f59e0b';
    return '#ef4444';
  };
  const formatAmount = amount => {
    if (!amount) return null;
    if (amount >= 1000000) return '$' + (amount / 1000000).toFixed(0) + 'M';
    if (amount >= 1000) return '$' + (amount / 1000).toFixed(0) + 'K';
    return '$' + amount.toFixed(0);
  };
  const states = [...new Set(predictions.map(p => p.state).filter(Boolean))].sort();
  return React.createElement('div', {
    style: {
      padding: '1.5rem'
    }
  }, React.createElement('div', {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '1.5rem'
    }
  }, React.createElement('div', null, React.createElement('h2', {
    style: {
      color: '#1e293b',
      fontSize: '1.5rem',
      fontWeight: 700,
      fontFamily: "'Orbitron', sans-serif",
      margin: 0
    }
  }, 'Capital Flow Signals'), React.createElement('p', {
    style: {
      color: '#64748b',
      fontSize: '0.85rem',
      marginTop: '0.3rem'
    }
  }, 'Financing signals indicating development projects are about to move forward')), React.createElement('div', {
    style: {
      display: 'flex',
      gap: '0.75rem',
      alignItems: 'center'
    }
  }, React.createElement('select', {
    value: filterState,
    onChange: e => setFilterState(e.target.value),
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      color: '#1e293b',
      borderRadius: '0.5rem',
      padding: '0.5rem 0.75rem',
      fontSize: '0.85rem'
    }
  }, React.createElement('option', {
    value: ''
  }, 'All States'), states.map(s => React.createElement('option', {
    key: s,
    value: s
  }, s))), React.createElement('button', {
    onClick: loadPredictions,
    style: {
      background: 'linear-gradient(135deg, #b45309, #eab308)',
      border: 'none',
      color: '#fff',
      borderRadius: '0.5rem',
      padding: '0.5rem 1rem',
      fontSize: '0.85rem',
      cursor: 'pointer',
      fontWeight: 600
    }
  }, 'Refresh'))), loading ? React.createElement('div', {
    style: {
      textAlign: 'center',
      padding: '3rem',
      color: '#64748b'
    }
  }, 'Scanning capital flow signals...') : predictions.length === 0 ? React.createElement('div', {
    style: {
      textAlign: 'center',
      padding: '3rem',
      color: '#64748b'
    }
  }, 'No capital predictions detected yet. The engine scans every 6 hours.') : React.createElement('div', {
    style: {
      display: 'grid',
      gridTemplateColumns: selectedPrediction ? '1fr 1fr' : '1fr',
      gap: '1.5rem'
    }
  }, React.createElement('div', {
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: '0.75rem'
    }
  }, predictions.map(p => React.createElement('div', {
    key: p.id,
    onClick: () => loadDetail(p.id),
    style: {
      background: selectedPrediction && selectedPrediction.id === p.id ? 'rgba(234,179,8,0.12)' : 'rgba(30,41,59,0.6)',
      border: selectedPrediction && selectedPrediction.id === p.id ? '1px solid rgba(234,179,8,0.4)' : '1px solid rgba(255,255,255,0.06)',
      borderRadius: '0.75rem',
      padding: '1rem 1.25rem',
      cursor: 'pointer',
      transition: 'all 0.2s'
    }
  }, React.createElement('div', {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'flex-start'
    }
  }, React.createElement('div', null, React.createElement('div', {
    style: {
      color: '#eab308',
      fontSize: '0.7rem',
      fontWeight: 700,
      letterSpacing: '0.05em',
      marginBottom: '0.3rem',
      fontFamily: "'Orbitron', sans-serif"
    }
  }, 'CAPITAL DEPLOYMENT DETECTED'), React.createElement('div', {
    style: {
      color: '#1e293b',
      fontSize: '1rem',
      fontWeight: 600
    }
  }, p.developer), React.createElement('div', {
    style: {
      color: '#64748b',
      fontSize: '0.85rem',
      marginTop: '0.15rem'
    }
  }, (p.city || '') + (p.state ? ', ' + p.state : '')), React.createElement('div', {
    style: {
      display: 'flex',
      gap: '0.5rem',
      marginTop: '0.4rem',
      alignItems: 'center'
    }
  }, React.createElement('span', {
    style: {
      background: eventTypeColors[p.capital_event] || '#eab308',
      color: '#000',
      padding: '0.15rem 0.5rem',
      borderRadius: '0.25rem',
      fontSize: '0.7rem',
      fontWeight: 700
    }
  }, eventTypeLabels[p.capital_event] || p.capital_event), p.estimated_amount && React.createElement('span', {
    style: {
      color: '#eab308',
      fontSize: '0.85rem',
      fontWeight: 700
    }
  }, formatAmount(p.estimated_amount)))), React.createElement('div', {
    style: {
      textAlign: 'right'
    }
  }, React.createElement('div', {
    style: {
      color: confidenceColor(p.confidence),
      fontSize: '1.5rem',
      fontWeight: 700,
      fontFamily: "'Orbitron', sans-serif"
    }
  }, p.confidence + '%'), React.createElement('div', {
    style: {
      color: '#64748b',
      fontSize: '0.7rem'
    }
  }, 'confidence'))), p.reasoning && React.createElement('div', {
    style: {
      color: '#64748b',
      fontSize: '0.8rem',
      marginTop: '0.5rem',
      lineHeight: 1.4
    }
  }, p.reasoning)))), selectedPrediction && React.createElement('div', {
    style: {
      background: 'rgba(30,41,59,0.6)',
      border: '1px solid rgba(234,179,8,0.3)',
      borderRadius: '0.75rem',
      padding: '1.25rem',
      position: 'sticky',
      top: '1rem',
      alignSelf: 'start'
    }
  }, React.createElement('div', {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '1rem'
    }
  }, React.createElement('h3', {
    style: {
      color: '#1e293b',
      margin: 0,
      fontSize: '1.1rem'
    }
  }, 'Capital Details'), React.createElement('button', {
    onClick: () => setSelectedPrediction(null),
    style: {
      background: 'transparent',
      border: 'none',
      color: '#64748b',
      cursor: 'pointer',
      fontSize: '1.2rem'
    }
  }, '\u00D7')), React.createElement('div', {
    style: {
      marginBottom: '1rem'
    }
  }, React.createElement('div', {
    style: {
      color: '#eab308',
      fontWeight: 700,
      fontSize: '0.9rem'
    }
  }, selectedPrediction.developer), React.createElement('div', {
    style: {
      color: '#64748b',
      fontSize: '0.85rem'
    }
  }, (selectedPrediction.city || '') + ', ' + (selectedPrediction.state || '')), selectedPrediction.estimated_amount && React.createElement('div', {
    style: {
      color: '#eab308',
      fontSize: '1.3rem',
      fontWeight: 700,
      marginTop: '0.5rem',
      fontFamily: "'Orbitron', sans-serif"
    }
  }, formatAmount(selectedPrediction.estimated_amount)), React.createElement('div', {
    style: {
      color: confidenceColor(selectedPrediction.confidence),
      fontSize: '1.1rem',
      fontWeight: 700,
      marginTop: '0.3rem',
      fontFamily: "'Orbitron', sans-serif"
    }
  }, 'Confidence: ' + selectedPrediction.confidence + '%')), selectedPrediction.reasoning && React.createElement('div', {
    style: {
      color: '#334155',
      fontSize: '0.85rem',
      marginBottom: '1rem',
      padding: '0.75rem',
      background: 'rgba(234,179,8,0.08)',
      borderRadius: '0.5rem',
      lineHeight: 1.5
    }
  }, selectedPrediction.reasoning), React.createElement('h4', {
    style: {
      color: '#64748b',
      fontSize: '0.8rem',
      fontWeight: 600,
      marginBottom: '0.5rem'
    }
  }, 'CAPITAL EVENTS'), (selectedPrediction.events || []).length === 0 ? React.createElement('div', {
    style: {
      color: '#64748b',
      fontSize: '0.8rem'
    }
  }, 'No event details available') : (selectedPrediction.events || []).map((ev, i) => React.createElement('div', {
    key: ev.id || i,
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '0.75rem',
      padding: '0.5rem 0',
      borderBottom: '1px solid rgba(255,255,255,0.04)'
    }
  }, React.createElement('span', {
    style: {
      display: 'inline-block',
      width: '8px',
      height: '8px',
      borderRadius: '50%',
      background: eventTypeColors[ev.event_type] || '#eab308',
      flexShrink: 0
    }
  }), React.createElement('div', null, React.createElement('div', {
    style: {
      color: '#1e293b',
      fontSize: '0.85rem',
      fontWeight: 500
    }
  }, eventTypeLabels[ev.event_type] || ev.event_type), ev.lender_name && React.createElement('div', {
    style: {
      color: '#64748b',
      fontSize: '0.75rem'
    }
  }, 'Lender: ' + ev.lender_name), ev.loan_amount && React.createElement('div', {
    style: {
      color: '#eab308',
      fontSize: '0.75rem',
      fontWeight: 600
    }
  }, formatAmount(ev.loan_amount)), React.createElement('div', {
    style: {
      color: '#94a3b8',
      fontSize: '0.7rem'
    }
  }, timeAgo(ev.created_at))))))));
}

// ===================================================================
// DEVELOPER INTENT PANEL
// ===================================================================
function DeveloperIntentPanel() {
  const [predictions, setPredictions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedPrediction, setSelectedPrediction] = useState(null);
  const [filterState, setFilterState] = useState('');
  useEffect(() => {
    loadPredictions();
  }, [filterState]);
  const loadPredictions = async () => {
    setLoading(true);
    try {
      let url = '/api/developer-intent?limit=100';
      if (filterState) url += '&state=' + encodeURIComponent(filterState);
      const res = await fetch(url);
      const data = await res.json();
      setPredictions(data.predictions || []);
    } catch (e) {
      console.error('Failed to load intent predictions:', e);
    }
    setLoading(false);
  };
  const loadDetail = async id => {
    try {
      const res = await fetch('/api/developer-intent/' + id);
      const data = await res.json();
      setSelectedPrediction(data);
    } catch (e) {
      console.error('Failed to load prediction detail:', e);
    }
  };
  const signalTypeLabels = {
    CONSULTANT_HIRING: 'Consultant Hiring',
    ENGINEERING_ENGAGEMENT: 'Engineering Engagement',
    CONTRACTOR_PRECON: 'Contractor Consultation',
    ENTITY_FORMATION: 'New LLC Formation',
    MARKET_RESEARCH: 'Market Research',
    HIRING_EXPANSION: 'Hiring Expansion'
  };
  const signalTypeColors = {
    CONSULTANT_HIRING: '#f59e0b',
    ENGINEERING_ENGAGEMENT: '#3b82f6',
    CONTRACTOR_PRECON: '#ef4444',
    ENTITY_FORMATION: '#a855f7',
    MARKET_RESEARCH: '#06b6d4',
    HIRING_EXPANSION: '#14b8a6'
  };
  const confidenceColor = score => {
    if (score >= 80) return '#14b8a6';
    if (score >= 60) return '#f59e0b';
    return '#ef4444';
  };
  const states = [...new Set(predictions.map(p => p.state).filter(Boolean))].sort();
  return React.createElement('div', {
    style: {
      padding: '1.5rem'
    }
  }, React.createElement('div', {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '1.5rem'
    }
  }, React.createElement('div', null, React.createElement('h2', {
    style: {
      color: '#1e293b',
      fontSize: '1.5rem',
      fontWeight: 700,
      fontFamily: "'Orbitron', sans-serif",
      margin: 0
    }
  }, 'Developer Intent Signals'), React.createElement('p', {
    style: {
      color: '#64748b',
      fontSize: '0.85rem',
      marginTop: '0.3rem'
    }
  }, 'Early detection of developer preparation activity before land acquisition')), React.createElement('div', {
    style: {
      display: 'flex',
      gap: '0.75rem',
      alignItems: 'center'
    }
  }, React.createElement('select', {
    value: filterState,
    onChange: e => setFilterState(e.target.value),
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      color: '#1e293b',
      borderRadius: '0.5rem',
      padding: '0.5rem 0.75rem',
      fontSize: '0.85rem'
    }
  }, React.createElement('option', {
    value: ''
  }, 'All States'), states.map(s => React.createElement('option', {
    key: s,
    value: s
  }, s))), React.createElement('button', {
    onClick: loadPredictions,
    style: {
      background: 'linear-gradient(135deg, #7c3aed, #a855f7)',
      border: 'none',
      color: '#fff',
      borderRadius: '0.5rem',
      padding: '0.5rem 1rem',
      fontSize: '0.85rem',
      cursor: 'pointer',
      fontWeight: 600
    }
  }, 'Refresh'))), loading ? React.createElement('div', {
    style: {
      textAlign: 'center',
      padding: '3rem',
      color: '#64748b'
    }
  }, 'Scanning developer intent signals...') : predictions.length === 0 ? React.createElement('div', {
    style: {
      textAlign: 'center',
      padding: '3rem',
      color: '#64748b'
    }
  }, 'No intent predictions detected yet. The engine scans every 4 hours.') : React.createElement('div', {
    style: {
      display: 'grid',
      gridTemplateColumns: selectedPrediction ? '1fr 1fr' : '1fr',
      gap: '1.5rem'
    }
  }, React.createElement('div', {
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: '0.75rem'
    }
  }, predictions.map(p => React.createElement('div', {
    key: p.id,
    onClick: () => loadDetail(p.id),
    style: {
      background: selectedPrediction && selectedPrediction.id === p.id ? 'rgba(168,85,247,0.12)' : 'rgba(30,41,59,0.6)',
      border: selectedPrediction && selectedPrediction.id === p.id ? '1px solid rgba(168,85,247,0.4)' : '1px solid rgba(255,255,255,0.06)',
      borderRadius: '0.75rem',
      padding: '1rem 1.25rem',
      cursor: 'pointer',
      transition: 'all 0.2s'
    }
  }, React.createElement('div', {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'flex-start'
    }
  }, React.createElement('div', null, React.createElement('div', {
    style: {
      color: '#a855f7',
      fontSize: '0.7rem',
      fontWeight: 700,
      letterSpacing: '0.05em',
      marginBottom: '0.3rem',
      fontFamily: "'Orbitron', sans-serif"
    }
  }, 'DEVELOPER INTENT DETECTED'), React.createElement('div', {
    style: {
      color: '#1e293b',
      fontSize: '1rem',
      fontWeight: 600
    }
  }, p.developer), React.createElement('div', {
    style: {
      color: '#64748b',
      fontSize: '0.85rem',
      marginTop: '0.15rem'
    }
  }, (p.city || '') + (p.state ? ', ' + p.state : ''))), React.createElement('div', {
    style: {
      textAlign: 'right'
    }
  }, React.createElement('div', {
    style: {
      color: confidenceColor(p.confidence),
      fontSize: '1.5rem',
      fontWeight: 700,
      fontFamily: "'Orbitron', sans-serif"
    }
  }, p.confidence + '%'), React.createElement('div', {
    style: {
      color: '#64748b',
      fontSize: '0.7rem'
    }
  }, p.signal_count + ' signals'))), p.reasoning && React.createElement('div', {
    style: {
      color: '#64748b',
      fontSize: '0.8rem',
      marginTop: '0.5rem',
      lineHeight: 1.4
    }
  }, p.reasoning)))), selectedPrediction && React.createElement('div', {
    style: {
      background: 'rgba(30,41,59,0.6)',
      border: '1px solid rgba(168,85,247,0.3)',
      borderRadius: '0.75rem',
      padding: '1.25rem',
      position: 'sticky',
      top: '1rem',
      alignSelf: 'start'
    }
  }, React.createElement('div', {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '1rem'
    }
  }, React.createElement('h3', {
    style: {
      color: '#1e293b',
      margin: 0,
      fontSize: '1.1rem'
    }
  }, 'Signal Details'), React.createElement('button', {
    onClick: () => setSelectedPrediction(null),
    style: {
      background: 'transparent',
      border: 'none',
      color: '#64748b',
      cursor: 'pointer',
      fontSize: '1.2rem'
    }
  }, '\u00D7')), React.createElement('div', {
    style: {
      marginBottom: '1rem'
    }
  }, React.createElement('div', {
    style: {
      color: '#a855f7',
      fontWeight: 700,
      fontSize: '0.9rem'
    }
  }, selectedPrediction.developer), React.createElement('div', {
    style: {
      color: '#64748b',
      fontSize: '0.85rem'
    }
  }, (selectedPrediction.city || '') + ', ' + (selectedPrediction.state || '')), React.createElement('div', {
    style: {
      color: confidenceColor(selectedPrediction.confidence),
      fontSize: '1.3rem',
      fontWeight: 700,
      marginTop: '0.5rem',
      fontFamily: "'Orbitron', sans-serif"
    }
  }, 'Confidence: ' + selectedPrediction.confidence + '%')), selectedPrediction.reasoning && React.createElement('div', {
    style: {
      color: '#334155',
      fontSize: '0.85rem',
      marginBottom: '1rem',
      padding: '0.75rem',
      background: 'rgba(168,85,247,0.08)',
      borderRadius: '0.5rem',
      lineHeight: 1.5
    }
  }, selectedPrediction.reasoning), React.createElement('h4', {
    style: {
      color: '#64748b',
      fontSize: '0.8rem',
      fontWeight: 600,
      marginBottom: '0.5rem'
    }
  }, 'DETECTED SIGNALS'), (selectedPrediction.signals || []).length === 0 ? React.createElement('div', {
    style: {
      color: '#64748b',
      fontSize: '0.8rem'
    }
  }, 'No signal details available') : (selectedPrediction.signals || []).map((sig, i) => React.createElement('div', {
    key: sig.id || i,
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '0.75rem',
      padding: '0.5rem 0',
      borderBottom: '1px solid rgba(255,255,255,0.04)'
    }
  }, React.createElement('span', {
    style: {
      display: 'inline-block',
      width: '8px',
      height: '8px',
      borderRadius: '50%',
      background: signalTypeColors[sig.signal_type] || '#64748b',
      flexShrink: 0
    }
  }), React.createElement('div', null, React.createElement('div', {
    style: {
      color: '#1e293b',
      fontSize: '0.85rem',
      fontWeight: 500
    }
  }, signalTypeLabels[sig.signal_type] || sig.signal_type), sig.related_entity && React.createElement('div', {
    style: {
      color: '#64748b',
      fontSize: '0.75rem'
    }
  }, sig.related_entity), React.createElement('div', {
    style: {
      color: '#94a3b8',
      fontSize: '0.7rem'
    }
  }, timeAgo(sig.created_at))))))));
}
function LiveIntelligenceFeed() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [paused, setPaused] = useState(false);
  const [filterType, setFilterType] = useState('');
  const [newIds, setNewIds] = useState(new Set());
  const previousIdsRef = useRef(new Set());
  const feedRef = useRef(null);
  const intervalRef = useRef(null);
  const fetchFeed = useCallback(async () => {
    try {
      let url = `${API_BASE}/api/intelligence-feed?limit=100`;
      if (filterType) url += `&type=${filterType}`;
      const res = await fetch(url);
      const data = await res.json();
      if (data.success && data.events) {
        // Detect new events for animation
        const incoming = new Set(data.events.map(e => e.id));
        const fresh = new Set();
        data.events.forEach(e => {
          if (!previousIdsRef.current.has(e.id)) fresh.add(e.id);
        });
        previousIdsRef.current = incoming;
        setNewIds(fresh);
        setEvents(data.events);
        // Auto-scroll to top when not paused
        if (!paused && feedRef.current) feedRef.current.scrollTop = 0;
      }
    } catch (e) {
      console.error('[Feed] Error:', e);
    } finally {
      setLoading(false);
    }
  }, [filterType, paused]);
  useEffect(() => {
    fetchFeed();
    intervalRef.current = setInterval(() => {
      if (!paused) fetchFeed();
    }, 10000);
    return () => clearInterval(intervalRef.current);
  }, [fetchFeed, paused]);

  // Clear new flags after animation
  useEffect(() => {
    if (newIds.size > 0) {
      const timer = setTimeout(() => setNewIds(new Set()), 500);
      return () => clearTimeout(timer);
    }
  }, [newIds]);
  const typeFilters = ['', 'SIGNAL', 'PERMIT', 'PATTERN', 'DEVELOPER_EXPANSION', 'CONTRACTOR_ACTIVITY', 'PARCEL_ALERT'];
  return /*#__PURE__*/React.createElement("div", {
    style: {
      maxWidth: '900px',
      margin: '0 auto'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '1.25rem',
      flexWrap: 'wrap',
      gap: '0.75rem'
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '1.3rem',
      fontWeight: 900,
      background: 'linear-gradient(135deg, #14b8a6 0%, #3b82f6 100%)',
      WebkitBackgroundClip: 'text',
      WebkitTextFillColor: 'transparent',
      margin: 0
    }
  }, "LIVE INTELLIGENCE FEED"), /*#__PURE__*/React.createElement("p", {
    style: {
      color: '#64748b',
      fontSize: '0.8rem',
      margin: '0.25rem 0 0'
    }
  }, "Real-time development signals across all monitored markets")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.5rem',
      alignItems: 'center'
    }
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => setPaused(!paused),
    style: {
      background: paused ? 'rgba(239,68,68,0.1)' : 'rgba(20,184,166,0.1)',
      border: '1px solid ' + (paused ? 'rgba(239,68,68,0.3)' : 'rgba(20,184,166,0.3)'),
      color: paused ? '#f87171' : '#34d399',
      padding: '0.4rem 0.85rem',
      borderRadius: '6px',
      cursor: 'pointer',
      fontSize: '0.75rem',
      fontWeight: 600,
      fontFamily: "'Orbitron', sans-serif"
    }
  }, paused ? 'PAUSED' : 'LIVE'))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.35rem',
      marginBottom: '1rem',
      flexWrap: 'wrap'
    }
  }, typeFilters.map(t => {
    const colors = FEED_EVENT_COLORS[t] || {
      accent: '#94a3b8',
      bg: 'transparent',
      border: 'rgba(255,255,255,0.08)'
    };
    const active = filterType === t;
    return /*#__PURE__*/React.createElement("button", {
      key: t || 'all',
      onClick: () => setFilterType(t),
      style: {
        background: active ? colors.bg : 'transparent',
        border: '1px solid ' + (active ? colors.border : 'rgba(255,255,255,0.06)'),
        color: active ? colors.accent : '#64748b',
        padding: '0.3rem 0.65rem',
        borderRadius: '4px',
        cursor: 'pointer',
        fontSize: '0.65rem',
        fontWeight: 600,
        fontFamily: "'Orbitron', sans-serif",
        textTransform: 'uppercase'
      }
    }, t ? FEED_EVENT_LABELS[t] || t : 'ALL');
  })), /*#__PURE__*/React.createElement("div", {
    ref: feedRef,
    style: {
      maxHeight: '65vh',
      overflowY: 'auto',
      padding: '2px',
      scrollBehavior: 'smooth'
    }
  }, loading && events.length === 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      textAlign: 'center',
      padding: '3rem',
      color: '#14b8a6',
      fontFamily: "'Orbitron', sans-serif",
      animation: 'pulse 1.5s ease-in-out infinite'
    }
  }, "INITIALIZING FEED..."), !loading && events.length === 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      textAlign: 'center',
      padding: '3rem'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '1.2rem',
      color: '#64748b',
      fontFamily: "'Orbitron', sans-serif",
      marginBottom: '0.5rem'
    }
  }, "NO EVENTS YET"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '0.85rem',
      color: '#94a3b8'
    }
  }, "Intelligence events will appear here as they are detected by the system.")), events.map(event => /*#__PURE__*/React.createElement(FeedEventCard, {
    key: event.id,
    event: event,
    isNew: newIds.has(event.id)
  }))), events.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      textAlign: 'center',
      padding: '0.5rem',
      fontSize: '0.7rem',
      color: '#94a3b8',
      marginTop: '0.5rem'
    }
  }, "Showing ", events.length, " events ", '\u00B7', " Polling every 10s ", paused ? ' (paused)' : ''));
}
function Stats({
  prospects
}) {
  const avgScore = prospects.length > 0 ? Math.round(prospects.reduce((sum, p) => sum + p.score, 0) / prospects.length) : 0;
  const hotLeads = prospects.filter(p => p.score >= 90).length;
  const hasData = prospects.length > 0;
  return /*#__PURE__*/React.createElement("div", {
    style: styles.statsBar
  }, /*#__PURE__*/React.createElement(StatCard, {
    label: "Total Prospects",
    value: hasData ? prospects.length : '--'
  }), /*#__PURE__*/React.createElement(StatCard, {
    label: "Hot Leads (90+)",
    value: hasData ? hotLeads : '--',
    pulse: hasData && hotLeads > 0
  }), /*#__PURE__*/React.createElement(StatCard, {
    label: "Avg Score",
    value: hasData ? avgScore : '--'
  }), /*#__PURE__*/React.createElement(StatCard, {
    label: "Status",
    value: "LIVE"
  }));
}
function StatCard({
  label,
  value,
  pulse
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      ...styles.statCard,
      borderRadius: '1rem'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: styles.statLabel
  }, label), /*#__PURE__*/React.createElement("div", {
    className: "flex items-end gap-2"
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      ...styles.statValue,
      ...(pulse ? styles.pulse : {})
    }
  }, String(value)), /*#__PURE__*/React.createElement(Sparkline, null)));
}
function Controls({
  searchCity,
  setSearchCity,
  filterScore,
  setFilterScore,
  filterTrigger,
  setFilterTrigger,
  filterSwimLane,
  setFilterSwimLane,
  sortBy,
  setSortBy,
  onSearch,
  onExport,
  loading,
  hasProspects,
  cooldown,
  filterEightyPlus,
  setFilterEightyPlus,
  filterCapitalEvents,
  setFilterCapitalEvents,
  filterLowComp,
  setFilterLowComp,
  filterCallNow,
  setFilterCallNow,
  dateFilter,
  setDateFilter,
  customDateStart,
  setCustomDateStart,
  customDateEnd,
  setCustomDateEnd,
  onDateFilterChange
}) {
  const isDisabled = loading || cooldown > 0;
  let btnLabel = 'Search Prospects';
  if (loading) btnLabel = 'Searching...';else if (cooldown > 0) btnLabel = `Wait ${cooldown}s`;
  const pillStyle = active => ({
    fontSize: '0.8rem',
    padding: '0.4rem 0.85rem',
    borderRadius: '9999px',
    border: `1px solid ${active ? '#34d399' : '#e2e8f0'}`,
    background: active ? 'rgba(20,184,166,0.1)' : 'transparent',
    color: active ? '#34d399' : '#94a3b8',
    cursor: 'pointer',
    fontFamily: 'Inter, sans-serif',
    fontWeight: 500
  });
  return /*#__PURE__*/React.createElement("div", {
    style: styles.controls
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.75rem',
      flexWrap: 'wrap',
      alignItems: 'center',
      width: '100%'
    }
  }, /*#__PURE__*/React.createElement("button", {
    style: {
      ...styles.btnPrimary,
      ...(isDisabled ? {
        opacity: 0.5,
        cursor: 'not-allowed'
      } : {})
    },
    onClick: onSearch,
    disabled: isDisabled
  }, btnLabel), /*#__PURE__*/React.createElement("input", {
    type: "text",
    style: styles.input,
    value: searchCity,
    onChange: e => setSearchCity(e.target.value),
    placeholder: "City or State (e.g., Dallas, Texas)"
  }), /*#__PURE__*/React.createElement("select", {
    style: styles.select,
    value: filterScore,
    onChange: e => setFilterScore(e.target.value)
  }, /*#__PURE__*/React.createElement("option", {
    value: "all"
  }, "All Scores"), /*#__PURE__*/React.createElement("option", {
    value: "90+"
  }, "90+ (Urgent)"), /*#__PURE__*/React.createElement("option", {
    value: "80+"
  }, "80+ (High Priority)"), /*#__PURE__*/React.createElement("option", {
    value: "80-89"
  }, "80-89 (High)")), /*#__PURE__*/React.createElement("select", {
    style: styles.select,
    value: filterTrigger,
    onChange: e => setFilterTrigger(e.target.value)
  }, /*#__PURE__*/React.createElement("option", {
    value: "all"
  }, "All Triggers"), /*#__PURE__*/React.createElement("option", {
    value: "Builder's Risk"
  }, "Builder's Risk"), /*#__PURE__*/React.createElement("option", {
    value: "lender covenants"
  }, "Lender Covenants"), /*#__PURE__*/React.createElement("option", {
    value: "Portfolio scale"
  }, "Portfolio Scale"), /*#__PURE__*/React.createElement("option", {
    value: "state expansion"
  }, "State Expansion"), /*#__PURE__*/React.createElement("option", {
    value: "capital event"
  }, "Capital Event"), /*#__PURE__*/React.createElement("option", {
    value: "Refinance"
  }, "Refinance / Debt"), /*#__PURE__*/React.createElement("option", {
    value: "Lease-up"
  }, "Lease-up Shift")), /*#__PURE__*/React.createElement("select", {
    style: styles.select,
    value: sortBy,
    onChange: e => setSortBy(e.target.value)
  }, /*#__PURE__*/React.createElement("option", {
    value: "score"
  }, "Sort: Severity Score"), /*#__PURE__*/React.createElement("option", {
    value: "swim_lane"
  }, "Sort: Swim Lane Fit"), /*#__PURE__*/React.createElement("option", {
    value: "call_timing"
  }, "Sort: Call Timing")), /*#__PURE__*/React.createElement("select", {
    style: styles.select,
    value: dateFilter,
    onChange: e => {
      setDateFilter(e.target.value);
      if (e.target.value !== 'custom') onDateFilterChange(e.target.value);
    }
  }, /*#__PURE__*/React.createElement("option", {
    value: "all"
  }, "Date: All Time"), /*#__PURE__*/React.createElement("option", {
    value: "today"
  }, "Date: Today"), /*#__PURE__*/React.createElement("option", {
    value: "7days"
  }, "Date: Last 7 Days"), /*#__PURE__*/React.createElement("option", {
    value: "30days"
  }, "Date: Last 30 Days"), /*#__PURE__*/React.createElement("option", {
    value: "custom"
  }, "Date: Custom Range")), dateFilter === 'custom' && /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("input", {
    type: "date",
    style: {
      ...styles.input,
      width: '140px'
    },
    value: customDateStart,
    onChange: e => setCustomDateStart(e.target.value)
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#64748b',
      fontSize: '0.8rem'
    }
  }, "to"), /*#__PURE__*/React.createElement("input", {
    type: "date",
    style: {
      ...styles.input,
      width: '140px'
    },
    value: customDateEnd,
    onChange: e => setCustomDateEnd(e.target.value)
  }), /*#__PURE__*/React.createElement("button", {
    style: styles.btn,
    onClick: () => onDateFilterChange('custom')
  }, "Apply")), hasProspects && /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: styles.btn,
    onClick: onExport
  }, "Download CSV")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.5rem',
      flexWrap: 'wrap',
      alignItems: 'center',
      paddingTop: '0.65rem',
      borderTop: '1px solid #e2e8f0',
      width: '100%'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.75rem',
      color: '#64748b',
      marginRight: '0.25rem',
      textTransform: 'uppercase',
      fontWeight: 600,
      letterSpacing: '0.05em'
    }
  }, "Quick Filters"), /*#__PURE__*/React.createElement("button", {
    className: "filter-pill",
    style: pillStyle(filterEightyPlus),
    onClick: () => setFilterEightyPlus(!filterEightyPlus)
  }, filterEightyPlus ? '✓ ' : '', "80+ Only"), /*#__PURE__*/React.createElement("button", {
    className: "filter-pill",
    style: pillStyle(filterSwimLane),
    onClick: () => setFilterSwimLane(!filterSwimLane)
  }, filterSwimLane ? '✓ ' : '', "40-400 Units"), /*#__PURE__*/React.createElement("button", {
    className: "filter-pill",
    style: pillStyle(filterCapitalEvents),
    onClick: () => setFilterCapitalEvents(!filterCapitalEvents)
  }, filterCapitalEvents ? '✓ ' : '', "Capital Events"), /*#__PURE__*/React.createElement("button", {
    className: "filter-pill",
    style: pillStyle(filterLowComp),
    onClick: () => setFilterLowComp(!filterLowComp)
  }, filterLowComp ? '✓ ' : '', "Low Competition"), /*#__PURE__*/React.createElement("button", {
    className: "filter-pill",
    style: {
      ...pillStyle(filterCallNow),
      borderColor: filterCallNow ? '#ef4444' : undefined,
      color: filterCallNow ? '#f87171' : undefined
    },
    onClick: () => setFilterCallNow(!filterCallNow)
  }, filterCallNow ? '✓ ' : '', "Call Now")));
}
function SearchStatus({
  message
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: styles.searchStatus
  }, /*#__PURE__*/React.createElement("p", null, message));
}
function Loading() {
  return /*#__PURE__*/React.createElement("div", {
    style: styles.loading
  }, /*#__PURE__*/React.createElement("div", {
    style: styles.loadingText
  }, "Processing..."));
}
function ProspectsList({
  prospects,
  onGenerateEmail,
  onDelete,
  crmStatuses,
  onSaveToPipeline,
  onLogTouchpoint,
  user,
  callTimingScores
}) {
  if (!Array.isArray(prospects) || prospects.length === 0) {
    return /*#__PURE__*/React.createElement(EmptyState, {
      title: "No prospects yet",
      subtitle: "Click \"Search Prospects\" to find BTR developers using AI",
      icon: /*#__PURE__*/React.createElement("svg", {
        width: "36",
        height: "36",
        viewBox: "0 0 24 24",
        fill: "none",
        stroke: "currentColor",
        strokeWidth: "1.5",
        className: "text-slate-600"
      }, /*#__PURE__*/React.createElement("circle", {
        cx: "11",
        cy: "11",
        r: "8"
      }), /*#__PURE__*/React.createElement("line", {
        x1: "21",
        y1: "21",
        x2: "16.65",
        y2: "16.65"
      }))
    });
  }
  return /*#__PURE__*/React.createElement("div", {
    style: styles.grid
  }, prospects.map(prospect => {
    const pk = makeProspectKey(prospect.company, null, prospect.city, prospect.state);
    const crmInfo = (crmStatuses || {})[pk];
    const nc = (prospect.company || '').toLowerCase().replace(/[^a-z0-9]/g, '');
    const nci = (prospect.city || '').toLowerCase().replace(/[^a-z0-9]/g, '');
    const ns = (prospect.state || '').toLowerCase().replace(/[^a-z0-9]/g, '');
    const timingKey = nc + '|' + nci + '|' + ns;
    const timingInfo = (callTimingScores || {})[timingKey];
    return /*#__PURE__*/React.createElement(ProspectCard, {
      key: prospect.id,
      prospect: prospect,
      onGenerateEmail: onGenerateEmail,
      onDelete: onDelete,
      crmInfo: crmInfo,
      onSaveToPipeline: onSaveToPipeline,
      onLogTouchpoint: onLogTouchpoint,
      user: user,
      timingInfo: timingInfo
    });
  }));
}
function ScoreBar({
  label,
  value,
  max,
  color
}) {
  const pct = max > 0 ? Math.round(value / max * 100) : 0;
  return /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '0.5rem',
      marginBottom: '0.3rem'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.7rem',
      color: '#64748b',
      width: '90px',
      textAlign: 'right',
      flexShrink: 0
    }
  }, label), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      height: '5px',
      background: '#FFFFFF',
      borderRadius: '3px',
      overflow: 'hidden'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: `${pct}%`,
      height: '100%',
      background: color,
      borderRadius: '3px',
      transition: 'width 0.3s'
    }
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.7rem',
      color: color,
      width: '30px',
      flexShrink: 0
    }
  }, value, "/", max));
}
function ProspectCard({
  prospect,
  onGenerateEmail,
  onDelete,
  crmInfo,
  onSaveToPipeline,
  onLogTouchpoint,
  user,
  timingInfo
}) {
  const [showEmailOptions, setShowEmailOptions] = useState(false);
  const [whyNowExpanded, setWhyNowExpanded] = useState(false);
  const [showTimingDetail, setShowTimingDetail] = useState(false);
  const [showGovSignals, setShowGovSignals] = useState(false);
  const [emailPurpose, setEmailPurpose] = useState('cold_outreach');
  const [tone, setTone] = useState('professional_direct');
  const [offer, setOffer] = useState('15_min_call');
  const foundDate = prospect.createdAt ? new Date(prospect.createdAt).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric'
  }) : null;

  // Call timing badge colors
  const timingColors = {
    'Call Now': {
      bg: 'rgba(239,68,68,0.15)',
      color: '#f87171',
      border: '#ef4444'
    },
    'Work': {
      bg: 'rgba(245,158,11,0.15)',
      color: '#fcd34d',
      border: '#f59e0b'
    },
    'Watch': {
      bg: 'rgba(148,163,184,0.15)',
      color: '#64748b',
      border: '#64748b'
    }
  };
  const handleGenerate = () => {
    onGenerateEmail(prospect, {
      emailPurpose,
      tone,
      offer
    });
    setShowEmailOptions(false);
  };
  const score = prospect.score || 0;
  const breakdown = prospect.score_breakdown || {};
  const hasBreakdown = Object.keys(breakdown).length > 0;
  const explanation = prospect.score_explanation || [];
  const triggers = prospect.insurance_triggers || [];
  const swimLane = prospect.swim_lane_fit_score || 0;
  const unitBand = prospect.unit_band || '';
  const competitiveDifficulty = prospect.competitive_difficulty || '';
  const govActivity = prospect.government_activity || [];

  // Score badge border + glow
  let scoreBorderColor = '#94a3b8';
  let scoreGlow = 'none';
  let scoreAnim = 'none';
  if (score >= 90) {
    scoreBorderColor = '#0d9488';
    scoreGlow = '0 0 14px rgba(16,185,129,0.45)';
    scoreAnim = 'glowPulse 2s ease-in-out infinite';
  } else if (score >= 80) {
    scoreBorderColor = '#14b8a6';
    scoreGlow = '0 0 10px rgba(20,184,166,0.15)';
  } else if (score >= 70) {
    scoreBorderColor = '#3b82f6';
  }

  // Card left accent
  let cardAccent = {};
  if (score >= 85) cardAccent = {
    borderLeft: '4px solid #14b8a6'
  };else if (score >= 70) cardAccent = {
    borderLeft: '4px solid #3b82f6'
  };

  // Competitive difficulty dot
  const compDotColor = competitiveDifficulty === 'Low' ? '#34d399' : competitiveDifficulty === 'Medium' ? '#fbbf24' : '#ef4444';
  return /*#__PURE__*/React.createElement("div", {
    className: cn('prospect-card', score >= 90 && 'card-score-glow card-high-priority'),
    style: {
      ...styles.card,
      ...cardAccent,
      borderRadius: '1rem'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: styles.cardHeader
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      minWidth: 0
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '0.5rem',
      flexWrap: 'wrap'
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      ...styles.companyName,
      marginBottom: 0
    }
  }, prospect.company), crmInfo && /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.65rem',
      padding: '0.15rem 0.45rem',
      borderRadius: '4px',
      fontWeight: 600,
      background: (CRM_STATUS_COLORS[crmInfo.status] || CRM_STATUS_COLORS.New).bg,
      color: (CRM_STATUS_COLORS[crmInfo.status] || CRM_STATUS_COLORS.New).color,
      textTransform: 'uppercase',
      letterSpacing: '0.03em'
    }
  }, crmInfo.status), crmInfo && crmInfo.owner_user_id && /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.65rem',
      color: '#64748b'
    }
  }, crmInfo.owner_user_id === user?.id ? 'Owned by: Me' : crmInfo.owner_name ? `Owned by: ${crmInfo.owner_name}` : '')), /*#__PURE__*/React.createElement("p", {
    style: styles.location
  }, prospect.city, ", ", prospect.state, foundDate ? ` · ${foundDate}` : '')), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.6rem',
      alignItems: 'center',
      flexShrink: 0
    }
  }, timingInfo && /*#__PURE__*/React.createElement("div", {
    onClick: () => setShowTimingDetail(!showTimingDetail),
    style: {
      fontSize: '0.7rem',
      padding: '0.2rem 0.55rem',
      borderRadius: '6px',
      background: (timingColors[timingInfo.timing_label] || timingColors.Watch).bg,
      color: (timingColors[timingInfo.timing_label] || timingColors.Watch).color,
      border: `1px solid ${(timingColors[timingInfo.timing_label] || timingColors.Watch).border}`,
      fontWeight: 700,
      letterSpacing: '0.03em',
      textTransform: 'uppercase',
      cursor: 'pointer'
    }
  }, timingInfo.timing_label, " ", Math.round(timingInfo.call_timing_score)), swimLane > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '0.75rem',
      padding: '0.25rem 0.55rem',
      borderRadius: '6px',
      background: 'rgba(99,102,241,0.15)',
      color: '#a5b4fc',
      fontWeight: 500,
      letterSpacing: '0.02em'
    }
  }, "Swim Fit ", swimLane), govActivity.length > 0 && /*#__PURE__*/React.createElement("div", {
    onClick: () => setShowGovSignals(!showGovSignals),
    style: {
      fontSize: '0.7rem',
      padding: '0.2rem 0.55rem',
      borderRadius: '6px',
      background: 'rgba(245,158,11,0.15)',
      color: '#fcd34d',
      border: '1px solid rgba(245,158,11,0.3)',
      fontWeight: 700,
      letterSpacing: '0.03em',
      textTransform: 'uppercase',
      cursor: 'pointer'
    }
  }, "Gov Signals ", govActivity.length), /*#__PURE__*/React.createElement("div", {
    style: {
      width: '3.5rem',
      height: '3.5rem',
      borderRadius: '50%',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      border: `2px solid ${scoreBorderColor}`,
      boxShadow: scoreGlow,
      animation: scoreAnim,
      fontFamily: "'Orbitron', sans-serif",
      fontWeight: 700,
      fontSize: '1.1rem',
      color: '#fff',
      flexShrink: 0
    }
  }, score))), /*#__PURE__*/React.createElement("div", {
    style: styles.executive
  }, /*#__PURE__*/React.createElement("strong", null, prospect.executive || 'Contact via company'), " ", prospect.title && `- ${prospect.title}`, validLinkedIn(prospect.linkedin) && /*#__PURE__*/React.createElement("a", {
    href: normalizeLinkedIn(prospect.linkedin),
    target: "_blank",
    rel: "noopener noreferrer",
    style: styles.linkedinLink
  }, "LinkedIn")), hasBreakdown && /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '0.75rem',
      background: '#F7F9FC',
      borderRadius: '8px',
      border: '1px solid #e2e8f0'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '0.7rem',
      color: '#64748b',
      fontWeight: 600,
      marginBottom: '0.5rem',
      textTransform: 'uppercase',
      letterSpacing: '0.05em'
    }
  }, brokerLabel('Trigger Severity', user?.role)), /*#__PURE__*/React.createElement(ScoreBar, {
    label: "Capital Event",
    value: breakdown.capital_event || 0,
    max: 40,
    color: "#ef4444"
  }), /*#__PURE__*/React.createElement(ScoreBar, {
    label: "Construction",
    value: breakdown.construction_stage || 0,
    max: 25,
    color: "#06b6d4"
  }), /*#__PURE__*/React.createElement(ScoreBar, {
    label: "Expansion",
    value: breakdown.expansion_velocity || 0,
    max: 20,
    color: "#f59e0b"
  }), /*#__PURE__*/React.createElement(ScoreBar, {
    label: "Freshness",
    value: breakdown.freshness || 0,
    max: 15,
    color: "#14b8a6"
  })), explanation.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '0.5rem 0.75rem',
      background: 'rgba(6,182,212,0.05)',
      borderLeft: '2px solid #06b6d4',
      borderRadius: '0 6px 6px 0'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '0.65rem',
      color: '#06b6d4',
      fontWeight: 600,
      marginBottom: '0.3rem',
      textTransform: 'uppercase',
      letterSpacing: '0.05em'
    }
  }, "Score Rationale"), explanation.map((line, idx) => /*#__PURE__*/React.createElement("div", {
    key: idx,
    style: {
      fontSize: '0.78rem',
      color: '#64748b',
      lineHeight: '1.4',
      marginBottom: '0.15rem'
    }
  }, "\u2022 ", line))), showTimingDetail && timingInfo && /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '0.75rem',
      background: 'rgba(239,68,68,0.04)',
      border: '1px solid rgba(239,68,68,0.15)',
      borderRadius: '8px'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '0.65rem',
      color: '#ef4444',
      fontWeight: 600,
      marginBottom: '0.5rem',
      textTransform: 'uppercase',
      letterSpacing: '0.05em'
    }
  }, "Call Timing Breakdown"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: '1fr 1fr',
      gap: '0.3rem',
      fontSize: '0.78rem',
      color: '#64748b',
      marginBottom: '0.5rem'
    }
  }, /*#__PURE__*/React.createElement("span", null, "Trigger: ", /*#__PURE__*/React.createElement("strong", {
    style: {
      color: '#0f172a'
    }
  }, timingInfo.trigger_severity), "/100"), /*#__PURE__*/React.createElement("span", null, "Swim Fit: ", /*#__PURE__*/React.createElement("strong", {
    style: {
      color: '#0f172a'
    }
  }, timingInfo.swim_lane_fit), "/100"), /*#__PURE__*/React.createElement("span", null, "Engagement: ", /*#__PURE__*/React.createElement("strong", {
    style: {
      color: '#0f172a'
    }
  }, timingInfo.engagement_score), "/100"), /*#__PURE__*/React.createElement("span", null, "Momentum: ", /*#__PURE__*/React.createElement("strong", {
    style: {
      color: '#0f172a'
    }
  }, Math.round(timingInfo.market_momentum_score)), "/100"), /*#__PURE__*/React.createElement("span", null, "Freshness: ", /*#__PURE__*/React.createElement("strong", {
    style: {
      color: '#0f172a'
    }
  }, timingInfo.freshness_score), "/100"), /*#__PURE__*/React.createElement("span", null, "Total: ", /*#__PURE__*/React.createElement("strong", {
    style: {
      color: (timingColors[timingInfo.timing_label] || timingColors.Watch).color
    }
  }, Math.round(timingInfo.call_timing_score)), "/100")), timingInfo.reasons && timingInfo.reasons.length > 0 && /*#__PURE__*/React.createElement("div", null, timingInfo.reasons.map((r, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      fontSize: '0.75rem',
      color: '#334155',
      marginBottom: '0.15rem'
    }
  }, "\u2022 ", r)))), triggers.length > 0 && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement(SectionLabel, {
    className: "mb-1.5"
  }, brokerLabel('Insurance Triggers', user?.role)), /*#__PURE__*/React.createElement("div", {
    className: "flex flex-wrap gap-1.5"
  }, triggers.map((trigger, idx) => /*#__PURE__*/React.createElement(SignalPill, {
    key: idx,
    label: trigger,
    glow: score >= 90
  })))), (unitBand || competitiveDifficulty) && /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.75rem',
      flexWrap: 'wrap',
      alignItems: 'center'
    }
  }, unitBand && /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.75rem',
      padding: '0.2rem 0.6rem',
      borderRadius: '6px',
      background: 'rgba(6,182,212,0.1)',
      color: '#67e8f9',
      border: '1px solid rgba(6,182,212,0.25)'
    }
  }, unitBand, " units"), competitiveDifficulty && /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '0.35rem'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: '0.5rem',
      height: '0.5rem',
      borderRadius: '50%',
      background: compDotColor,
      display: 'inline-block'
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.75rem',
      color: '#64748b'
    }
  }, user?.role === 'broker' ? `${competitiveDifficulty} Complexity` : `${competitiveDifficulty} Competition`))), /*#__PURE__*/React.createElement("div", {
    style: styles.details
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#64748b'
    }
  }, "Project:"), " ", prospect.projectName), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#64748b'
    }
  }, "Status:"), " ", prospect.projectStatus), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#64748b'
    }
  }, "Size:"), " ", prospect.units), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#64748b'
    }
  }, "TIV:"), " ", prospect.tiv)), prospect.whyNow && /*#__PURE__*/React.createElement("div", {
    style: styles.whyNow
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '0.7rem',
      color: '#ef4444',
      fontWeight: 600,
      marginBottom: '0.3rem',
      textTransform: 'uppercase',
      letterSpacing: '0.05em'
    }
  }, "Why Call Now"), /*#__PURE__*/React.createElement("p", {
    className: `why-now-text${whyNowExpanded ? ' expanded' : ''}`,
    style: {
      color: '#334155',
      fontSize: '0.875rem',
      margin: 0,
      lineHeight: '1.5'
    }
  }, prospect.whyNow), /*#__PURE__*/React.createElement("span", {
    onClick: () => setWhyNowExpanded(!whyNowExpanded),
    style: {
      fontSize: '0.75rem',
      color: '#ef4444',
      cursor: 'pointer',
      marginTop: '0.25rem',
      display: 'inline-block',
      opacity: 0.8
    }
  }, whyNowExpanded ? 'Collapse' : 'Expand')), prospect.signals && prospect.signals.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: styles.signals
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '0.7rem',
      color: '#06b6d4',
      fontWeight: 600,
      marginBottom: '0.3rem',
      textTransform: 'uppercase',
      letterSpacing: '0.05em'
    }
  }, "Signals"), /*#__PURE__*/React.createElement("ul", {
    style: styles.signalList
  }, prospect.signals.map((signal, idx) => /*#__PURE__*/React.createElement("li", {
    key: idx,
    style: styles.signalItem
  }, "\u25B8 ", signal)))), showGovSignals && govActivity.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '0.75rem',
      background: 'rgba(245,158,11,0.04)',
      border: '1px solid rgba(245,158,11,0.15)',
      borderRadius: '8px'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '0.65rem',
      color: '#f59e0b',
      fontWeight: 600,
      marginBottom: '0.5rem',
      textTransform: 'uppercase',
      letterSpacing: '0.05em'
    }
  }, "Government Activity (", govActivity.length, ")"), govActivity.map((sig, idx) => /*#__PURE__*/React.createElement("div", {
    key: idx,
    style: {
      marginBottom: '0.5rem',
      paddingBottom: '0.5rem',
      borderBottom: idx < govActivity.length - 1 ? '1px solid rgba(245,158,11,0.1)' : 'none'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '0.5rem',
      marginBottom: '0.2rem'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.65rem',
      padding: '0.1rem 0.4rem',
      borderRadius: '4px',
      background: sig.signal_type === 'permit' ? 'rgba(6,182,212,0.15)' : sig.signal_type === 'zoning' ? 'rgba(139,92,246,0.15)' : sig.signal_type === 'deed' ? 'rgba(20,184,166,0.1)' : sig.signal_type === 'mortgage' ? 'rgba(239,68,68,0.15)' : 'rgba(148,163,184,0.15)',
      color: sig.signal_type === 'permit' ? '#67e8f9' : sig.signal_type === 'zoning' ? '#c4b5fd' : sig.signal_type === 'deed' ? '#0d9488' : sig.signal_type === 'mortgage' ? '#fca5a5' : '#94a3b8',
      fontWeight: 600,
      textTransform: 'uppercase'
    }
  }, sig.signal_type), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.7rem',
      color: '#64748b'
    }
  }, sig.filing_date), sig.amount && /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.7rem',
      color: '#fcd34d'
    }
  }, "$", typeof sig.amount === 'number' ? sig.amount.toLocaleString() : sig.amount)), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '0.78rem',
      color: '#334155',
      lineHeight: '1.4'
    }
  }, sig.summary), sig.source_url && /*#__PURE__*/React.createElement("a", {
    href: sig.source_url,
    target: "_blank",
    rel: "noopener noreferrer",
    style: {
      fontSize: '0.7rem',
      color: '#60a5fa',
      textDecoration: 'none'
    }
  }, sig.source_name || 'Source', " \u2197")))), showEmailOptions && /*#__PURE__*/React.createElement("div", {
    style: styles.emailOptions
  }, /*#__PURE__*/React.createElement("div", {
    style: styles.emailOptionRow
  }, /*#__PURE__*/React.createElement("label", {
    style: styles.emailOptionLabel
  }, "Purpose"), /*#__PURE__*/React.createElement("select", {
    style: styles.select,
    value: emailPurpose,
    onChange: e => setEmailPurpose(e.target.value)
  }, /*#__PURE__*/React.createElement("option", {
    value: "cold_outreach"
  }, "Cold Outreach"), /*#__PURE__*/React.createElement("option", {
    value: "follow_up"
  }, "Follow Up"), /*#__PURE__*/React.createElement("option", {
    value: "event_invite"
  }, "Event Invite"), /*#__PURE__*/React.createElement("option", {
    value: "post_event_follow_up"
  }, "Post-Event Follow Up"), /*#__PURE__*/React.createElement("option", {
    value: "referral_intro"
  }, "Referral Intro"), /*#__PURE__*/React.createElement("option", {
    value: "renewal_quote_follow_up"
  }, "Renewal/Quote Follow Up"))), /*#__PURE__*/React.createElement("div", {
    style: styles.emailOptionRow
  }, /*#__PURE__*/React.createElement("label", {
    style: styles.emailOptionLabel
  }, "Tone"), /*#__PURE__*/React.createElement("select", {
    style: styles.select,
    value: tone,
    onChange: e => setTone(e.target.value)
  }, /*#__PURE__*/React.createElement("option", {
    value: "professional_direct"
  }, "Professional Direct"), /*#__PURE__*/React.createElement("option", {
    value: "strategic_exec"
  }, "Strategic Exec"), /*#__PURE__*/React.createElement("option", {
    value: "conversational"
  }, "Conversational"), /*#__PURE__*/React.createElement("option", {
    value: "friendly"
  }, "Friendly"), /*#__PURE__*/React.createElement("option", {
    value: "urgent_light"
  }, "Urgent (Light)"))), /*#__PURE__*/React.createElement("div", {
    style: styles.emailOptionRow
  }, /*#__PURE__*/React.createElement("label", {
    style: styles.emailOptionLabel
  }, "CTA / Offer"), /*#__PURE__*/React.createElement("select", {
    style: styles.select,
    value: offer,
    onChange: e => setOffer(e.target.value)
  }, /*#__PURE__*/React.createElement("option", {
    value: "15_min_call"
  }, "15-Min Call"), /*#__PURE__*/React.createElement("option", {
    value: "share_resource"
  }, "Share a Resource"), /*#__PURE__*/React.createElement("option", {
    value: "quick_question"
  }, "Quick Question"))), /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: {
      ...styles.btnPrimary,
      fontSize: '0.85rem'
    },
    onClick: handleGenerate
  }, "Generate Now")), /*#__PURE__*/React.createElement("div", {
    style: {
      ...styles.cardActions,
      justifyContent: 'flex-end'
    }
  }, user?.role === 'broker' ? /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: {
      ...styles.actionBtn,
      borderColor: '#f59e0b',
      color: '#fcd34d'
    },
    onClick: async () => {
      try {
        const res = await fetch(`${API_BASE}/api/broker/saved`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            prospect_id: prospect.id,
            company: prospect.company
          })
        });
        const d = await res.json();
        alert(d.success ? 'Saved to Deal Board!' : d.message || 'Failed');
      } catch (e) {
        alert('Error saving: ' + e.message);
      }
    }
  }, "Save to Deal Board"), /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: styles.actionBtn,
    onClick: () => setShowEmailOptions(!showEmailOptions)
  }, showEmailOptions ? 'Cancel' : 'Generate Email'), validLinkedIn(prospect.linkedin) ? /*#__PURE__*/React.createElement("a", {
    href: normalizeLinkedIn(prospect.linkedin),
    target: "_blank",
    rel: "noopener noreferrer",
    style: {
      ...styles.actionBtn,
      textDecoration: 'none',
      textAlign: 'center',
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center'
    }
  }, "LinkedIn DM") : /*#__PURE__*/React.createElement("button", {
    className: "action-btn btn-disabled",
    style: styles.actionBtn,
    disabled: true
  }, "LinkedIn DM")) : /*#__PURE__*/React.createElement(React.Fragment, null, !crmInfo ? /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: {
      ...styles.actionBtn,
      borderColor: '#14b8a6',
      color: '#14b8a6'
    },
    onClick: () => onSaveToPipeline(prospect)
  }, user?.role === 'admin' ? 'Save to Pipeline' : 'Save to My Leads') : /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: styles.actionBtn,
    onClick: () => onLogTouchpoint(crmInfo.lead_id, prospect.company)
  }, "Log Touchpoint"), /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: styles.actionBtn,
    onClick: () => setShowEmailOptions(!showEmailOptions)
  }, showEmailOptions ? 'Cancel' : 'Generate Email'), validLinkedIn(prospect.linkedin) ? /*#__PURE__*/React.createElement("a", {
    href: normalizeLinkedIn(prospect.linkedin),
    target: "_blank",
    rel: "noopener noreferrer",
    style: {
      ...styles.actionBtn,
      textDecoration: 'none',
      textAlign: 'center',
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center'
    }
  }, "LinkedIn DM") : /*#__PURE__*/React.createElement("button", {
    className: "action-btn btn-disabled",
    style: styles.actionBtn,
    disabled: true
  }, "LinkedIn DM"), /*#__PURE__*/React.createElement("button", {
    className: "action-btn btn-disabled",
    style: styles.actionBtn,
    disabled: true
  }, "Call Angle"), /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: styles.actionBtn,
    onClick: () => onDelete(prospect.id)
  }, "Delete"))));
}
function EmailModal({
  email,
  prospect,
  onClose
}) {
  const subject = email.subject || '';
  const body = email.body || email || '';
  const fullText = subject ? `Subject: ${subject}\n\n${body}` : body;
  const copyEmail = () => {
    navigator.clipboard.writeText(fullText);
    alert('Email copied to clipboard!');
  };
  const copySubject = () => {
    navigator.clipboard.writeText(subject);
    alert('Subject line copied!');
  };
  return /*#__PURE__*/React.createElement("div", {
    style: styles.modalOverlay,
    onClick: onClose
  }, /*#__PURE__*/React.createElement("div", {
    style: styles.modal,
    onClick: e => e.stopPropagation()
  }, /*#__PURE__*/React.createElement("div", {
    style: styles.modalHeader
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontSize: '1.2rem'
    }
  }, "Email for ", prospect.company), /*#__PURE__*/React.createElement("button", {
    style: styles.closeBtn,
    onClick: onClose
  }, "\u2715")), subject && /*#__PURE__*/React.createElement("div", {
    style: styles.subjectRow
  }, /*#__PURE__*/React.createElement("span", {
    style: styles.subjectLabel
  }, "SUBJECT:"), /*#__PURE__*/React.createElement("span", {
    style: styles.subjectText
  }, subject), /*#__PURE__*/React.createElement("button", {
    style: styles.copySmall,
    onClick: copySubject,
    title: "Copy subject"
  }, "\uD83D\uDCCB")), /*#__PURE__*/React.createElement("div", {
    style: styles.emailBody
  }, body.split('\n').map((line, i) => /*#__PURE__*/React.createElement(React.Fragment, {
    key: i
  }, line, /*#__PURE__*/React.createElement("br", null)))), /*#__PURE__*/React.createElement("div", {
    style: styles.modalActions
  }, /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: styles.btnPrimary,
    onClick: copyEmail
  }, "Copy Full Email"), /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: styles.btn,
    onClick: onClose
  }, "Close"))));
}
function DailyDiscovery() {
  const [config, setConfig] = useState(null);
  const [latestRun, setLatestRun] = useState(null);
  const [selectedRun, setSelectedRun] = useState(null);
  const [history, setHistory] = useState([]);
  const [running, setRunning] = useState(false);
  const [status, setStatus] = useState('');
  const [showDigest, setShowDigest] = useState(false);
  const [sourceRefresh, setSourceRefresh] = useState({});
  const [sourceFilters, setSourceFilters] = useState({
    filing: true,
    permit: true,
    news: true,
    press_release: true
  });
  useEffect(() => {
    loadConfig();
    loadLatest();
    loadHistory();
    checkStatus();
    loadSourceRefresh();
  }, []);
  useEffect(() => {
    if (!running) return;
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/api/discovery/status`);
        const data = await res.json();
        if (!data.running) {
          setRunning(false);
          setStatus('Discovery complete!');
          loadLatest();
          loadHistory();
          loadSourceRefresh();
          setTimeout(() => setStatus(''), 5000);
        }
      } catch (e) {
        console.error('Poll error:', e);
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [running]);
  const loadConfig = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/discovery/config`);
      const data = await res.json();
      if (data.success) setConfig(data.config);
    } catch (e) {
      console.error('Config load error:', e);
    }
  };
  const loadLatest = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/discovery/latest`);
      const data = await res.json();
      if (data.success && data.run) {
        setLatestRun(data.run);
        setSelectedRun(data.run);
      }
    } catch (e) {
      console.error('Latest load error:', e);
    }
  };
  const loadHistory = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/discovery/history`);
      const data = await res.json();
      if (data.success) setHistory(data.runs);
    } catch (e) {
      console.error('History load error:', e);
    }
  };
  const checkStatus = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/discovery/status`);
      const data = await res.json();
      if (data.running) {
        setRunning(true);
        setStatus('Discovery is running...');
      }
    } catch (e) {
      console.error('Status check error:', e);
    }
  };
  const loadSourceRefresh = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/discovery/source-refresh`);
      const data = await res.json();
      if (data.success) setSourceRefresh(data.sources || {});
    } catch (e) {
      console.error('Source refresh load error:', e);
    }
  };
  const triggerRun = async () => {
    try {
      setRunning(true);
      setStatus('Starting discovery run — scanning EDGAR, press releases, permits, and news...');
      const res = await fetch(`${API_BASE}/api/discovery/run`, {
        method: 'POST'
      });
      const data = await res.json();
      if (!data.success) {
        setRunning(false);
        setStatus(data.message);
        setTimeout(() => setStatus(''), 5000);
      } else {
        setStatus('Discovery is running — scanning multiple sources...');
      }
    } catch (e) {
      setRunning(false);
      setStatus('Failed to start discovery.');
      setTimeout(() => setStatus(''), 5000);
    }
  };
  const loadRunDetail = async runId => {
    try {
      const res = await fetch(`${API_BASE}/api/discovery/run/${runId}`);
      const data = await res.json();
      if (data.success) setSelectedRun(data.run);
    } catch (e) {
      console.error('Run detail error:', e);
    }
  };
  const toggleSourceFilter = source => {
    setSourceFilters(prev => ({
      ...prev,
      [source]: !prev[source]
    }));
  };
  const filterSignals = signals => {
    if (!signals) return [];
    return signals.filter(s => {
      const st = s.source_type || 'news';
      return sourceFilters[st] !== false;
    });
  };
  const formatRefreshTime = isoStr => {
    if (!isoStr) return 'Never';
    try {
      return new Date(isoStr).toLocaleString();
    } catch (e) {
      return 'Unknown';
    }
  };
  if (!config) return /*#__PURE__*/React.createElement("div", {
    style: ds.loadingMsg
  }, "Loading configuration...");
  const results = selectedRun?.results || {};
  const adapterStats = selectedRun?.adapter_stats || {};
  const sourceTypeConfig = {
    filing: {
      label: 'SEC Filing',
      color: '#a78bfa',
      icon: 'F'
    },
    permit: {
      label: 'Permit',
      color: '#fbbf24',
      icon: 'P'
    },
    news: {
      label: 'News',
      color: '#3b82f6',
      icon: 'N'
    },
    press_release: {
      label: 'Press Release',
      color: '#fb7185',
      icon: 'R'
    }
  };
  const confidenceConfig = {
    high: {
      color: '#14b8a6',
      label: 'HIGH'
    },
    medium: {
      color: '#fbbf24',
      label: 'MED'
    },
    low: {
      color: '#64748b',
      label: 'LOW'
    }
  };
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      ...ds.configPanel,
      borderRadius: '1rem'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: ds.configHeader
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-2"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-slate-400"
  }, SECTION_ICONS.discovery), /*#__PURE__*/React.createElement("h2", {
    style: ds.sectionTitle
  }, "Daily Discovery")), /*#__PURE__*/React.createElement("div", {
    style: ds.schedule
  }, "Runs daily at ", config.schedule_hour, ":", String(config.schedule_minute).padStart(2, '0'), " AM PT")), /*#__PURE__*/React.createElement("div", {
    style: ds.configGrid
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: ds.configLabel
  }, "Target Cities"), /*#__PURE__*/React.createElement("div", {
    style: ds.chipGroup
  }, config.cities.map((c, i) => /*#__PURE__*/React.createElement("span", {
    key: i,
    style: ds.chip
  }, c.city, ", ", c.state)))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: ds.configLabel
  }, "ICP Keywords"), /*#__PURE__*/React.createElement("div", {
    style: ds.chipGroup
  }, config.icp_keywords.map((kw, i) => /*#__PURE__*/React.createElement("span", {
    key: i,
    style: ds.keywordChip
  }, kw)))), config.monitor_operators && config.monitor_operators.length > 0 && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: ds.configLabel
  }, "Monitored Operators (EDGAR)"), /*#__PURE__*/React.createElement("div", {
    style: ds.chipGroup
  }, config.monitor_operators.map((op, i) => /*#__PURE__*/React.createElement("span", {
    key: i,
    style: ds.operatorChip
  }, op)))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: ds.configLabel
  }, "Settings"), /*#__PURE__*/React.createElement("div", {
    style: ds.filterRow
  }, /*#__PURE__*/React.createElement("span", {
    style: ds.filterItem
  }, "Max ", config.max_signals_per_day || 10, " signals/day"), /*#__PURE__*/React.createElement("span", {
    style: ds.filterItem
  }, "Delivery: ", config.delivery_method))))), Object.keys(sourceRefresh).length > 0 && /*#__PURE__*/React.createElement("div", {
    style: ds.sourceRefreshBar
  }, /*#__PURE__*/React.createElement("div", {
    style: ds.configLabel
  }, "Last Refreshed"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '1.5rem',
      flexWrap: 'wrap',
      marginTop: '0.4rem'
    }
  }, Object.entries(sourceTypeConfig).map(([key, cfg]) => {
    const info = sourceRefresh[key];
    return /*#__PURE__*/React.createElement("span", {
      key: key,
      style: {
        fontSize: '0.8rem',
        color: cfg.color
      }
    }, "[", cfg.icon, "] ", cfg.label, ": ", info ? formatRefreshTime(info.last_refreshed_at) : 'Never', info && info.items_found > 0 ? ` (${info.items_found})` : '');
  }))), /*#__PURE__*/React.createElement("div", {
    style: ds.actionBar
  }, /*#__PURE__*/React.createElement("button", {
    style: {
      ...styles.btnPrimary,
      ...(running ? {
        opacity: 0.5,
        cursor: 'not-allowed'
      } : {}),
      fontSize: '1rem',
      padding: '0.85rem 2rem'
    },
    onClick: triggerRun,
    disabled: running
  }, running ? 'Running Discovery...' : 'Run Discovery Now'), selectedRun && /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: {
      ...styles.btn,
      fontSize: '0.9rem'
    },
    onClick: () => setShowDigest(!showDigest)
  }, showDigest ? 'Show Cards' : 'Show Digest'), latestRun && /*#__PURE__*/React.createElement("span", {
    style: ds.lastRun
  }, "Last run: ", new Date(latestRun.run_at).toLocaleString(), " \xB7 ", latestRun.total_new, " new")), selectedRun && !showDigest && /*#__PURE__*/React.createElement("div", {
    style: ds.filterBar
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.8rem',
      color: '#64748b',
      marginRight: '0.75rem'
    }
  }, "Filter:"), Object.entries(sourceTypeConfig).map(([key, cfg]) => /*#__PURE__*/React.createElement("button", {
    key: key,
    className: "filter-pill",
    onClick: () => toggleSourceFilter(key),
    style: {
      ...ds.filterToggle,
      borderColor: sourceFilters[key] ? cfg.color : '#e2e8f0',
      color: sourceFilters[key] ? cfg.color : '#94a3b8',
      background: sourceFilters[key] ? `${cfg.color}15` : 'transparent'
    }
  }, "[", cfg.icon, "] ", cfg.label))), selectedRun && adapterStats && Object.keys(adapterStats).length > 0 && !showDigest && /*#__PURE__*/React.createElement("div", {
    style: ds.adapterStatsBar
  }, Object.entries(adapterStats).map(([key, stat]) => /*#__PURE__*/React.createElement("span", {
    key: key,
    style: {
      fontSize: '0.8rem',
      color: stat.status === 'ok' ? '#34d399' : stat.status === 'skipped' ? '#94a3b8' : '#ef4444',
      padding: '0.25rem 0.6rem',
      borderRadius: '12px',
      border: `1px solid ${stat.status === 'ok' ? 'rgba(16,185,129,0.3)' : 'rgba(148,163,184,0.3)'}`
    }
  }, "[", (sourceTypeConfig[key] || {
    icon: '?'
  }).icon, "] ", key, ": ", stat.items, " items (", stat.status, ")"))), status && /*#__PURE__*/React.createElement("div", {
    style: styles.searchStatus
  }, /*#__PURE__*/React.createElement("p", null, status)), running && /*#__PURE__*/React.createElement("div", {
    style: styles.loading
  }, /*#__PURE__*/React.createElement("div", {
    style: styles.loadingText
  }, "Scanning EDGAR, press releases, permits, and news...")), showDigest && selectedRun?.digest && /*#__PURE__*/React.createElement("div", {
    style: ds.digestBox
  }, /*#__PURE__*/React.createElement("pre", {
    style: ds.digestText
  }, selectedRun.digest)), !showDigest && selectedRun && /*#__PURE__*/React.createElement("div", null, Object.entries(results).map(([location, data]) => {
    const filtered = filterSignals(data.signals);
    return /*#__PURE__*/React.createElement("div", {
      key: location,
      style: ds.citySection
    }, /*#__PURE__*/React.createElement("div", {
      style: ds.cityHeader
    }, /*#__PURE__*/React.createElement("h3", {
      style: ds.cityTitle
    }, location), data.new_count !== undefined && /*#__PURE__*/React.createElement("span", {
      style: ds.newBadge
    }, data.new_count, " new")), data.error && /*#__PURE__*/React.createElement("p", {
      style: ds.errorText
    }, "Error: ", data.error), !data.error && filtered.length === 0 && /*#__PURE__*/React.createElement("p", {
      style: ds.noResults
    }, "No new activity signals found"), /*#__PURE__*/React.createElement("div", {
      style: ds.signalGrid
    }, filtered.map((s, i) => {
      const typeLabel = (s.signal_type || 'other').replace(/_/g, ' ');
      const typeColor = {
        'new build': '#34d399',
        'under construction': '#3b82f6',
        'permit rezoning': '#fbbf24',
        'acquisition': '#ef4444',
        'sale': '#fb7185',
        'recapitalization': '#a78bfa',
        'financing': '#a78bfa'
      }[typeLabel] || '#94a3b8';
      const srcCfg = sourceTypeConfig[s.source_type] || sourceTypeConfig.news;
      const confCfg = confidenceConfig[s.confidence] || confidenceConfig.medium;
      return /*#__PURE__*/React.createElement("div", {
        key: i,
        style: ds.signalCard
      }, /*#__PURE__*/React.createElement("div", {
        style: ds.signalCardHeader
      }, /*#__PURE__*/React.createElement("span", {
        style: {
          ...ds.signalTypeBadge,
          borderColor: typeColor,
          color: typeColor
        }
      }, typeLabel), /*#__PURE__*/React.createElement("span", {
        style: {
          ...ds.sourceTypeBadge,
          borderColor: srcCfg.color,
          color: srcCfg.color
        }
      }, "[", srcCfg.icon, "] ", srcCfg.label), /*#__PURE__*/React.createElement("span", {
        style: {
          ...ds.confidenceBadge,
          color: confCfg.color
        }
      }, confCfg.label)), s.entity_name && /*#__PURE__*/React.createElement("div", {
        style: ds.entityName
      }, s.entity_name), /*#__PURE__*/React.createElement("div", {
        style: ds.signalTitle
      }, s.title), s.summary && /*#__PURE__*/React.createElement("div", {
        style: ds.signalSummary
      }, s.summary), /*#__PURE__*/React.createElement("div", {
        style: ds.signalMeta
      }, s.source_name && /*#__PURE__*/React.createElement("span", {
        style: ds.signalSource
      }, s.source_name), s.published_at && /*#__PURE__*/React.createElement("span", {
        style: ds.signalDate
      }, s.published_at)), s.url && /*#__PURE__*/React.createElement("a", {
        href: s.url,
        target: "_blank",
        rel: "noopener noreferrer",
        style: ds.signalLink
      }, "Read source"));
    })));
  })), !selectedRun && !running && /*#__PURE__*/React.createElement("div", {
    style: styles.empty
  }, /*#__PURE__*/React.createElement("h2", {
    style: styles.emptyTitle
  }, "No discovery runs yet"), /*#__PURE__*/React.createElement("p", {
    style: styles.emptyText
  }, "Click \"Run Discovery Now\" to scan multiple sources for BTR activity signals"), /*#__PURE__*/React.createElement("p", {
    style: styles.emptySubtext
  }, "Searches SEC EDGAR filings, press releases, city permits, and CRE news")), history.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: ds.historySection
  }, /*#__PURE__*/React.createElement("h3", {
    style: ds.sectionTitle
  }, "Run History"), /*#__PURE__*/React.createElement("div", {
    style: ds.historyList
  }, history.map(run => /*#__PURE__*/React.createElement("div", {
    key: run.id,
    style: {
      ...ds.historyItem,
      ...(selectedRun?.id === run.id ? ds.historyItemActive : {})
    },
    onClick: () => loadRunDetail(run.id)
  }, /*#__PURE__*/React.createElement("span", {
    style: ds.historyDate
  }, new Date(run.run_at).toLocaleString()), /*#__PURE__*/React.createElement("span", {
    style: ds.historyStats
  }, run.total_new, " new \xB7 ", run.city_count, " cities"), /*#__PURE__*/React.createElement("span", {
    style: {
      ...ds.historyStatus,
      color: run.status === 'completed' ? '#34d399' : '#fbbf24'
    }
  }, run.status))))));
}

// ======= STATEWIDE DISCOVERY =======
const STATEWIDE_STATES = [{
  abbr: 'TX',
  name: 'Texas'
}, {
  abbr: 'AZ',
  name: 'Arizona'
}, {
  abbr: 'GA',
  name: 'Georgia'
}, {
  abbr: 'NC',
  name: 'North Carolina'
}, {
  abbr: 'FL',
  name: 'Florida'
}];
const EVENT_TYPE_COLORS = {
  'acquisition': {
    bg: 'rgba(239,68,68,0.15)',
    color: '#f87171'
  },
  'sale': {
    bg: 'rgba(236,72,153,0.15)',
    color: '#f9a8d4'
  },
  'groundbreaking': {
    bg: 'rgba(20,184,166,0.1)',
    color: '#14b8a6'
  },
  'permit': {
    bg: 'rgba(245,158,11,0.15)',
    color: '#fcd34d'
  },
  'rezoning': {
    bg: 'rgba(245,158,11,0.15)',
    color: '#fcd34d'
  },
  'financing': {
    bg: 'rgba(168,85,247,0.15)',
    color: '#c4b5fd'
  },
  'JV': {
    bg: 'rgba(168,85,247,0.15)',
    color: '#c4b5fd'
  },
  'construction': {
    bg: 'rgba(6,182,212,0.15)',
    color: '#67e8f9'
  },
  'other': {
    bg: 'rgba(148,163,184,0.15)',
    color: '#64748b'
  }
};
function StatewideDiscovery() {
  const [rankings, setRankings] = useState([]);
  const [selectedState, setSelectedState] = useState(null);
  const [stateData, setStateData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [scanningState, setScanningState] = useState(null);
  const [status, setStatus] = useState('');
  useEffect(() => {
    loadRankings();
  }, []);
  const loadRankings = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/discovery/state-rankings`);
      const data = await res.json();
      if (data.success) setRankings(data.rankings);
    } catch (e) {
      console.error('Rankings load error:', e);
    }
  };
  const scanState = async stateAbbr => {
    setScanningState(stateAbbr);
    setStatus(`Scanning ${stateAbbr}...`);
    try {
      const res = await fetch(`${API_BASE}/api/discovery/statewide/run`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          state: stateAbbr
        })
      });
      const data = await res.json();
      if (data.success) {
        setStatus(`Found ${data.count} signals in ${stateAbbr}`);
        loadRankings();
        if (selectedState === stateAbbr) loadStateSummary(stateAbbr);
      } else {
        setStatus(data.message || 'Scan failed');
      }
    } catch (e) {
      setStatus('Scan error: ' + e.message);
    }
    setScanningState(null);
    setTimeout(() => setStatus(''), 5000);
  };
  const scanAllStates = async () => {
    for (const s of STATEWIDE_STATES) {
      await scanState(s.abbr);
    }
  };
  const loadStateSummary = async stateAbbr => {
    setSelectedState(stateAbbr);
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/discovery/state-summary?state=${stateAbbr}`);
      const data = await res.json();
      if (data.success) setStateData(data);
    } catch (e) {
      console.error('State summary error:', e);
    }
    setLoading(false);
  };

  // Compute intensity for heat grid
  const maxScore = Math.max(1, ...rankings.map(r => r.state_activity_score));
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement(SectionHeader, {
    title: "Statewide Intelligence",
    subtitle: "BTR activity scanning across TX, AZ, GA, NC, FL",
    icon: "rankings"
  }, /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: {
      ...styles.btnPrimary,
      fontSize: '0.9rem',
      padding: '0.65rem 1.5rem',
      ...(scanningState ? {
        opacity: 0.5,
        cursor: 'not-allowed'
      } : {})
    },
    onClick: scanAllStates,
    disabled: !!scanningState
  }, scanningState ? `Scanning ${scanningState}...` : 'Scan All States')), /*#__PURE__*/React.createElement(Divider, null), status && /*#__PURE__*/React.createElement("div", {
    style: styles.searchStatus
  }, /*#__PURE__*/React.createElement("p", null, status)), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fill,minmax(240px,1fr))',
      gap: '1rem',
      marginBottom: '2rem'
    }
  }, STATEWIDE_STATES.map(s => {
    const ranking = rankings.find(r => r.state === s.abbr) || {};
    const score = ranking.state_activity_score || 0;
    const intensity = maxScore > 0 ? score / maxScore : 0;
    const isSelected = selectedState === s.abbr;
    const borderColor = intensity > 0.7 ? '#34d399' : intensity > 0.4 ? '#fbbf24' : intensity > 0 ? '#3b82f6' : '#e2e8f0';
    const glowColor = intensity > 0.7 ? 'rgba(16,185,129,0.2)' : intensity > 0.4 ? 'rgba(251,191,36,0.15)' : 'transparent';
    return /*#__PURE__*/React.createElement("div", {
      key: s.abbr,
      onClick: () => loadStateSummary(s.abbr),
      style: {
        background: isSelected ? '#F1F5F9' : '#1e293b',
        border: `2px solid ${isSelected ? '#34d399' : borderColor}`,
        borderRadius: '12px',
        padding: '1.25rem',
        cursor: 'pointer',
        boxShadow: isSelected ? '0 0 20px rgba(20,184,166,0.1)' : `0 0 12px ${glowColor}`,
        transition: 'all 0.2s'
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '0.75rem'
      }
    }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "'Orbitron',sans-serif",
        fontSize: '1.6rem',
        fontWeight: 900,
        color: '#0f172a'
      }
    }, s.abbr), /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: '0.8rem',
        color: '#64748b'
      }
    }, s.name)), /*#__PURE__*/React.createElement("div", {
      style: {
        width: '3rem',
        height: '3rem',
        borderRadius: '50%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        border: `2px solid ${borderColor}`,
        fontFamily: "'JetBrains Mono',monospace",
        fontSize: '0.9rem',
        fontWeight: 700,
        color: intensity > 0.4 ? '#f1f5f9' : '#64748b',
        boxShadow: intensity > 0.5 ? `0 0 10px ${glowColor}` : 'none'
      }
    }, score)), /*#__PURE__*/React.createElement("div", {
      style: {
        display: 'flex',
        gap: '1rem',
        fontSize: '0.8rem',
        color: '#64748b'
      }
    }, /*#__PURE__*/React.createElement("span", null, ranking.total_signals || 0, " signals"), /*#__PURE__*/React.createElement("span", null, ranking.capital_events_count || 0, " capital"), /*#__PURE__*/React.createElement("span", null, ranking.construction_signals_count || 0, " construction")), ranking.top_cities && ranking.top_cities.length > 0 && /*#__PURE__*/React.createElement("div", {
      style: {
        marginTop: '0.5rem',
        display: 'flex',
        gap: '0.4rem',
        flexWrap: 'wrap'
      }
    }, ranking.top_cities.map((tc, i) => /*#__PURE__*/React.createElement("span", {
      key: i,
      style: {
        fontSize: '0.7rem',
        padding: '0.15rem 0.45rem',
        borderRadius: '4px',
        background: 'rgba(16,185,129,0.1)',
        color: '#0d9488'
      }
    }, tc.city))), /*#__PURE__*/React.createElement("button", {
      className: "action-btn",
      style: {
        ...styles.actionBtn,
        marginTop: '0.75rem',
        fontSize: '0.75rem',
        ...(scanningState === s.abbr ? {
          opacity: 0.5
        } : {})
      },
      onClick: e => {
        e.stopPropagation();
        scanState(s.abbr);
      },
      disabled: !!scanningState
    }, scanningState === s.abbr ? 'Scanning...' : 'Scan'));
  })), selectedState && loading && /*#__PURE__*/React.createElement("div", {
    style: styles.loading
  }, /*#__PURE__*/React.createElement("div", {
    style: styles.loadingText
  }, "Loading ", selectedState, "...")), selectedState && !loading && stateData && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "'Orbitron',sans-serif",
      fontSize: '1.2rem',
      fontWeight: 700,
      color: '#3b82f6',
      marginBottom: '1rem'
    }
  }, STATEWIDE_STATES.find(s => s.abbr === selectedState)?.name, " \u2014 Detail"), stateData.top_cities_7d && stateData.top_cities_7d.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      marginBottom: '1.5rem'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '0.75rem',
      color: '#64748b',
      textTransform: 'uppercase',
      fontWeight: 600,
      letterSpacing: '0.05em',
      marginBottom: '0.5rem'
    }
  }, "Top Cities (7-Day Activity)"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.75rem',
      flexWrap: 'wrap'
    }
  }, stateData.top_cities_7d.map((tc, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      borderRadius: '10px',
      padding: '0.85rem 1.25rem',
      minWidth: '160px'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "'Orbitron',sans-serif",
      fontSize: '1rem',
      fontWeight: 700,
      color: '#0f172a'
    }
  }, tc.city), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.75rem',
      marginTop: '0.3rem',
      fontSize: '0.8rem',
      color: '#64748b'
    }
  }, /*#__PURE__*/React.createElement("span", null, "Score: ", /*#__PURE__*/React.createElement("b", {
    style: {
      color: '#14b8a6'
    }
  }, tc.activity_score)), /*#__PURE__*/React.createElement("span", null, tc.signals_count, " signals")), tc.dominant_event_types && /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.3rem',
      marginTop: '0.4rem',
      flexWrap: 'wrap'
    }
  }, tc.dominant_event_types.map((et, j) => {
    const ec = EVENT_TYPE_COLORS[et] || EVENT_TYPE_COLORS.other;
    return /*#__PURE__*/React.createElement("span", {
      key: j,
      style: {
        fontSize: '0.65rem',
        padding: '0.1rem 0.4rem',
        borderRadius: '4px',
        background: ec.bg,
        color: ec.color
      }
    }, et);
  })))))), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '0.75rem',
      color: '#64748b',
      textTransform: 'uppercase',
      fontWeight: 600,
      letterSpacing: '0.05em',
      marginBottom: '0.75rem'
    }
  }, "All Signals (", stateData.total_signals || 0, ")"), (!stateData.items || stateData.items.length === 0) && /*#__PURE__*/React.createElement("div", {
    style: styles.empty
  }, /*#__PURE__*/React.createElement("p", {
    style: styles.emptyText
  }, "No signals found. Click \"Scan\" on the state tile above to search.")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fill,minmax(360px,1fr))',
      gap: '0.75rem'
    }
  }, (stateData.items || []).map((item, i) => {
    const ec = EVENT_TYPE_COLORS[item.event_type] || EVENT_TYPE_COLORS.other;
    const confColor = item.confidence === 'high' ? '#34d399' : item.confidence === 'medium' ? '#fbbf24' : '#94a3b8';
    return /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        background: '#FFFFFF',
        border: '1px solid #e2e8f0',
        borderRadius: '10px',
        padding: '1rem'
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: 'flex',
        gap: '0.5rem',
        alignItems: 'center',
        marginBottom: '0.5rem',
        flexWrap: 'wrap'
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontSize: '0.7rem',
        padding: '0.15rem 0.5rem',
        borderRadius: '9999px',
        fontWeight: 600,
        background: ec.bg,
        color: ec.color,
        textTransform: 'uppercase'
      }
    }, item.event_type), /*#__PURE__*/React.createElement("span", {
      style: {
        fontSize: '0.7rem',
        color: confColor,
        fontWeight: 600
      }
    }, (item.confidence || '').toUpperCase()), item.city && item.city !== 'Unknown' && /*#__PURE__*/React.createElement("span", {
      style: {
        fontSize: '0.75rem',
        color: '#3b82f6'
      }
    }, item.city, ", ", item.state)), item.company && /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: '0.9rem',
        fontWeight: 600,
        color: '#0f172a',
        marginBottom: '0.25rem'
      }
    }, item.company), /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: '0.85rem',
        color: '#334155',
        marginBottom: '0.4rem',
        lineHeight: '1.4'
      }
    }, item.summary || item.title), /*#__PURE__*/React.createElement("div", {
      style: {
        display: 'flex',
        gap: '0.75rem',
        flexWrap: 'wrap',
        fontSize: '0.75rem',
        color: '#64748b'
      }
    }, item.units && /*#__PURE__*/React.createElement("span", null, "Units: ", item.units), item.date && /*#__PURE__*/React.createElement("span", null, item.date)), item.url && /*#__PURE__*/React.createElement("a", {
      href: item.url,
      target: "_blank",
      rel: "noopener noreferrer",
      style: {
        color: '#3b82f6',
        textDecoration: 'none',
        fontSize: '0.8rem',
        display: 'inline-block',
        marginTop: '0.3rem'
      }
    }, "Read source"));
  }))), !selectedState && rankings.length === 0 && /*#__PURE__*/React.createElement("div", {
    style: styles.empty
  }, /*#__PURE__*/React.createElement("h2", {
    style: styles.emptyTitle
  }, "No statewide data yet"), /*#__PURE__*/React.createElement("p", {
    style: styles.emptyText
  }, "Click \"Scan All States\" or select a state to begin scanning")));
}

// ======= SUNBELT INTELLIGENCE =======
function SunbeltIntelligence({
  user
}) {
  const [subTab, setSubTab] = useState('brief');
  const [weeklyData, setWeeklyData] = useState(null);
  const [momentumData, setMomentumData] = useState(null);
  const [trendsData, setTrendsData] = useState(null);
  const [rankingsData, setRankingsData] = useState(null);
  const [loading, setLoading] = useState({});
  const [errors, setErrors] = useState({});
  const [trendFilter, setTrendFilter] = useState({
    state: '',
    topic: ''
  });

  // Also keep the existing brief/optimization flows for admin actions
  const [latestBrief, setLatestBrief] = useState(null);
  const [genLoading, setGenLoading] = useState(false);
  const [optLoading, setOptLoading] = useState(false);
  const [actionError, setActionError] = useState('');

  // Sparknotes state
  const [sparknotes, setSparknotes] = useState({}); // keyed by tab name
  const [sparkLoading, setSparkLoading] = useState(false);
  const [sparkError, setSparkError] = useState('');
  const [sparkExpanded, setSparkExpanded] = useState({}); // keyed by item id

  const setTabLoading = (tab, val) => setLoading(prev => ({
    ...prev,
    [tab]: val
  }));
  const setTabError = (tab, val) => setErrors(prev => ({
    ...prev,
    [tab]: val
  }));
  const fetchWeekly = async () => {
    setTabLoading('brief', true);
    setTabError('brief', '');
    try {
      const res = await fetch(`${API_BASE}/api/sunbelt/weekly?windowDays=7`);
      const d = await res.json();
      if (d.ok === false) {
        setTabError('brief', d.error || 'Failed to load weekly brief');
      } else {
        setWeeklyData(d.data);
      }
    } catch (e) {
      setTabError('brief', 'Network error loading weekly brief');
    }
    setTabLoading('brief', false);
  };
  const fetchMomentum = async () => {
    setTabLoading('momentum', true);
    setTabError('momentum', '');
    try {
      const res = await fetch(`${API_BASE}/api/sunbelt/momentum?windowDays=7&baselineDays=30`);
      const d = await res.json();
      if (d.ok === false) {
        setTabError('momentum', d.error || 'Failed to load momentum');
      } else {
        setMomentumData(d.data);
      }
    } catch (e) {
      setTabError('momentum', 'Network error loading momentum');
    }
    setTabLoading('momentum', false);
  };
  const fetchTrends = async () => {
    setTabLoading('trends', true);
    setTabError('trends', '');
    try {
      let url = `${API_BASE}/api/sunbelt/trends?windowDays=7&baselineDays=30`;
      if (trendFilter.topic) url += `&topic=${encodeURIComponent(trendFilter.topic)}`;
      const res = await fetch(url);
      const d = await res.json();
      if (d.ok === false) {
        setTabError('trends', d.error || 'Failed to load trends');
      } else {
        setTrendsData(d.data);
      }
    } catch (e) {
      setTabError('trends', 'Network error loading trends');
    }
    setTabLoading('trends', false);
  };
  const fetchRankings = async () => {
    setTabLoading('rankings', true);
    setTabError('rankings', '');
    try {
      const res = await fetch(`${API_BASE}/api/sunbelt/state-rankings?windowDays=30`);
      const d = await res.json();
      if (d.ok === false) {
        setTabError('rankings', d.error || 'Failed to load rankings');
      } else {
        setRankingsData(d.data);
      }
    } catch (e) {
      setTabError('rankings', 'Network error loading rankings');
    }
    setTabLoading('rankings', false);
  };
  const fetchLatestBrief = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/intelligence/briefs/latest`);
      const data = await res.json();
      if (data.brief) setLatestBrief(data.brief);
    } catch (e) {/* optional */}
  };
  useEffect(() => {
    fetchWeekly();
    fetchMomentum();
    fetchTrends();
    fetchRankings();
    fetchLatestBrief();
  }, []);
  useEffect(() => {
    fetchTrends();
  }, [trendFilter.topic]);
  const generateBrief = async () => {
    setGenLoading(true);
    setActionError('');
    try {
      const res = await fetch(`${API_BASE}/api/intelligence/briefs/generate`, {
        method: 'POST'
      });
      const data = await res.json();
      if (data.error) setActionError(data.error);else {
        await fetchLatestBrief();
      }
    } catch (e) {
      setActionError('Failed to generate brief');
    }
    setGenLoading(false);
  };
  const runOptimization = async () => {
    setOptLoading(true);
    setActionError('');
    try {
      const res = await fetch(`${API_BASE}/api/intelligence/optimization/run`, {
        method: 'POST'
      });
      const data = await res.json();
      if (data.error) setActionError(data.error);else {
        await fetchMomentum();
        await fetchRankings();
      }
    } catch (e) {
      setActionError('Failed to run optimization');
    }
    setOptLoading(false);
  };
  const copyBrief = () => {
    const text = weeklyData?.brief_text || '';
    if (text) navigator.clipboard.writeText(text);
  };

  // --- Sparknotes ---
  const tabToApiTab = {
    brief: 'weekly',
    momentum: 'momentum',
    trends: 'trends',
    rankings: 'state_rankings'
  };
  const tabWindowDays = {
    brief: 7,
    momentum: 7,
    trends: 7,
    rankings: 30
  };
  const generateSparknotes = async () => {
    const apiTab = tabToApiTab[subTab] || 'weekly';
    setSparkLoading(true);
    setSparkError('');
    try {
      const res = await fetch(`${API_BASE}/api/sunbelt/sparknotes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          tab: apiTab,
          windowDays: tabWindowDays[subTab] || 7
        })
      });
      if (!res.ok) {
        // Try to parse error JSON; fall back to status text
        let errMsg = `Server error (${res.status})`;
        try {
          const ej = await res.json();
          errMsg = ej.error || ej.message || errMsg;
        } catch (_) {
          try {
            errMsg = (await res.text()).substring(0, 200) || errMsg;
          } catch (_2) {}
        }
        setSparkError(errMsg);
      } else {
        const d = await res.json();
        if (!d.ok) {
          setSparkError(d.error || 'Failed to generate sparknotes');
        } else {
          setSparknotes(prev => ({
            ...prev,
            [subTab]: {
              data: d.data,
              meta: d.meta
            }
          }));
          setSparkExpanded({});
        }
      }
    } catch (e) {
      setSparkError('Network error: ' + (e.message || 'Failed to connect'));
    }
    setSparkLoading(false);
  };
  const copySparknotes = () => {
    const sn = sparknotes[subTab]?.data;
    if (!sn) return;
    let text = '=== AI SPARKNOTES ===\n\n';
    text += 'EXECUTIVE SUMMARY:\n' + (sn.executive_summary || '') + '\n\n';
    text += 'KEY THEMES: ' + (sn.key_themes || []).join(', ') + '\n\n';
    (sn.sparknotes_by_item || []).forEach((item, i) => {
      text += `--- Item ${i + 1} ---\n`;
      text += item.one_liner + '\n';
      (item.bullets || []).forEach(b => {
        text += '  - ' + b + '\n';
      });
      text += 'Why it matters: ' + (item.why_it_matters || '') + '\n';
      text += 'Next step: ' + (item.suggested_next_step || '') + '\n\n';
    });
    navigator.clipboard.writeText(text);
  };
  const toggleSparkItem = id => {
    setSparkExpanded(prev => ({
      ...prev,
      [id]: !prev[id]
    }));
  };
  const SparknotesPanel = () => {
    const sn = sparknotes[subTab]?.data;
    const meta = sparknotes[subTab]?.meta;
    if (!sn) return null;
    return /*#__PURE__*/React.createElement("div", {
      style: {
        background: 'linear-gradient(135deg, rgba(20,184,166,0.06), rgba(167,139,250,0.08))',
        border: '1px solid rgba(16,185,129,0.3)',
        borderRadius: '12px',
        padding: '1.5rem',
        marginBottom: '1.5rem'
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '1rem'
      }
    }, /*#__PURE__*/React.createElement("h3", {
      style: {
        fontFamily: "'Orbitron', sans-serif",
        fontSize: '0.85rem',
        fontWeight: 700,
        color: '#14b8a6',
        textTransform: 'uppercase',
        margin: 0
      }
    }, "AI Sparknotes"), /*#__PURE__*/React.createElement("div", {
      style: {
        display: 'flex',
        gap: '0.5rem',
        alignItems: 'center'
      }
    }, meta?.cached && /*#__PURE__*/React.createElement("span", {
      style: {
        fontSize: '0.65rem',
        color: '#64748b',
        background: 'rgba(100,116,139,0.15)',
        padding: '0.15rem 0.5rem',
        borderRadius: '10px'
      }
    }, "cached"), /*#__PURE__*/React.createElement("span", {
      style: {
        fontSize: '0.65rem',
        color: '#64748b'
      }
    }, meta?.generated_at ? new Date(meta.generated_at).toLocaleString() : ''), /*#__PURE__*/React.createElement("button", {
      onClick: copySparknotes,
      style: {
        ...styles.btn,
        fontSize: '0.75rem',
        padding: '0.3rem 0.75rem'
      }
    }, "Copy Sparknotes"))), sn.executive_summary && /*#__PURE__*/React.createElement("div", {
      style: {
        background: 'rgba(15,23,42,0.5)',
        border: '1px solid #e2e8f0',
        borderRadius: '8px',
        padding: '1rem',
        marginBottom: '1rem'
      }
    }, /*#__PURE__*/React.createElement("h4", {
      style: {
        fontFamily: "'Orbitron', sans-serif",
        fontSize: '0.7rem',
        fontWeight: 700,
        color: '#3b82f6',
        textTransform: 'uppercase',
        marginTop: 0,
        marginBottom: '0.5rem'
      }
    }, "Executive Summary"), sn.executive_summary.split('\n').map((line, i) => {
      const trimmed = line.replace(/^[-•]\s*/, '').trim();
      if (!trimmed) return null;
      return /*#__PURE__*/React.createElement("div", {
        key: i,
        style: {
          fontSize: '0.85rem',
          color: '#334155',
          lineHeight: '1.6',
          marginBottom: '0.25rem',
          paddingLeft: '0.75rem',
          borderLeft: '2px solid rgba(34,211,238,0.3)'
        }
      }, trimmed);
    })), sn.key_themes && sn.key_themes.length > 0 && /*#__PURE__*/React.createElement("div", {
      style: {
        display: 'flex',
        gap: '0.5rem',
        flexWrap: 'wrap',
        marginBottom: '1rem'
      }
    }, sn.key_themes.map((theme, i) => /*#__PURE__*/React.createElement("span", {
      key: i,
      style: {
        background: 'rgba(167,139,250,0.15)',
        border: '1px solid rgba(167,139,250,0.3)',
        borderRadius: '20px',
        padding: '0.25rem 0.75rem',
        fontSize: '0.75rem',
        color: '#c4b5fd',
        fontWeight: 500
      }
    }, theme))), sn.sparknotes_by_item && sn.sparknotes_by_item.length > 0 && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h4", {
      style: {
        fontFamily: "'Orbitron', sans-serif",
        fontSize: '0.7rem',
        fontWeight: 700,
        color: '#fbbf24',
        textTransform: 'uppercase',
        marginBottom: '0.5rem'
      }
    }, "Item Sparknotes"), sn.sparknotes_by_item.map((item, i) => {
      const expanded = sparkExpanded[item.id || i];
      return /*#__PURE__*/React.createElement("div", {
        key: item.id || i,
        style: {
          background: 'rgba(15,23,42,0.4)',
          border: '1px solid #e2e8f0',
          borderRadius: '8px',
          padding: '0.75rem 1rem',
          marginBottom: '0.5rem',
          cursor: 'pointer',
          transition: 'border-color 0.2s'
        },
        onClick: () => toggleSparkItem(item.id || i)
      }, /*#__PURE__*/React.createElement("div", {
        style: {
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }
      }, /*#__PURE__*/React.createElement("span", {
        style: {
          fontSize: '0.85rem',
          color: '#0f172a',
          fontWeight: 500
        }
      }, item.one_liner), /*#__PURE__*/React.createElement("span", {
        style: {
          fontSize: '0.7rem',
          color: '#64748b',
          flexShrink: 0,
          marginLeft: '0.5rem'
        }
      }, expanded ? '▲' : '▼')), expanded && /*#__PURE__*/React.createElement("div", {
        style: {
          marginTop: '0.75rem',
          paddingTop: '0.75rem',
          borderTop: '1px solid #e2e8f0'
        }
      }, item.bullets && item.bullets.map((b, j) => /*#__PURE__*/React.createElement("div", {
        key: j,
        style: {
          fontSize: '0.8rem',
          color: '#64748b',
          marginBottom: '0.3rem',
          paddingLeft: '0.75rem',
          borderLeft: '2px solid rgba(148,163,184,0.3)'
        }
      }, b)), item.why_it_matters && /*#__PURE__*/React.createElement("div", {
        style: {
          fontSize: '0.8rem',
          color: '#fbbf24',
          marginTop: '0.5rem'
        }
      }, /*#__PURE__*/React.createElement("strong", null, "Why it matters:"), " ", item.why_it_matters), item.suggested_next_step && /*#__PURE__*/React.createElement("div", {
        style: {
          fontSize: '0.8rem',
          color: '#14b8a6',
          marginTop: '0.3rem'
        }
      }, /*#__PURE__*/React.createElement("strong", null, "Next step:"), " ", item.suggested_next_step)));
    })));
  };
  const classColor = cls => {
    const c = (cls || '').toLowerCase();
    if (c === 'accelerating') return {
      bg: 'rgba(239,68,68,0.15)',
      color: '#f87171',
      border: '#ef4444'
    };
    if (c === 'emerging' || c === 'steady') return {
      bg: 'rgba(245,158,11,0.15)',
      color: '#fcd34d',
      border: '#f59e0b'
    };
    if (c === 'peaking') return {
      bg: 'rgba(168,85,247,0.15)',
      color: '#c4b5fd',
      border: '#a855f7'
    };
    if (c === 'cooling') return {
      bg: 'rgba(59,130,246,0.15)',
      color: '#3b82f6',
      border: '#3b82f6'
    };
    return {
      bg: 'rgba(148,163,184,0.15)',
      color: '#64748b',
      border: '#64748b'
    };
  };
  const subTabs = [{
    id: 'brief',
    label: 'Weekly Brief'
  }, {
    id: 'momentum',
    label: 'Momentum Index'
  }, {
    id: 'trends',
    label: 'Trend Signals'
  }, {
    id: 'rankings',
    label: 'State Rankings'
  }];
  const states = ['TX', 'AZ', 'GA', 'NC', 'FL'];
  const ErrorPanel = ({
    msg
  }) => /*#__PURE__*/React.createElement("div", {
    style: {
      background: 'rgba(239,68,68,0.1)',
      border: '1px solid rgba(239,68,68,0.3)',
      borderRadius: '8px',
      padding: '1rem',
      color: '#f87171',
      fontSize: '0.9rem'
    }
  }, msg);
  const EmptyPanel = ({
    title,
    desc
  }) => /*#__PURE__*/React.createElement(EmptyState, {
    title: title,
    subtitle: desc
  });
  const LoadingPanel = () => /*#__PURE__*/React.createElement("div", {
    style: {
      textAlign: 'center',
      padding: '3rem',
      color: '#64748b'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '1rem'
    }
  }, "Loading..."));
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement(SectionHeader, {
    title: "SUNBELT INTELLIGENCE",
    icon: "signals"
  }), /*#__PURE__*/React.createElement(Divider, null), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.5rem',
      marginBottom: '1.5rem',
      borderBottom: '1px solid #e2e8f0',
      paddingBottom: '0.75rem'
    }
  }, subTabs.map(t => /*#__PURE__*/React.createElement("button", {
    key: t.id,
    onClick: () => setSubTab(t.id),
    style: {
      background: subTab === t.id ? 'rgba(20,184,166,0.1)' : 'transparent',
      border: subTab === t.id ? '1px solid #14b8a6' : '1px solid #e2e8f0',
      color: subTab === t.id ? '#34d399' : '#94a3b8',
      padding: '0.5rem 1.2rem',
      borderRadius: '8px',
      fontSize: '0.85rem',
      cursor: 'pointer',
      fontFamily: "'Inter', sans-serif",
      fontWeight: 500,
      transition: 'all 0.2s'
    }
  }, t.label))), actionError && /*#__PURE__*/React.createElement(ErrorPanel, {
    msg: actionError
  }), sparkError && /*#__PURE__*/React.createElement(ErrorPanel, {
    msg: sparkError
  }), sparknotes[subTab] && /*#__PURE__*/React.createElement(SparknotesPanel, null), subTab === 'brief' && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.75rem',
      marginBottom: '1.5rem',
      alignItems: 'center',
      flexWrap: 'wrap'
    }
  }, user?.role === 'admin' && /*#__PURE__*/React.createElement("button", {
    onClick: generateBrief,
    disabled: genLoading,
    style: {
      ...styles.btnPrimary,
      opacity: genLoading ? 0.6 : 1,
      cursor: genLoading ? 'not-allowed' : 'pointer'
    }
  }, genLoading ? 'Generating...' : 'Generate Brief Now'), /*#__PURE__*/React.createElement("button", {
    onClick: generateSparknotes,
    disabled: sparkLoading,
    style: {
      background: sparkLoading ? 'rgba(167,139,250,0.1)' : 'rgba(167,139,250,0.15)',
      border: '1px solid rgba(167,139,250,0.4)',
      color: '#c4b5fd',
      padding: '0.5rem 1rem',
      borderRadius: '8px',
      fontSize: '0.85rem',
      cursor: sparkLoading ? 'not-allowed' : 'pointer',
      fontFamily: "'Inter', sans-serif",
      fontWeight: 500,
      opacity: sparkLoading ? 0.6 : 1,
      transition: 'all 0.2s'
    }
  }, sparkLoading ? 'Generating Sparknotes...' : 'Generate Sparknotes'), /*#__PURE__*/React.createElement("button", {
    onClick: copyBrief,
    style: styles.btn,
    disabled: !weeklyData?.brief_text
  }, "Copy to Clipboard"), /*#__PURE__*/React.createElement("button", {
    onClick: fetchWeekly,
    style: styles.btn
  }, "Refresh")), loading.brief && /*#__PURE__*/React.createElement(LoadingPanel, null), errors.brief && /*#__PURE__*/React.createElement(ErrorPanel, {
    msg: errors.brief
  }), !loading.brief && !errors.brief && weeklyData && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      borderRadius: '12px',
      padding: '1.25rem',
      marginBottom: '1.5rem'
    }
  }, /*#__PURE__*/React.createElement("p", {
    style: {
      fontSize: '0.95rem',
      color: '#334155',
      lineHeight: '1.7'
    }
  }, weeklyData.brief_text)), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: '1fr 1fr',
      gap: '1rem',
      marginBottom: '1.5rem'
    }
  }, weeklyData.top_markets && weeklyData.top_markets.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      borderRadius: '12px',
      padding: '1.25rem'
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '0.8rem',
      fontWeight: 700,
      color: '#3b82f6',
      textTransform: 'uppercase',
      marginBottom: '0.75rem',
      marginTop: 0
    }
  }, "Top Markets"), weeklyData.top_markets.map((m, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      padding: '0.3rem 0',
      borderBottom: '1px solid #0f172a'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#0f172a',
      fontSize: '0.85rem'
    }
  }, m.market), /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#14b8a6',
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: '0.85rem'
    }
  }, m.weighted_signals)))), weeklyData.top_topics && weeklyData.top_topics.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      borderRadius: '12px',
      padding: '1.25rem'
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '0.8rem',
      fontWeight: 700,
      color: '#a78bfa',
      textTransform: 'uppercase',
      marginBottom: '0.75rem',
      marginTop: 0
    }
  }, "Top Topics"), weeklyData.top_topics.map((t, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      padding: '0.3rem 0',
      borderBottom: '1px solid #0f172a'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#0f172a',
      fontSize: '0.85rem'
    }
  }, t.topic), /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#64748b',
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: '0.85rem'
    }
  }, t.count))))), weeklyData.highlights && weeklyData.highlights.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      borderRadius: '12px',
      padding: '1.25rem'
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '0.8rem',
      fontWeight: 700,
      color: '#fbbf24',
      textTransform: 'uppercase',
      marginBottom: '0.75rem',
      marginTop: 0
    }
  }, "Top Highlights"), weeklyData.highlights.map((h, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      marginBottom: '0.75rem',
      paddingBottom: '0.75rem',
      borderBottom: i < weeklyData.highlights.length - 1 ? '1px solid #0f172a' : 'none'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      gap: '0.5rem'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#0f172a',
      fontSize: '0.85rem',
      fontWeight: 600
    }
  }, h.url ? /*#__PURE__*/React.createElement("a", {
    href: h.url,
    target: "_blank",
    rel: "noopener noreferrer",
    style: {
      color: '#0f172a',
      textDecoration: 'underline'
    }
  }, h.title) : h.title), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.7rem',
      color: '#64748b',
      whiteSpace: 'nowrap'
    }
  }, h.city ? `${h.city}, ${h.state}` : '')), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.75rem',
      marginTop: '0.2rem'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.7rem',
      color: '#64748b'
    }
  }, h.topic), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.7rem',
      color: '#94a3b8'
    }
  }, h.date ? new Date(h.date).toLocaleDateString() : ''))))), latestBrief && /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: '1.5rem'
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '0.85rem',
      fontWeight: 700,
      color: '#14b8a6',
      marginBottom: '0.75rem'
    }
  }, "AI-GENERATED BRIEF"), /*#__PURE__*/React.createElement(BriefDisplay, {
    brief: latestBrief
  }))), !loading.brief && !errors.brief && !weeklyData && /*#__PURE__*/React.createElement(EmptyPanel, {
    title: "No Weekly Data",
    desc: "No discovery signals found. Run daily discovery first."
  })), subTab === 'momentum' && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.75rem',
      marginBottom: '1.5rem',
      alignItems: 'center',
      flexWrap: 'wrap'
    }
  }, user?.role === 'admin' && /*#__PURE__*/React.createElement("button", {
    onClick: runOptimization,
    disabled: optLoading,
    style: {
      ...styles.btnPrimary,
      opacity: optLoading ? 0.6 : 1,
      cursor: optLoading ? 'not-allowed' : 'pointer'
    }
  }, optLoading ? 'Running...' : 'Run Optimization'), /*#__PURE__*/React.createElement("button", {
    onClick: generateSparknotes,
    disabled: sparkLoading,
    style: {
      background: sparkLoading ? 'rgba(167,139,250,0.1)' : 'rgba(167,139,250,0.15)',
      border: '1px solid rgba(167,139,250,0.4)',
      color: '#c4b5fd',
      padding: '0.5rem 1rem',
      borderRadius: '8px',
      fontSize: '0.85rem',
      cursor: sparkLoading ? 'not-allowed' : 'pointer',
      fontFamily: "'Inter', sans-serif",
      fontWeight: 500,
      opacity: sparkLoading ? 0.6 : 1,
      transition: 'all 0.2s'
    }
  }, sparkLoading ? 'Generating Sparknotes...' : 'Generate Sparknotes'), /*#__PURE__*/React.createElement("button", {
    onClick: fetchMomentum,
    style: styles.btn
  }, "Refresh"), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.8rem',
      color: '#64748b'
    }
  }, "Top cities by momentum (7d vs 30d baseline)")), loading.momentum && /*#__PURE__*/React.createElement(LoadingPanel, null), errors.momentum && /*#__PURE__*/React.createElement(ErrorPanel, {
    msg: errors.momentum
  }), !loading.momentum && !errors.momentum && momentumData && (momentumData.markets || []).length > 0 ? /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'grid',
      gap: '0.75rem'
    }
  }, momentumData.markets.map((m, i) => {
    const lc = classColor(m.momentum_label);
    return /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        background: '#FFFFFF',
        border: '1px solid #e2e8f0',
        borderRadius: '12px',
        padding: '1.25rem',
        display: 'grid',
        gridTemplateColumns: 'auto 1fr auto',
        gap: '1.25rem',
        alignItems: 'center'
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "'Orbitron', sans-serif",
        fontSize: '1.5rem',
        fontWeight: 900,
        color: i < 3 ? '#34d399' : '#64748b',
        width: '2.5rem',
        textAlign: 'center'
      }
    }, "#", i + 1), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
      style: {
        display: 'flex',
        alignItems: 'center',
        gap: '0.75rem',
        marginBottom: '0.3rem'
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "'Orbitron', sans-serif",
        fontSize: '1rem',
        fontWeight: 700,
        color: '#0f172a'
      }
    }, m.city || 'Unknown', ", ", m.state || '??'), /*#__PURE__*/React.createElement("span", {
      style: {
        background: lc.bg,
        color: lc.color,
        border: `1px solid ${lc.border}`,
        borderRadius: '20px',
        padding: '0.15rem 0.6rem',
        fontSize: '0.65rem',
        fontWeight: 700,
        textTransform: 'uppercase',
        letterSpacing: '0.05em'
      }
    }, m.momentum_label)), /*#__PURE__*/React.createElement("div", {
      style: {
        display: 'flex',
        gap: '1.5rem',
        fontSize: '0.8rem',
        color: '#64748b'
      }
    }, /*#__PURE__*/React.createElement("span", null, "7d signals: ", /*#__PURE__*/React.createElement("strong", {
      style: {
        color: '#14b8a6'
      }
    }, m.signals_window)), /*#__PURE__*/React.createElement("span", null, "30d signals: ", /*#__PURE__*/React.createElement("strong", {
      style: {
        color: '#64748b'
      }
    }, m.signals_baseline)), /*#__PURE__*/React.createElement("span", null, "ratio: ", /*#__PURE__*/React.createElement("strong", {
      style: {
        color: lc.color
      }
    }, (m.ratio || 0).toFixed(2))))), /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: '1.4rem',
        fontWeight: 700,
        color: lc.color
      }
    }, Math.round(m.momentum_score)));
  })) : !loading.momentum && !errors.momentum ? /*#__PURE__*/React.createElement(EmptyPanel, {
    title: "No Momentum Data",
    desc: momentumData?.message || 'No discovery signals found for momentum calculation.'
  }) : null), subTab === 'trends' && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.75rem',
      marginBottom: '1.5rem',
      alignItems: 'center',
      flexWrap: 'wrap'
    }
  }, /*#__PURE__*/React.createElement("input", {
    type: "text",
    placeholder: "Filter by topic...",
    value: trendFilter.topic,
    onChange: e => setTrendFilter(f => ({
      ...f,
      topic: e.target.value
    })),
    style: {
      ...styles.input,
      minWidth: '180px'
    }
  }), /*#__PURE__*/React.createElement("button", {
    onClick: generateSparknotes,
    disabled: sparkLoading,
    style: {
      background: sparkLoading ? 'rgba(167,139,250,0.1)' : 'rgba(167,139,250,0.15)',
      border: '1px solid rgba(167,139,250,0.4)',
      color: '#c4b5fd',
      padding: '0.5rem 1rem',
      borderRadius: '8px',
      fontSize: '0.85rem',
      cursor: sparkLoading ? 'not-allowed' : 'pointer',
      fontFamily: "'Inter', sans-serif",
      fontWeight: 500,
      opacity: sparkLoading ? 0.6 : 1,
      transition: 'all 0.2s'
    }
  }, sparkLoading ? 'Generating Sparknotes...' : 'Generate Sparknotes'), /*#__PURE__*/React.createElement("button", {
    onClick: fetchTrends,
    style: styles.btn
  }, "Refresh"), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.8rem',
      color: '#64748b'
    }
  }, (trendsData?.trends || []).length, " trends found")), loading.trends && /*#__PURE__*/React.createElement(LoadingPanel, null), errors.trends && /*#__PURE__*/React.createElement(ErrorPanel, {
    msg: errors.trends
  }), !loading.trends && !errors.trends && (trendsData?.trends || []).length > 0 ? /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))',
      gap: '1rem'
    }
  }, trendsData.trends.map((t, i) => {
    const cc = classColor(t.classification);
    return /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        background: '#FFFFFF',
        border: '1px solid #e2e8f0',
        borderRadius: '12px',
        padding: '1.25rem',
        borderLeft: `3px solid ${cc.border}`
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        marginBottom: '0.75rem'
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "'Orbitron', sans-serif",
        fontSize: '0.95rem',
        fontWeight: 700,
        color: '#0f172a'
      }
    }, t.city || 'Unknown', ", ", t.state || '??'), /*#__PURE__*/React.createElement("span", {
      style: {
        background: cc.bg,
        color: cc.color,
        border: `1px solid ${cc.border}`,
        borderRadius: '20px',
        padding: '0.2rem 0.7rem',
        fontSize: '0.7rem',
        fontWeight: 700,
        textTransform: 'uppercase',
        letterSpacing: '0.05em'
      }
    }, t.classification)), /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: '0.9rem',
        color: '#0f172a',
        marginBottom: '0.5rem',
        fontWeight: 500
      }
    }, t.topic), /*#__PURE__*/React.createElement("div", {
      style: {
        display: 'flex',
        gap: '1.5rem',
        fontSize: '0.8rem',
        color: '#64748b',
        marginBottom: '0.75rem'
      }
    }, /*#__PURE__*/React.createElement("span", null, "7d: ", /*#__PURE__*/React.createElement("strong", {
      style: {
        color: '#14b8a6'
      }
    }, t.count_window)), /*#__PURE__*/React.createElement("span", null, "30d: ", /*#__PURE__*/React.createElement("strong", {
      style: {
        color: '#64748b'
      }
    }, t.count_baseline)), /*#__PURE__*/React.createElement("span", null, "Ratio: ", /*#__PURE__*/React.createElement("strong", {
      style: {
        color: cc.color
      }
    }, (t.trend_ratio || 0).toFixed(1), "x"))), t.examples && t.examples.length > 0 && /*#__PURE__*/React.createElement("div", {
      style: {
        borderTop: '1px solid #e2e8f0',
        paddingTop: '0.5rem'
      }
    }, t.examples.map((ex, j) => /*#__PURE__*/React.createElement("div", {
      key: j,
      style: {
        fontSize: '0.75rem',
        color: '#64748b',
        marginBottom: '0.3rem',
        display: 'flex',
        justifyContent: 'space-between',
        gap: '0.5rem'
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap'
      }
    }, ex.source_url ? /*#__PURE__*/React.createElement("a", {
      href: ex.source_url,
      target: "_blank",
      rel: "noopener noreferrer",
      style: {
        color: '#64748b'
      }
    }, ex.title) : ex.title), /*#__PURE__*/React.createElement("span", {
      style: {
        color: '#94a3b8',
        whiteSpace: 'nowrap',
        flexShrink: 0
      }
    }, ex.date ? new Date(ex.date).toLocaleDateString() : '')))));
  })) : !loading.trends && !errors.trends ? /*#__PURE__*/React.createElement(EmptyPanel, {
    title: "No Trend Signals",
    desc: trendsData?.message || 'No discovery signals found matching your filters.'
  }) : null), subTab === 'rankings' && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.75rem',
      marginBottom: '1.5rem',
      alignItems: 'center',
      flexWrap: 'wrap'
    }
  }, /*#__PURE__*/React.createElement("button", {
    onClick: generateSparknotes,
    disabled: sparkLoading,
    style: {
      background: sparkLoading ? 'rgba(167,139,250,0.1)' : 'rgba(167,139,250,0.15)',
      border: '1px solid rgba(167,139,250,0.4)',
      color: '#c4b5fd',
      padding: '0.5rem 1rem',
      borderRadius: '8px',
      fontSize: '0.85rem',
      cursor: sparkLoading ? 'not-allowed' : 'pointer',
      fontFamily: "'Inter', sans-serif",
      fontWeight: 500,
      opacity: sparkLoading ? 0.6 : 1,
      transition: 'all 0.2s'
    }
  }, sparkLoading ? 'Generating Sparknotes...' : 'Generate Sparknotes'), /*#__PURE__*/React.createElement("button", {
    onClick: fetchRankings,
    style: styles.btn
  }, "Refresh")), loading.rankings && /*#__PURE__*/React.createElement(LoadingPanel, null), errors.rankings && /*#__PURE__*/React.createElement(ErrorPanel, {
    msg: errors.rankings
  }), !loading.rankings && !errors.rankings && (rankingsData?.rankings || []).length > 0 ? /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'grid',
      gap: '1rem'
    }
  }, rankingsData.rankings.map((r, i) => /*#__PURE__*/React.createElement("div", {
    key: r.state,
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      borderRadius: '12px',
      padding: '1.5rem',
      display: 'grid',
      gridTemplateColumns: 'auto 1fr auto',
      gap: '1.5rem',
      alignItems: 'center'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '2rem',
      fontWeight: 900,
      color: i === 0 ? '#fbbf24' : i === 1 ? '#94a3b8' : i === 2 ? '#cd7f32' : '#64748b',
      width: '3rem',
      textAlign: 'center'
    }
  }, "#", i + 1), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '1.2rem',
      fontWeight: 700,
      color: '#0f172a',
      marginBottom: '0.5rem'
    }
  }, r.state_name || r.state), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '2rem',
      flexWrap: 'wrap',
      fontSize: '0.85rem',
      color: '#64748b'
    }
  }, /*#__PURE__*/React.createElement("span", null, "Signals: ", /*#__PURE__*/React.createElement("strong", {
    style: {
      color: '#14b8a6'
    }
  }, r.total_signals || 0)), /*#__PURE__*/React.createElement("span", null, "Capital: ", /*#__PURE__*/React.createElement("strong", {
    style: {
      color: '#a78bfa'
    }
  }, r.capital_events || 0)), /*#__PURE__*/React.createElement("span", null, "Construction: ", /*#__PURE__*/React.createElement("strong", {
    style: {
      color: '#67e8f9'
    }
  }, r.construction_signals || 0))), r.top_cities && r.top_cities.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.5rem',
      marginTop: '0.5rem',
      flexWrap: 'wrap'
    }
  }, r.top_cities.map((c, j) => /*#__PURE__*/React.createElement("span", {
    key: j,
    style: {
      background: 'rgba(16,185,129,0.1)',
      border: '1px solid rgba(16,185,129,0.3)',
      borderRadius: '20px',
      padding: '0.2rem 0.6rem',
      fontSize: '0.75rem',
      color: '#14b8a6'
    }
  }, c.city, " (", c.weighted_score, ")"))), r.top_topics && r.top_topics.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.5rem',
      marginTop: '0.4rem',
      flexWrap: 'wrap'
    }
  }, r.top_topics.slice(0, 5).map((t, j) => /*#__PURE__*/React.createElement("span", {
    key: j,
    style: {
      fontSize: '0.7rem',
      color: '#64748b'
    }
  }, t.topic, ": ", t.count)))), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: '1.6rem',
      fontWeight: 700,
      color: '#14b8a6',
      textAlign: 'right'
    }
  }, r.weighted_signals || 0)))) : !loading.rankings && !errors.rankings ? /*#__PURE__*/React.createElement(EmptyPanel, {
    title: "No Rankings Data",
    desc: rankingsData?.message || 'No discovery signals found for ranking.'
  }) : null));
}
function BriefDisplay({
  brief
}) {
  let content = brief.brief_json;
  if (typeof content === 'string') {
    try {
      content = JSON.parse(content);
    } catch (e) {/* use as string */}
  }
  if (typeof content === 'object' && content !== null) {
    return /*#__PURE__*/React.createElement("div", {
      style: {
        display: 'grid',
        gap: '1.25rem'
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: '0.8rem',
        color: '#64748b',
        marginBottom: '0.5rem'
      }
    }, "Week of ", brief.week_start, " to ", brief.week_end, " \xB7 Generated ", new Date(brief.generated_at).toLocaleString()), content.executive_summary && /*#__PURE__*/React.createElement(BriefSection, {
      title: "Executive Summary",
      color: "#34d399"
    }, /*#__PURE__*/React.createElement("p", {
      style: {
        fontSize: '0.9rem',
        color: '#334155',
        lineHeight: '1.7'
      }
    }, content.executive_summary)), content.top_emerging_markets && content.top_emerging_markets.length > 0 && /*#__PURE__*/React.createElement(BriefSection, {
      title: "Top Emerging Markets",
      color: "#3b82f6"
    }, content.top_emerging_markets.map((m, i) => /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        marginBottom: '0.75rem',
        paddingBottom: '0.75rem',
        borderBottom: i < content.top_emerging_markets.length - 1 ? '1px solid #e2e8f0' : 'none'
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontWeight: 600,
        color: '#0f172a',
        marginBottom: '0.25rem'
      }
    }, m.market || m.city), /*#__PURE__*/React.createElement("p", {
      style: {
        fontSize: '0.85rem',
        color: '#64748b',
        lineHeight: '1.5'
      }
    }, m.summary || m.reason || m.description)))), content.capital_flow_highlights && content.capital_flow_highlights.length > 0 && /*#__PURE__*/React.createElement(BriefSection, {
      title: "Capital Flow Highlights",
      color: "#a78bfa"
    }, content.capital_flow_highlights.map((h, i) => /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        marginBottom: '0.5rem',
        fontSize: '0.85rem',
        color: '#334155'
      }
    }, "\u2022 ", typeof h === 'string' ? h : h.description || h.summary || JSON.stringify(h)))), content.construction_pipeline && content.construction_pipeline.length > 0 && /*#__PURE__*/React.createElement(BriefSection, {
      title: "Construction Pipeline",
      color: "#67e8f9"
    }, content.construction_pipeline.map((p, i) => /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        marginBottom: '0.5rem',
        fontSize: '0.85rem',
        color: '#334155'
      }
    }, "\u2022 ", typeof p === 'string' ? p : p.description || p.summary || JSON.stringify(p)))), content.operator_movements && content.operator_movements.length > 0 && /*#__PURE__*/React.createElement(BriefSection, {
      title: "Operator Movements",
      color: "#fbbf24"
    }, content.operator_movements.map((o, i) => /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        marginBottom: '0.5rem',
        fontSize: '0.85rem',
        color: '#334155'
      }
    }, "\u2022 ", typeof o === 'string' ? o : o.description || o.summary || JSON.stringify(o)))), content.risk_watchlist && content.risk_watchlist.length > 0 && /*#__PURE__*/React.createElement(BriefSection, {
      title: "Risk Watchlist",
      color: "#f87171"
    }, content.risk_watchlist.map((r, i) => /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        marginBottom: '0.5rem',
        fontSize: '0.85rem',
        color: '#334155'
      }
    }, "\u2022 ", typeof r === 'string' ? r : r.description || r.summary || JSON.stringify(r)))), content.recommended_actions && content.recommended_actions.length > 0 && /*#__PURE__*/React.createElement(BriefSection, {
      title: "Recommended Actions",
      color: "#14b8a6"
    }, content.recommended_actions.map((a, i) => /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        marginBottom: '0.5rem',
        fontSize: '0.85rem',
        color: '#334155'
      }
    }, i + 1, ". ", typeof a === 'string' ? a : a.action || a.description || JSON.stringify(a)))));
  }

  // Fallback: plain text
  return /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#F1F5F9',
      border: '1px solid #e2e8f0',
      borderRadius: '12px',
      padding: '1.5rem'
    }
  }, /*#__PURE__*/React.createElement("pre", {
    style: {
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: '0.85rem',
      color: '#0f172a',
      whiteSpace: 'pre-wrap',
      lineHeight: '1.6'
    }
  }, typeof content === 'string' ? content : JSON.stringify(content, null, 2)));
}
function BriefSection({
  title,
  color,
  children
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      borderRadius: '12px',
      padding: '1.25rem'
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '0.85rem',
      fontWeight: 700,
      color: color,
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
      marginBottom: '0.75rem',
      paddingBottom: '0.5rem',
      borderBottom: `1px solid ${color}33`
    }
  }, title), children);
}

// ======= QUOTING PAGE =======
function QuotingPage({
  user
}) {
  const US_STATES = ['AL', 'AK', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DE', 'FL', 'GA', 'HI', 'ID', 'IL', 'IN', 'IA', 'KS', 'KY', 'LA', 'ME', 'MD', 'MA', 'MI', 'MN', 'MS', 'MO', 'MT', 'NE', 'NV', 'NH', 'NJ', 'NM', 'NY', 'NC', 'ND', 'OH', 'OK', 'OR', 'PA', 'RI', 'SC', 'SD', 'TN', 'TX', 'UT', 'VT', 'VA', 'WA', 'WV', 'WI', 'WY'];
  const [form, setForm] = useState({
    sqft: '',
    loss_rents: '',
    city: '',
    state: 'TX',
    rc_per_sf: '120',
    aop_buydown: false,
    street: '',
    zip: ''
  });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [candidates, setCandidates] = useState([]);
  const [needsCounty, setNeedsCounty] = useState(false);
  const [countyOverride, setCountyOverride] = useState('');
  const [history, setHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  // Admin: rate groups & county mapping editors
  const isSuperAdmin = user && user.is_super_admin;
  const [adminTab, setAdminTab] = useState(null); // 'rates' | 'counties' | null
  const [rateGroups, setRateGroups] = useState([]);
  const [countyMappings, setCountyMappings] = useState([]);
  const [countyMapState, setCountyMapState] = useState('TX');
  const [newMapping, setNewMapping] = useState({
    state: 'TX',
    county_name: '',
    group_name: ''
  });
  const fetchHistory = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/quotes/history`);
      const data = await res.json();
      if (data.success) setHistory(data.quotes || []);
    } catch (e) {
      console.error(e);
    }
  };
  const fetchRateGroups = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/admin/rate-groups`);
      const data = await res.json();
      if (data.success) setRateGroups(data.groups || []);
    } catch (e) {
      console.error(e);
    }
  };
  const fetchCountyMappings = async st => {
    try {
      const res = await fetch(`${API_BASE}/api/admin/county-mapping?state=${st || countyMapState}`);
      const data = await res.json();
      if (data.success) setCountyMappings(data.mappings || []);
    } catch (e) {
      console.error(e);
    }
  };
  const submitQuote = async override => {
    setLoading(true);
    setError('');
    setResult(null);
    setNeedsCounty(false);
    setCandidates([]);
    try {
      const body = {
        sqft: parseInt(form.sqft),
        loss_rents: parseFloat(form.loss_rents),
        city: form.city,
        state: form.state,
        rc_per_sf: parseFloat(form.rc_per_sf || '120'),
        aop_buydown: form.aop_buydown
      };
      if (form.street) body.street = form.street;
      if (form.zip) body.zip = form.zip;
      if (override) body.county_override = override;
      const res = await fetch(`${API_BASE}/api/quotes/property`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (data.needs_county) {
        setNeedsCounty(true);
        setCandidates(data.candidates || []);
        setError(data.message || 'Could not determine county.');
      } else if (data.needs_county_selection) {
        setNeedsCounty(true);
        setCandidates(data.candidates || []);
        setCountyOverride(data.county || '');
        setError(data.message || 'Please confirm county.');
      } else if (data.success) {
        setResult(data);
        fetchHistory();
      } else {
        setError(data.message || 'Quote failed');
      }
    } catch (e) {
      setError('Network error');
    }
    setLoading(false);
  };
  const handleSubmit = e => {
    e.preventDefault();
    if (!form.sqft || !form.loss_rents || !form.city || !form.state) {
      setError('All required fields must be filled');
      return;
    }
    submitQuote(null);
  };
  const handleCountySelect = () => {
    if (countyOverride) submitQuote(countyOverride);
  };
  const fmt = n => {
    if (n == null) return '-';
    return '$' + Number(n).toLocaleString('en-US', {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    });
  };
  const addCountyMapping = async () => {
    if (!newMapping.state || !newMapping.county_name || !newMapping.group_name) return;
    try {
      await fetch(`${API_BASE}/api/admin/county-mapping`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(newMapping)
      });
      fetchCountyMappings(newMapping.state);
      setNewMapping({
        ...newMapping,
        county_name: ''
      });
    } catch (e) {
      console.error(e);
    }
  };
  const deleteMapping = async id => {
    try {
      await fetch(`${API_BASE}/api/admin/county-mapping/${id}`, {
        method: 'DELETE'
      });
      fetchCountyMappings();
    } catch (e) {
      console.error(e);
    }
  };
  const groupNames = rateGroups.filter(g => g.name !== 'AOP Buydown').map(g => g.name);
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '1.5rem',
      fontWeight: 700,
      color: '#14b8a6',
      marginBottom: '1.5rem'
    }
  }, "Property Quote Calculator"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: '1fr 1fr',
      gap: '2rem'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      borderRadius: '12px',
      padding: '1.5rem'
    }
  }, /*#__PURE__*/React.createElement("form", {
    onSubmit: handleSubmit
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'grid',
      gap: '1rem'
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    style: {
      display: 'block',
      fontSize: '0.75rem',
      color: '#64748b',
      textTransform: 'uppercase',
      fontWeight: 600,
      marginBottom: '0.4rem'
    }
  }, "Total Square Feet *"), /*#__PURE__*/React.createElement("input", {
    style: {
      ...styles.input,
      width: '100%',
      boxSizing: 'border-box'
    },
    type: "number",
    required: true,
    min: "1",
    placeholder: "e.g. 250000",
    value: form.sqft,
    onChange: e => setForm({
      ...form,
      sqft: e.target.value
    })
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    style: {
      display: 'block',
      fontSize: '0.75rem',
      color: '#64748b',
      textTransform: 'uppercase',
      fontWeight: 600,
      marginBottom: '0.4rem'
    }
  }, "Loss of Rents ($) *"), /*#__PURE__*/React.createElement("input", {
    style: {
      ...styles.input,
      width: '100%',
      boxSizing: 'border-box'
    },
    type: "number",
    required: true,
    min: "0",
    step: "0.01",
    placeholder: "e.g. 500000",
    value: form.loss_rents,
    onChange: e => setForm({
      ...form,
      loss_rents: e.target.value
    })
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: '2fr 1fr',
      gap: '0.75rem'
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    style: {
      display: 'block',
      fontSize: '0.75rem',
      color: '#64748b',
      textTransform: 'uppercase',
      fontWeight: 600,
      marginBottom: '0.4rem'
    }
  }, "City *"), /*#__PURE__*/React.createElement("input", {
    style: {
      ...styles.input,
      width: '100%',
      boxSizing: 'border-box'
    },
    required: true,
    placeholder: "e.g. Dallas",
    value: form.city,
    onChange: e => setForm({
      ...form,
      city: e.target.value
    })
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    style: {
      display: 'block',
      fontSize: '0.75rem',
      color: '#64748b',
      textTransform: 'uppercase',
      fontWeight: 600,
      marginBottom: '0.4rem'
    }
  }, "State *"), /*#__PURE__*/React.createElement("select", {
    style: {
      ...styles.select,
      width: '100%',
      boxSizing: 'border-box'
    },
    value: form.state,
    onChange: e => setForm({
      ...form,
      state: e.target.value
    })
  }, US_STATES.map(s => /*#__PURE__*/React.createElement("option", {
    key: s,
    value: s
  }, s))))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    style: {
      display: 'block',
      fontSize: '0.75rem',
      color: '#64748b',
      textTransform: 'uppercase',
      fontWeight: 600,
      marginBottom: '0.4rem'
    }
  }, "Replacement Cost / SF"), /*#__PURE__*/React.createElement("input", {
    style: {
      ...styles.input,
      width: '100%',
      boxSizing: 'border-box'
    },
    type: "number",
    min: "1",
    step: "0.01",
    value: form.rc_per_sf,
    onChange: e => setForm({
      ...form,
      rc_per_sf: e.target.value
    })
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '0.75rem'
    }
  }, /*#__PURE__*/React.createElement("label", {
    style: {
      fontSize: '0.85rem',
      color: '#0f172a',
      cursor: 'pointer',
      display: 'flex',
      alignItems: 'center',
      gap: '0.5rem'
    }
  }, /*#__PURE__*/React.createElement("input", {
    type: "checkbox",
    checked: form.aop_buydown,
    onChange: e => setForm({
      ...form,
      aop_buydown: e.target.checked
    }),
    style: {
      width: '18px',
      height: '18px',
      accentColor: '#34d399'
    }
  }), "AOP Buydown (+0.0345 to rate)")), /*#__PURE__*/React.createElement("div", {
    style: {
      borderTop: '1px solid #e2e8f0',
      paddingTop: '1rem',
      marginTop: '0.25rem'
    }
  }, /*#__PURE__*/React.createElement("label", {
    style: {
      display: 'block',
      fontSize: '0.7rem',
      color: '#94a3b8',
      textTransform: 'uppercase',
      fontWeight: 600,
      marginBottom: '0.75rem'
    }
  }, "Optional: Improve county accuracy"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: '2fr 1fr',
      gap: '0.75rem'
    }
  }, /*#__PURE__*/React.createElement("input", {
    style: {
      ...styles.input,
      width: '100%',
      boxSizing: 'border-box'
    },
    placeholder: "Street address",
    value: form.street,
    onChange: e => setForm({
      ...form,
      street: e.target.value
    })
  }), /*#__PURE__*/React.createElement("input", {
    style: {
      ...styles.input,
      width: '100%',
      boxSizing: 'border-box'
    },
    placeholder: "ZIP",
    value: form.zip,
    onChange: e => setForm({
      ...form,
      zip: e.target.value
    })
  }))), /*#__PURE__*/React.createElement("button", {
    type: "submit",
    style: {
      ...styles.btnPrimary,
      width: '100%',
      padding: '0.85rem',
      fontSize: '1rem'
    },
    disabled: loading
  }, loading ? 'Calculating...' : 'Get Quote'))), needsCounty && /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: '1rem',
      background: 'rgba(251,191,36,0.08)',
      border: '1px solid rgba(251,191,36,0.3)',
      borderRadius: '8px',
      padding: '1rem'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      color: '#fbbf24',
      fontSize: '0.9rem',
      fontWeight: 600,
      marginBottom: '0.5rem'
    }
  }, candidates.length > 0 ? 'Select County' : 'County Required'), candidates.length > 0 ? /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.5rem',
      flexWrap: 'wrap',
      marginBottom: '0.75rem'
    }
  }, candidates.map(c => /*#__PURE__*/React.createElement("button", {
    key: c,
    style: {
      ...styles.btn,
      fontSize: '0.85rem',
      ...(countyOverride === c ? {
        borderColor: '#34d399',
        color: '#14b8a6'
      } : {})
    },
    onClick: () => setCountyOverride(c)
  }, c))) : /*#__PURE__*/React.createElement("input", {
    style: {
      ...styles.input,
      width: '100%',
      boxSizing: 'border-box',
      marginBottom: '0.75rem'
    },
    placeholder: "Type county name",
    value: countyOverride,
    onChange: e => setCountyOverride(e.target.value)
  }), /*#__PURE__*/React.createElement("button", {
    style: styles.btnPrimary,
    onClick: handleCountySelect,
    disabled: !countyOverride
  }, "Use This County")), error && !needsCounty && /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: '1rem',
      color: '#ef4444',
      fontSize: '0.9rem'
    }
  }, error)), /*#__PURE__*/React.createElement("div", null, result ? /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      borderRadius: '12px',
      padding: '1.5rem'
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '1.1rem',
      color: '#14b8a6',
      marginTop: 0,
      marginBottom: '1.25rem'
    }
  }, "Quote Breakdown"), result.warnings && result.warnings.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      background: 'rgba(251,191,36,0.08)',
      border: '1px solid rgba(251,191,36,0.3)',
      borderRadius: '8px',
      padding: '0.75rem',
      marginBottom: '1rem'
    }
  }, result.warnings.map((w, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      color: '#fbbf24',
      fontSize: '0.85rem'
    }
  }, w))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'grid',
      gap: '0.6rem'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      padding: '0.5rem 0',
      borderBottom: '1px solid #0f172a'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#64748b',
      fontSize: '0.9rem'
    }
  }, "County"), /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#0f172a',
      fontSize: '0.9rem',
      fontWeight: 600
    }
  }, result.county)), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      padding: '0.5rem 0',
      borderBottom: '1px solid #0f172a'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#64748b',
      fontSize: '0.9rem'
    }
  }, "Grouping"), /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#3b82f6',
      fontSize: '0.9rem',
      fontWeight: 600
    }
  }, result.grouping)), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      padding: '0.5rem 0',
      borderBottom: '1px solid #0f172a'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#64748b',
      fontSize: '0.9rem'
    }
  }, "Rate x100"), /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#0f172a',
      fontSize: '0.9rem',
      fontFamily: "'JetBrains Mono', monospace"
    }
  }, result.group_rate_x100, result.aop_buydown ? ` + 0.0345 AOP` : '', " = ", result.effective_rate_x100)), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      padding: '0.5rem 0',
      borderBottom: '1px solid #0f172a'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#64748b',
      fontSize: '0.9rem'
    }
  }, "Replacement Cost"), /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#0f172a',
      fontSize: '0.9rem',
      fontFamily: "'JetBrains Mono', monospace"
    }
  }, fmt(result.replacement_cost))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      padding: '0.5rem 0',
      borderBottom: '1px solid #0f172a'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#64748b',
      fontSize: '0.9rem'
    }
  }, "Total TIV"), /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#0f172a',
      fontSize: '0.9rem',
      fontFamily: "'JetBrains Mono', monospace"
    }
  }, fmt(result.total_tiv))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      padding: '0.5rem 0',
      borderBottom: '1px solid #e2e8f0'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#64748b',
      fontSize: '0.9rem'
    }
  }, "Base Premium"), /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#0f172a',
      fontSize: '0.9rem',
      fontWeight: 600,
      fontFamily: "'JetBrains Mono', monospace"
    }
  }, fmt(result.base_premium))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      padding: '0.5rem 0',
      borderBottom: '1px solid #e2e8f0'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#64748b',
      fontSize: '0.9rem'
    }
  }, "Taxes (6%)"), /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#0f172a',
      fontSize: '0.9rem',
      fontFamily: "'JetBrains Mono', monospace"
    }
  }, fmt(result.taxes))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      padding: '0.75rem 0',
      background: 'rgba(20,184,166,0.06)',
      borderRadius: '8px',
      paddingLeft: '0.75rem',
      paddingRight: '0.75rem',
      marginTop: '0.25rem'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#14b8a6',
      fontSize: '1.05rem',
      fontWeight: 700
    }
  }, "Total Premium"), /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#14b8a6',
      fontSize: '1.2rem',
      fontWeight: 700,
      fontFamily: "'JetBrains Mono', monospace"
    }
  }, fmt(result.total_premium))))) : /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      borderRadius: '12px',
      padding: '3rem',
      textAlign: 'center'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      color: '#94a3b8',
      fontSize: '0.95rem'
    }
  }, "Fill in the form and click \"Get Quote\" to see the premium breakdown.")), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: '1rem'
    }
  }, /*#__PURE__*/React.createElement("button", {
    style: {
      ...styles.btn,
      fontSize: '0.85rem'
    },
    onClick: () => {
      setShowHistory(!showHistory);
      if (!showHistory) fetchHistory();
    }
  }, showHistory ? 'Hide' : 'Show', " Recent Quotes"), showHistory && history.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: '0.75rem',
      display: 'flex',
      flexDirection: 'column',
      gap: '0.5rem'
    }
  }, history.map(q => /*#__PURE__*/React.createElement("div", {
    key: q.id,
    style: {
      background: '#F1F5F9',
      border: '1px solid #e2e8f0',
      borderRadius: '8px',
      padding: '0.75rem',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      flexWrap: 'wrap',
      gap: '0.5rem'
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#0f172a',
      fontSize: '0.85rem',
      fontWeight: 600
    }
  }, q.city, ", ", q.state), /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#64748b',
      fontSize: '0.8rem',
      marginLeft: '0.75rem'
    }
  }, q.sqft.toLocaleString(), " SF"), /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#64748b',
      fontSize: '0.8rem',
      marginLeft: '0.5rem'
    }
  }, q.grouping)), /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#14b8a6',
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: '0.9rem',
      fontWeight: 600
    }
  }, fmt(q.total_premium)))))))), isSuperAdmin && /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: '2rem',
      borderTop: '2px solid #e2e8f0',
      paddingTop: '1.5rem'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.75rem',
      marginBottom: '1rem'
    }
  }, /*#__PURE__*/React.createElement("button", {
    style: {
      ...styles.btn,
      ...(adminTab === 'rates' ? {
        borderColor: '#34d399',
        color: '#14b8a6'
      } : {})
    },
    onClick: () => {
      setAdminTab(adminTab === 'rates' ? null : 'rates');
      fetchRateGroups();
    }
  }, "Rate Groups"), /*#__PURE__*/React.createElement("button", {
    style: {
      ...styles.btn,
      ...(adminTab === 'counties' ? {
        borderColor: '#34d399',
        color: '#14b8a6'
      } : {})
    },
    onClick: () => {
      setAdminTab(adminTab === 'counties' ? null : 'counties');
      fetchCountyMappings();
    }
  }, "County Mappings")), adminTab === 'rates' && /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      borderRadius: '12px',
      overflow: 'hidden'
    }
  }, /*#__PURE__*/React.createElement("table", {
    style: {
      width: '100%',
      borderCollapse: 'collapse',
      fontSize: '0.85rem'
    }
  }, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", {
    style: {
      textAlign: 'left',
      padding: '0.6rem 1rem',
      borderBottom: '2px solid #e2e8f0',
      color: '#64748b',
      fontWeight: 600,
      fontSize: '0.75rem',
      textTransform: 'uppercase'
    }
  }, "Group Name"), /*#__PURE__*/React.createElement("th", {
    style: {
      textAlign: 'right',
      padding: '0.6rem 1rem',
      borderBottom: '2px solid #e2e8f0',
      color: '#64748b',
      fontWeight: 600,
      fontSize: '0.75rem',
      textTransform: 'uppercase'
    }
  }, "Rate"), /*#__PURE__*/React.createElement("th", {
    style: {
      textAlign: 'right',
      padding: '0.6rem 1rem',
      borderBottom: '2px solid #e2e8f0',
      color: '#64748b',
      fontWeight: 600,
      fontSize: '0.75rem',
      textTransform: 'uppercase'
    }
  }, "Rate x100"))), /*#__PURE__*/React.createElement("tbody", null, rateGroups.map(g => /*#__PURE__*/React.createElement("tr", {
    key: g.id
  }, /*#__PURE__*/React.createElement("td", {
    style: {
      padding: '0.6rem 1rem',
      borderBottom: '1px solid #0f172a',
      color: '#0f172a'
    }
  }, g.name), /*#__PURE__*/React.createElement("td", {
    style: {
      padding: '0.6rem 1rem',
      borderBottom: '1px solid #0f172a',
      color: '#64748b',
      textAlign: 'right',
      fontFamily: "'JetBrains Mono', monospace"
    }
  }, g.rate), /*#__PURE__*/React.createElement("td", {
    style: {
      padding: '0.6rem 1rem',
      borderBottom: '1px solid #0f172a',
      color: '#14b8a6',
      textAlign: 'right',
      fontFamily: "'JetBrains Mono', monospace",
      fontWeight: 600
    }
  }, g.rate_x100)))))), adminTab === 'counties' && /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      borderRadius: '12px',
      padding: '1.25rem'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.75rem',
      marginBottom: '1rem',
      alignItems: 'flex-end',
      flexWrap: 'wrap'
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    style: {
      display: 'block',
      fontSize: '0.7rem',
      color: '#64748b',
      textTransform: 'uppercase',
      fontWeight: 600,
      marginBottom: '0.3rem'
    }
  }, "State"), /*#__PURE__*/React.createElement("select", {
    style: styles.select,
    value: countyMapState,
    onChange: e => {
      setCountyMapState(e.target.value);
      fetchCountyMappings(e.target.value);
    }
  }, US_STATES.map(s => /*#__PURE__*/React.createElement("option", {
    key: s,
    value: s
  }, s)))), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1
    }
  }, /*#__PURE__*/React.createElement("label", {
    style: {
      display: 'block',
      fontSize: '0.7rem',
      color: '#64748b',
      textTransform: 'uppercase',
      fontWeight: 600,
      marginBottom: '0.3rem'
    }
  }, "County Name"), /*#__PURE__*/React.createElement("input", {
    style: {
      ...styles.input,
      width: '100%',
      boxSizing: 'border-box'
    },
    placeholder: "e.g. Harris",
    value: newMapping.county_name,
    onChange: e => setNewMapping({
      ...newMapping,
      state: countyMapState,
      county_name: e.target.value
    })
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    style: {
      display: 'block',
      fontSize: '0.7rem',
      color: '#64748b',
      textTransform: 'uppercase',
      fontWeight: 600,
      marginBottom: '0.3rem'
    }
  }, "Group"), /*#__PURE__*/React.createElement("select", {
    style: styles.select,
    value: newMapping.group_name,
    onChange: e => setNewMapping({
      ...newMapping,
      group_name: e.target.value
    })
  }, /*#__PURE__*/React.createElement("option", {
    value: ""
  }, "Select group..."), groupNames.map(n => /*#__PURE__*/React.createElement("option", {
    key: n,
    value: n
  }, n)))), /*#__PURE__*/React.createElement("button", {
    style: styles.btnPrimary,
    onClick: addCountyMapping
  }, "Add")), countyMappings.length > 0 ? /*#__PURE__*/React.createElement("table", {
    style: {
      width: '100%',
      borderCollapse: 'collapse',
      fontSize: '0.85rem'
    }
  }, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", {
    style: {
      textAlign: 'left',
      padding: '0.5rem 0.75rem',
      borderBottom: '1px solid #e2e8f0',
      color: '#64748b',
      fontSize: '0.7rem',
      textTransform: 'uppercase'
    }
  }, "County"), /*#__PURE__*/React.createElement("th", {
    style: {
      textAlign: 'left',
      padding: '0.5rem 0.75rem',
      borderBottom: '1px solid #e2e8f0',
      color: '#64748b',
      fontSize: '0.7rem',
      textTransform: 'uppercase'
    }
  }, "Group"), /*#__PURE__*/React.createElement("th", {
    style: {
      padding: '0.5rem 0.75rem',
      borderBottom: '1px solid #e2e8f0',
      width: '60px'
    }
  }))), /*#__PURE__*/React.createElement("tbody", null, countyMappings.map(m => /*#__PURE__*/React.createElement("tr", {
    key: m.id
  }, /*#__PURE__*/React.createElement("td", {
    style: {
      padding: '0.5rem 0.75rem',
      borderBottom: '1px solid #0f172a',
      color: '#0f172a'
    }
  }, m.county_name), /*#__PURE__*/React.createElement("td", {
    style: {
      padding: '0.5rem 0.75rem',
      borderBottom: '1px solid #0f172a',
      color: '#3b82f6'
    }
  }, m.group_name), /*#__PURE__*/React.createElement("td", {
    style: {
      padding: '0.5rem 0.75rem',
      borderBottom: '1px solid #0f172a'
    }
  }, /*#__PURE__*/React.createElement("button", {
    style: {
      ...styles.btn,
      fontSize: '0.75rem',
      padding: '0.2rem 0.5rem',
      color: '#ef4444',
      borderColor: '#ef4444'
    },
    onClick: () => deleteMapping(m.id)
  }, "X")))))) : /*#__PURE__*/React.createElement("div", {
    style: {
      color: '#94a3b8',
      fontSize: '0.85rem',
      fontStyle: 'italic'
    }
  }, "No county mappings for ", countyMapState, ". Fallback grouping will be used."))));
}

// ======= UNDERWRITING SHEET (Admin Only) =======
const UW_SECTIONS = {
  location: 'Location',
  values: 'Values & BI',
  construction: 'Construction & Occupancy',
  building: 'Building Details',
  structure: 'Roof & Structural Features',
  premium: 'Premium & Tax'
};
function UnderwritingSheet({
  user
}) {
  const [columns, setColumns] = useState([]);
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [showHistory, setShowHistory] = useState(false);
  const [showNewForm, setShowNewForm] = useState(false);
  const [addUnitsTarget, setAddUnitsTarget] = useState(null);
  const [editRow, setEditRow] = useState(null);
  const [showImportModal, setShowImportModal] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState(null); // {community_id, name}
  const [deleting, setDeleting] = useState(false);
  const [hoveredRow, setHoveredRow] = useState(null);
  const loadColumns = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/underwriting/columns`);
      const d = await res.json();
      if (d.ok) setColumns(d.columns);else setLoadError(d.error || d.message || 'Failed to load columns');
    } catch (e) {
      console.error('Failed to load columns', e);
      setLoadError('Failed to load columns: ' + e.message);
    }
  };
  const loadRows = async () => {
    setLoading(true);
    setLoadError('');
    try {
      const res = await fetch(`${API_BASE}/api/underwriting/rows?latest=${!showHistory}`);
      const d = await res.json();
      if (d.ok) {
        setRows(d.data);
      } else {
        setRows([]);
        setLoadError(d.error || d.message || 'Failed to load rows');
      }
    } catch (e) {
      console.error('Failed to load rows', e);
      setRows([]);
      setLoadError('Failed to load rows: ' + e.message);
    }
    setLoading(false);
  };
  useEffect(() => {
    loadColumns();
  }, []);
  useEffect(() => {
    loadRows();
  }, [showHistory]);
  const exportXlsx = mode => {
    window.open(`${API_BASE}/api/underwriting/export?mode=${mode}`, '_blank');
  };
  const deleteCommunity = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      const res = await fetch(`${API_BASE}/api/underwriting/communities/${deleteTarget.community_id}?mode=soft`, {
        method: 'DELETE'
      });
      const d = await res.json();
      if (d.ok) {
        setDeleteTarget(null);
        loadRows();
      } else {
        alert(d.error || 'Delete failed');
      }
    } catch (e) {
      alert('Network error: ' + e.message);
    }
    setDeleting(false);
  };

  // ── Sticky column config ──
  const stickyKeys = ['location_name', 'city', 'state_province_district'];
  const stickyWidths = [160, 120, 100]; // px widths for each sticky col
  const actionsWidth = 130;
  const versionWidth = 60;
  const stickyLeftOffsets = stickyKeys.map((_, i) => {
    let offset = actionsWidth;
    if (showHistory) offset += versionWidth;
    for (let j = 0; j < i; j++) offset += stickyWidths[j];
    return offset;
  });

  // ── Section grouping for header row ──
  const sectionOrder = ['location', 'values', 'construction', 'building', 'structure', 'premium'];
  const sectionColors = {
    location: '#6366f1',
    values: '#14b8a6',
    construction: '#f59e0b',
    building: '#3b82f6',
    structure: '#8b5cf6',
    premium: '#ef4444'
  };
  const buildSectionGroups = () => {
    if (!columns.length) return [];
    const groups = [];
    let curSection = null;
    let curCount = 0;
    columns.forEach(col => {
      const sec = col.section || 'other';
      if (sec !== curSection) {
        if (curSection !== null) groups.push({
          section: curSection,
          count: curCount
        });
        curSection = sec;
        curCount = 1;
      } else {
        curCount++;
      }
    });
    if (curSection !== null) groups.push({
      section: curSection,
      count: curCount
    });
    return groups;
  };

  // ── Cell formatter ──
  const formatCell = (col, value) => {
    if (!value && value !== 0) return '';
    const v = String(value);
    if (!v) return '';
    if (col.type === 'currency') {
      const n = Number(v);
      if (isNaN(n)) return v;
      return '$' + n.toLocaleString(undefined, {
        minimumFractionDigits: 0,
        maximumFractionDigits: 0
      });
    }
    if (col.type === 'percent') {
      const n = Number(v);
      if (isNaN(n)) return v;
      return n.toFixed(1) + '%';
    }
    if (col.type === 'date' && v.match(/^\d{4}-\d{2}-\d{2}/)) {
      const parts = v.split('-');
      return parts[1] + '/' + parts[2].substring(0, 2) + '/' + parts[0];
    }
    return v;
  };

  // ── Color scheme ──
  const rowBgEven = '#FFFFFF';
  const rowBgOdd = '#F7F9FC';
  const rowBgHover = '#162032';
  const headerBg = '#080e1a';
  const groupHeaderBg = '#0a1020';
  const sectionGroups = buildSectionGroups();
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '1rem',
      flexWrap: 'wrap',
      gap: '0.75rem'
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h2", {
    style: {
      ...styles.sectionTitle,
      fontSize: '1.3rem',
      margin: 0
    }
  }, "Underwriting Sheet"), /*#__PURE__*/React.createElement("p", {
    style: {
      color: '#64748b',
      fontSize: '0.85rem',
      margin: '0.25rem 0 0'
    }
  }, rows.length, " ", showHistory ? 'total rows' : 'communities')), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.5rem',
      flexWrap: 'wrap'
    }
  }, /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: {
      ...styles.actionBtn,
      borderColor: '#14b8a6',
      color: '#14b8a6'
    },
    onClick: () => setShowNewForm(true)
  }, "+ New Community"), /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: {
      ...styles.actionBtn,
      borderColor: '#6366f1',
      color: '#818cf8'
    },
    onClick: () => setShowImportModal(true)
  }, "Import Spreadsheet"), /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: styles.actionBtn,
    onClick: () => setShowHistory(!showHistory)
  }, showHistory ? 'Latest Only' : 'Show History'), /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: styles.actionBtn,
    onClick: () => exportXlsx('latest')
  }, "Export Latest XLSX"), showHistory && /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: styles.actionBtn,
    onClick: () => exportXlsx('all')
  }, "Export All XLSX"))), loadError && /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '0.75rem 1rem',
      background: 'rgba(239,68,68,0.1)',
      border: '1px solid rgba(239,68,68,0.3)',
      borderRadius: '0.5rem',
      color: '#f87171',
      fontSize: '0.85rem',
      marginBottom: '1rem',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center'
    }
  }, /*#__PURE__*/React.createElement("span", null, loadError), /*#__PURE__*/React.createElement("button", {
    onClick: () => {
      setLoadError('');
      loadRows();
    },
    style: {
      background: 'none',
      border: '1px solid #f87171',
      color: '#f87171',
      borderRadius: '4px',
      padding: '0.25rem 0.75rem',
      cursor: 'pointer',
      fontSize: '0.78rem',
      whiteSpace: 'nowrap',
      marginLeft: '1rem'
    }
  }, "Retry")), loading ? /*#__PURE__*/React.createElement("div", {
    style: {
      textAlign: 'center',
      padding: '3rem',
      color: '#64748b'
    }
  }, "Loading...") : rows.length === 0 && !loadError ? /*#__PURE__*/React.createElement(EmptyState, {
    title: "No underwriting records",
    subtitle: "Click \"+ New Community\" to add the first record",
    icon: /*#__PURE__*/React.createElement("svg", {
      width: "36",
      height: "36",
      viewBox: "0 0 24 24",
      fill: "none",
      stroke: "currentColor",
      strokeWidth: "1.5",
      className: "text-slate-600"
    }, /*#__PURE__*/React.createElement("rect", {
      x: "3",
      y: "3",
      width: "18",
      height: "18",
      rx: "2"
    }), /*#__PURE__*/React.createElement("path", {
      d: "M3 9h18M9 21V9"
    }))
  }) : rows.length === 0 ? null : /*#__PURE__*/React.createElement("div", {
    style: {
      overflowX: 'auto',
      border: '1px solid #e2e8f0',
      borderRadius: '0.5rem',
      maxHeight: '74vh',
      overflowY: 'auto'
    }
  }, /*#__PURE__*/React.createElement("table", {
    style: {
      borderCollapse: 'collapse',
      width: 'max-content',
      minWidth: '100%',
      fontSize: '0.76rem'
    }
  }, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", {
    style: {
      position: 'sticky',
      top: 0,
      zIndex: 40,
      background: groupHeaderBg
    }
  }, /*#__PURE__*/React.createElement("th", {
    style: {
      position: 'sticky',
      left: 0,
      zIndex: 50,
      background: groupHeaderBg,
      borderBottom: '1px solid #e2e8f0',
      padding: 0,
      minWidth: actionsWidth + 'px'
    },
    rowSpan: "1"
  }), showHistory && /*#__PURE__*/React.createElement("th", {
    style: {
      position: 'sticky',
      top: 0,
      zIndex: 40,
      background: groupHeaderBg,
      borderBottom: '1px solid #e2e8f0',
      padding: 0,
      minWidth: versionWidth + 'px'
    }
  }), stickyKeys.map((sk, si) => /*#__PURE__*/React.createElement("th", {
    key: sk,
    style: {
      position: 'sticky',
      left: stickyLeftOffsets[si] + 'px',
      zIndex: 45,
      background: groupHeaderBg,
      borderBottom: '1px solid #e2e8f0',
      padding: 0,
      minWidth: stickyWidths[si] + 'px'
    }
  })), sectionGroups.map(g => {
    // subtract sticky columns that belong to this section
    const stickyInSection = stickyKeys.filter((sk, si) => {
      const col = columns.find(c => c.key === sk);
      return col && col.section === g.section;
    }).length;
    const span = g.count - stickyInSection;
    if (span <= 0) return null;
    const color = sectionColors[g.section] || '#64748b';
    const label = UW_SECTIONS[g.section] || g.section;
    return /*#__PURE__*/React.createElement("th", {
      key: g.section,
      colSpan: span,
      style: {
        background: groupHeaderBg,
        padding: '0.35rem 0.5rem',
        borderBottom: `2px solid ${color}`,
        color,
        fontSize: '0.65rem',
        fontWeight: 700,
        textTransform: 'uppercase',
        letterSpacing: '0.06em',
        textAlign: 'center',
        whiteSpace: 'nowrap'
      }
    }, label);
  })), /*#__PURE__*/React.createElement("tr", {
    style: {
      position: 'sticky',
      top: '26px',
      zIndex: 38,
      background: headerBg
    }
  }, /*#__PURE__*/React.createElement("th", {
    style: {
      position: 'sticky',
      left: 0,
      zIndex: 48,
      background: headerBg,
      padding: '0.4rem 0.5rem',
      borderBottom: '2px solid #e2e8f0',
      color: '#64748b',
      fontWeight: 700,
      textAlign: 'left',
      whiteSpace: 'nowrap',
      fontSize: '0.68rem',
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
      minWidth: actionsWidth + 'px'
    }
  }, "Actions"), showHistory && /*#__PURE__*/React.createElement("th", {
    style: {
      position: 'sticky',
      top: '26px',
      zIndex: 38,
      background: headerBg,
      padding: '0.4rem 0.5rem',
      borderBottom: '2px solid #e2e8f0',
      color: '#64748b',
      fontWeight: 700,
      textAlign: 'left',
      whiteSpace: 'nowrap',
      fontSize: '0.68rem',
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
      minWidth: versionWidth + 'px'
    }
  }, "Ver"), columns.map((col, ci) => {
    const si = stickyKeys.indexOf(col.key);
    const isSticky = si >= 0;
    const isNumeric = ['currency', 'numeric', 'integer', 'percent'].includes(col.type);
    return /*#__PURE__*/React.createElement("th", {
      key: col.key,
      style: {
        position: isSticky ? 'sticky' : 'relative',
        left: isSticky ? stickyLeftOffsets[si] + 'px' : 'auto',
        zIndex: isSticky ? 42 : 38,
        background: headerBg,
        padding: '0.4rem 0.5rem',
        borderBottom: '2px solid #e2e8f0',
        color: '#64748b',
        fontWeight: 700,
        textAlign: isNumeric ? 'right' : 'left',
        whiteSpace: 'nowrap',
        fontSize: '0.68rem',
        textTransform: 'uppercase',
        letterSpacing: '0.05em',
        minWidth: isSticky ? stickyWidths[si] + 'px' : col.type === 'currency' ? '115px' : '95px'
      }
    }, col.header);
  }))), /*#__PURE__*/React.createElement("tbody", null, rows.map((row, ri) => {
    const isHovered = hoveredRow === ri;
    const baseBg = ri % 2 === 0 ? rowBgEven : rowBgOdd;
    const bg = isHovered ? rowBgHover : baseBg;
    const stickyBg = isHovered ? rowBgHover : baseBg;
    return /*#__PURE__*/React.createElement("tr", {
      key: row.id,
      onMouseEnter: () => setHoveredRow(ri),
      onMouseLeave: () => setHoveredRow(null),
      style: {
        borderBottom: '1px solid #e2e8f0',
        background: bg,
        transition: 'background 0.1s'
      }
    }, /*#__PURE__*/React.createElement("td", {
      style: {
        position: 'sticky',
        left: 0,
        zIndex: 10,
        background: stickyBg,
        padding: '0.35rem 0.4rem',
        whiteSpace: 'nowrap',
        transition: 'background 0.1s'
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: 'flex',
        gap: '0.25rem'
      }
    }, /*#__PURE__*/React.createElement("button", {
      className: "action-btn",
      style: {
        ...styles.actionBtn,
        fontSize: '0.63rem',
        padding: '0.12rem 0.35rem'
      },
      onClick: () => setEditRow(row)
    }, "Edit"), /*#__PURE__*/React.createElement("button", {
      className: "action-btn",
      style: {
        ...styles.actionBtn,
        fontSize: '0.63rem',
        padding: '0.12rem 0.35rem',
        borderColor: '#f59e0b',
        color: '#fcd34d'
      },
      onClick: () => setAddUnitsTarget({
        community_id: row.community_id,
        row
      })
    }, "+Units"), /*#__PURE__*/React.createElement("button", {
      className: "action-btn",
      style: {
        ...styles.actionBtn,
        fontSize: '0.63rem',
        padding: '0.12rem 0.35rem',
        borderColor: '#ef4444',
        color: '#f87171'
      },
      onClick: () => setDeleteTarget({
        community_id: row.community_id,
        name: row.location_name || row._community_name || 'this community'
      })
    }, "Del"))), showHistory && /*#__PURE__*/React.createElement("td", {
      style: {
        padding: '0.35rem 0.4rem',
        color: '#94a3b8',
        fontSize: '0.72rem',
        background: bg,
        transition: 'background 0.1s'
      }
    }, row.row_version), columns.map(col => {
      const si = stickyKeys.indexOf(col.key);
      const isSticky = si >= 0;
      const isNumeric = ['currency', 'numeric', 'integer', 'percent'].includes(col.type);
      return /*#__PURE__*/React.createElement("td", {
        key: col.key,
        style: {
          position: isSticky ? 'sticky' : 'relative',
          left: isSticky ? stickyLeftOffsets[si] + 'px' : 'auto',
          zIndex: isSticky ? 10 : 1,
          background: isSticky ? stickyBg : bg,
          padding: '0.35rem 0.5rem',
          color: isNumeric ? '#3b82f6' : '#1e293b',
          maxWidth: '200px',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          textAlign: isNumeric ? 'right' : 'left',
          fontFamily: isNumeric ? "'Orbitron', monospace" : 'inherit',
          fontSize: isNumeric ? '0.73rem' : '0.76rem',
          transition: 'background 0.1s'
        }
      }, formatCell(col, row[col.key]));
    }));
  })))), showNewForm && /*#__PURE__*/React.createElement(UWFormModal, {
    columns: columns,
    onClose: () => setShowNewForm(false),
    onSaved: () => {
      setShowNewForm(false);
      loadRows();
    },
    mode: "create"
  }), editRow && /*#__PURE__*/React.createElement(UWFormModal, {
    columns: columns,
    onClose: () => setEditRow(null),
    onSaved: () => {
      setEditRow(null);
      loadRows();
    },
    mode: "edit",
    initialData: editRow
  }), addUnitsTarget && /*#__PURE__*/React.createElement(UWFormModal, {
    columns: columns,
    onClose: () => setAddUnitsTarget(null),
    onSaved: () => {
      setAddUnitsTarget(null);
      loadRows();
    },
    mode: "add-units",
    initialData: addUnitsTarget.row,
    communityId: addUnitsTarget.community_id
  }), showImportModal && /*#__PURE__*/React.createElement(UWImportModal, {
    onClose: () => setShowImportModal(false),
    onImported: () => {
      setShowImportModal(false);
      loadRows();
    }
  }), deleteTarget && /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'fixed',
      inset: 0,
      zIndex: 9999,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'rgba(0,0,0,0.3)'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#F1F5F9',
      border: '1px solid #e2e8f0',
      borderRadius: '1rem',
      width: '95vw',
      maxWidth: '440px',
      padding: '1.5rem'
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      margin: '0 0 0.75rem',
      color: '#0f172a',
      fontSize: '1.05rem'
    }
  }, "Delete Community"), /*#__PURE__*/React.createElement("p", {
    style: {
      color: '#64748b',
      fontSize: '0.88rem',
      margin: '0 0 0.5rem',
      lineHeight: 1.5
    }
  }, "Are you sure you want to delete ", /*#__PURE__*/React.createElement("strong", {
    style: {
      color: '#f87171'
    }
  }, deleteTarget.name), " and all its rows?"), /*#__PURE__*/React.createElement("p", {
    style: {
      color: '#64748b',
      fontSize: '0.78rem',
      margin: '0 0 1.25rem'
    }
  }, "This is a soft delete. Records can be recovered by an administrator."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'flex-end',
      gap: '0.5rem'
    }
  }, /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: styles.actionBtn,
    onClick: () => setDeleteTarget(null),
    disabled: deleting
  }, "Cancel"), /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: {
      ...styles.actionBtn,
      borderColor: '#ef4444',
      color: '#f87171'
    },
    onClick: deleteCommunity,
    disabled: deleting
  }, deleting ? 'Deleting...' : 'Delete Community')))));
}

// ── Import Spreadsheet Modal ──
function UWImportModal({
  onClose,
  onImported
}) {
  const [file, setFile] = useState(null);
  const [mode, setMode] = useState('merge');
  const [dryRun, setDryRun] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const handleFileChange = e => {
    const f = e.target.files[0];
    if (f) {
      const ext = f.name.split('.').pop().toLowerCase();
      if (!['xlsx', 'csv'].includes(ext)) {
        setError('Please select an .xlsx or .csv file');
        setFile(null);
        return;
      }
      if (f.size > 25 * 1024 * 1024) {
        setError('File too large (max 25MB)');
        setFile(null);
        return;
      }
      setError('');
      setFile(f);
    }
  };
  const doImport = async () => {
    if (!file) {
      setError('Please select a file');
      return;
    }
    setUploading(true);
    setError('');
    setResult(null);
    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('mode', mode);
      formData.append('dry_run', dryRun ? 'true' : 'false');
      formData.append('strict_headers', mode === 'strict' ? 'true' : 'false');
      const res = await fetch(`${API_BASE}/api/underwriting/import`, {
        method: 'POST',
        body: formData
      });
      const d = await res.json();
      if (d.ok) {
        setResult(d.data);
      } else {
        setError(d.error || 'Import failed');
        if (d.data) setResult(d.data);
      }
    } catch (e) {
      setError('Network error: ' + e.message);
    }
    setUploading(false);
  };
  const downloadErrorReport = () => {
    if (!result || !result.errors || result.errors.length === 0) return;
    const rows = [['Row', 'Field', 'Message']];
    result.errors.forEach(e => {
      rows.push([e.rowIndex || '', e.field || '', e.message || '']);
    });
    if (result.warnings) {
      result.warnings.forEach(w => {
        rows.push([w.rowIndex || '', 'WARNING', w.message || '']);
      });
    }
    const csv = rows.map(r => r.map(c => '"' + String(c).replace(/"/g, '""') + '"').join(',')).join('\n');
    const blob = new Blob([csv], {
      type: 'text/csv'
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'import_errors.csv';
    a.click();
    URL.revokeObjectURL(url);
  };
  const downloadTemplate = () => {
    window.open(`${API_BASE}/api/underwriting/import/template`, '_blank');
  };
  const modalBg = {
    position: 'fixed',
    inset: 0,
    zIndex: 9999,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: 'rgba(0,0,0,0.3)'
  };
  const modalBox = {
    background: '#F1F5F9',
    border: '1px solid #e2e8f0',
    borderRadius: '1rem',
    width: '95vw',
    maxWidth: '640px',
    maxHeight: '90vh',
    display: 'flex',
    flexDirection: 'column'
  };
  const labelStyle = {
    display: 'block',
    fontSize: '0.72rem',
    color: '#64748b',
    fontWeight: 600,
    marginBottom: '0.35rem',
    textTransform: 'uppercase',
    letterSpacing: '0.03em'
  };
  const summaryCard = {
    background: '#F7F9FC',
    border: '1px solid #e2e8f0',
    borderRadius: '0.5rem',
    padding: '0.75rem 1rem',
    marginBottom: '0.75rem'
  };
  const summaryRow = {
    display: 'flex',
    justifyContent: 'space-between',
    padding: '0.25rem 0',
    fontSize: '0.85rem'
  };
  const summaryLabel = {
    color: '#64748b'
  };
  const summaryValue = {
    color: '#0f172a',
    fontWeight: 600,
    fontFamily: "'Orbitron', monospace"
  };
  return /*#__PURE__*/React.createElement("div", {
    style: modalBg
  }, /*#__PURE__*/React.createElement("div", {
    style: modalBox
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '1.25rem 1.5rem',
      borderBottom: '1px solid #e2e8f0',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center'
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      margin: 0,
      color: '#0f172a',
      fontSize: '1.1rem'
    }
  }, "Import Spreadsheet"), /*#__PURE__*/React.createElement("button", {
    onClick: onClose,
    style: {
      background: 'none',
      border: 'none',
      color: '#64748b',
      fontSize: '1.5rem',
      cursor: 'pointer'
    }
  }, "\xD7")), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '1.25rem 1.5rem',
      overflowY: 'auto',
      flex: 1
    }
  }, error && /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '0.5rem 0.75rem',
      background: 'rgba(239,68,68,0.1)',
      border: '1px solid rgba(239,68,68,0.3)',
      borderRadius: '6px',
      color: '#f87171',
      fontSize: '0.85rem',
      marginBottom: '1rem'
    }
  }, error), !result ? /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      marginBottom: '1rem'
    }
  }, /*#__PURE__*/React.createElement("label", {
    style: labelStyle
  }, "Upload File (.xlsx or .csv)"), /*#__PURE__*/React.createElement("div", {
    style: {
      border: '2px dashed #e2e8f0',
      borderRadius: '0.5rem',
      padding: '1.5rem',
      textAlign: 'center',
      cursor: 'pointer',
      background: '#F7F9FC',
      transition: 'border-color 0.2s'
    },
    onDragOver: e => {
      e.preventDefault();
      e.currentTarget.style.borderColor = '#6366f1';
    },
    onDragLeave: e => {
      e.currentTarget.style.borderColor = '#e2e8f0';
    },
    onDrop: e => {
      e.preventDefault();
      e.currentTarget.style.borderColor = '#e2e8f0';
      const f = e.dataTransfer.files[0];
      if (f) {
        const inp = {
          target: {
            files: [f]
          }
        };
        handleFileChange(inp);
      }
    },
    onClick: () => document.getElementById('uw-import-file').click()
  }, /*#__PURE__*/React.createElement("input", {
    id: "uw-import-file",
    type: "file",
    accept: ".xlsx,.csv",
    onChange: handleFileChange,
    style: {
      display: 'none'
    }
  }), file ? /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      color: '#818cf8',
      fontSize: '0.9rem',
      fontWeight: 600
    }
  }, file.name), /*#__PURE__*/React.createElement("div", {
    style: {
      color: '#64748b',
      fontSize: '0.78rem',
      marginTop: '0.25rem'
    }
  }, (file.size / 1024).toFixed(1), " KB")) : /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("svg", {
    width: "32",
    height: "32",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "#475569",
    strokeWidth: "1.5",
    style: {
      margin: '0 auto 0.5rem'
    }
  }, /*#__PURE__*/React.createElement("path", {
    d: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"
  }), /*#__PURE__*/React.createElement("polyline", {
    points: "17 8 12 3 7 8"
  }), /*#__PURE__*/React.createElement("line", {
    x1: "12",
    y1: "3",
    x2: "12",
    y2: "15"
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      color: '#64748b',
      fontSize: '0.85rem'
    }
  }, "Click or drag & drop"), /*#__PURE__*/React.createElement("div", {
    style: {
      color: '#94a3b8',
      fontSize: '0.75rem',
      marginTop: '0.25rem'
    }
  }, "Accepts .xlsx and .csv (max 25MB)")))), /*#__PURE__*/React.createElement("div", {
    style: {
      marginBottom: '1rem'
    }
  }, /*#__PURE__*/React.createElement("label", {
    style: labelStyle
  }, "Import Mode"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.5rem'
    }
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => setMode('merge'),
    style: {
      flex: 1,
      padding: '0.6rem 0.75rem',
      borderRadius: '0.5rem',
      fontSize: '0.82rem',
      border: mode === 'merge' ? '1px solid #6366f1' : '1px solid #e2e8f0',
      background: mode === 'merge' ? 'rgba(99,102,241,0.1)' : '#F7F9FC',
      color: mode === 'merge' ? '#818cf8' : '#64748b',
      cursor: 'pointer',
      textAlign: 'left'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontWeight: 600,
      marginBottom: '0.15rem'
    }
  }, "Create + Merge"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '0.72rem',
      opacity: 0.8
    }
  }, "Normalize headers, create communities as needed")), /*#__PURE__*/React.createElement("button", {
    onClick: () => setMode('strict'),
    style: {
      flex: 1,
      padding: '0.6rem 0.75rem',
      borderRadius: '0.5rem',
      fontSize: '0.82rem',
      border: mode === 'strict' ? '1px solid #f59e0b' : '1px solid #e2e8f0',
      background: mode === 'strict' ? 'rgba(245,158,11,0.1)' : '#F7F9FC',
      color: mode === 'strict' ? '#fcd34d' : '#64748b',
      cursor: 'pointer',
      textAlign: 'left'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontWeight: 600,
      marginBottom: '0.15rem'
    }
  }, "Strict Match"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: '0.72rem',
      opacity: 0.8
    }
  }, "Headers must match exactly")))), /*#__PURE__*/React.createElement("div", {
    style: {
      marginBottom: '1rem'
    }
  }, /*#__PURE__*/React.createElement("label", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '0.5rem',
      cursor: 'pointer',
      fontSize: '0.85rem',
      color: '#64748b'
    }
  }, /*#__PURE__*/React.createElement("input", {
    type: "checkbox",
    checked: dryRun,
    onChange: e => setDryRun(e.target.checked),
    style: {
      accentColor: '#6366f1',
      width: '16px',
      height: '16px'
    }
  }), "Dry run (validate only, no writes)")), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '0.6rem 0.75rem',
      background: 'rgba(99,102,241,0.06)',
      border: '1px solid rgba(99,102,241,0.2)',
      borderRadius: '6px',
      fontSize: '0.8rem',
      color: '#64748b'
    }
  }, "Need the correct format? ", /*#__PURE__*/React.createElement("button", {
    onClick: downloadTemplate,
    style: {
      background: 'none',
      border: 'none',
      color: '#818cf8',
      cursor: 'pointer',
      textDecoration: 'underline',
      fontSize: '0.8rem',
      padding: 0
    }
  }, "Download blank template"))) : /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: summaryCard
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      ...summaryRow,
      paddingBottom: '0.5rem',
      borderBottom: '1px solid #e2e8f0',
      marginBottom: '0.35rem'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#0f172a',
      fontWeight: 700,
      fontSize: '0.9rem'
    }
  }, dryRun ? 'Dry Run Results' : 'Import Complete'), /*#__PURE__*/React.createElement("span", {
    style: {
      color: error ? '#f87171' : '#34d399',
      fontWeight: 600,
      fontSize: '0.85rem'
    }
  }, error ? 'With Errors' : 'Success')), /*#__PURE__*/React.createElement("div", {
    style: summaryRow
  }, /*#__PURE__*/React.createElement("span", {
    style: summaryLabel
  }, "Rows Imported"), /*#__PURE__*/React.createElement("span", {
    style: {
      ...summaryValue,
      color: '#14b8a6'
    }
  }, result.imported_rows)), /*#__PURE__*/React.createElement("div", {
    style: summaryRow
  }, /*#__PURE__*/React.createElement("span", {
    style: summaryLabel
  }, "Communities Created"), /*#__PURE__*/React.createElement("span", {
    style: {
      ...summaryValue,
      color: '#818cf8'
    }
  }, result.created_communities)), /*#__PURE__*/React.createElement("div", {
    style: summaryRow
  }, /*#__PURE__*/React.createElement("span", {
    style: summaryLabel
  }, "Communities Matched"), /*#__PURE__*/React.createElement("span", {
    style: summaryValue
  }, result.matched_communities)), /*#__PURE__*/React.createElement("div", {
    style: summaryRow
  }, /*#__PURE__*/React.createElement("span", {
    style: summaryLabel
  }, "Rows Skipped"), /*#__PURE__*/React.createElement("span", {
    style: {
      ...summaryValue,
      color: result.skipped_rows > 0 ? '#f87171' : '#64748b'
    }
  }, result.skipped_rows))), result.errors && result.errors.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      marginBottom: '0.75rem'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '0.5rem'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#f87171',
      fontSize: '0.85rem',
      fontWeight: 600
    }
  }, "Errors (", result.errors.length, ")"), /*#__PURE__*/React.createElement("button", {
    onClick: downloadErrorReport,
    className: "action-btn",
    style: {
      ...styles.actionBtn,
      fontSize: '0.7rem',
      padding: '0.2rem 0.5rem',
      borderColor: '#f87171',
      color: '#f87171'
    }
  }, "Download Error CSV")), /*#__PURE__*/React.createElement("div", {
    style: {
      maxHeight: '150px',
      overflowY: 'auto',
      background: '#F7F9FC',
      border: '1px solid #e2e8f0',
      borderRadius: '0.5rem',
      fontSize: '0.78rem'
    }
  }, result.errors.slice(0, 50).map((err, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      padding: '0.35rem 0.75rem',
      borderBottom: '1px solid #0f172a',
      color: '#f1a1a1',
      display: 'flex',
      gap: '0.5rem'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#f87171',
      fontWeight: 600,
      whiteSpace: 'nowrap'
    }
  }, "Row ", err.rowIndex, ":"), /*#__PURE__*/React.createElement("span", null, err.message))), result.errors.length > 50 && /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '0.35rem 0.75rem',
      color: '#64748b',
      fontStyle: 'italic'
    }
  }, "...and ", result.errors.length - 50, " more (download CSV for full list)"))), result.warnings && result.warnings.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      marginBottom: '0.75rem'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#fcd34d',
      fontSize: '0.85rem',
      fontWeight: 600,
      display: 'block',
      marginBottom: '0.5rem'
    }
  }, "Warnings (", result.warnings.length, ")"), /*#__PURE__*/React.createElement("div", {
    style: {
      maxHeight: '120px',
      overflowY: 'auto',
      background: '#F7F9FC',
      border: '1px solid #e2e8f0',
      borderRadius: '0.5rem',
      fontSize: '0.78rem'
    }
  }, result.warnings.slice(0, 30).map((w, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      padding: '0.35rem 0.75rem',
      borderBottom: '1px solid #0f172a',
      color: '#fde68a'
    }
  }, w.rowIndex ? /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#f59e0b',
      fontWeight: 600
    }
  }, "Row ", w.rowIndex, ": ") : null, w.message)), result.warnings.length > 30 && /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '0.35rem 0.75rem',
      color: '#64748b',
      fontStyle: 'italic'
    }
  }, "...and ", result.warnings.length - 30, " more"))))), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '1rem 1.5rem',
      borderTop: '1px solid #e2e8f0',
      display: 'flex',
      justifyContent: 'flex-end',
      gap: '0.5rem'
    }
  }, result ? /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: styles.actionBtn,
    onClick: () => {
      setResult(null);
      setFile(null);
      setError('');
    }
  }, "Import Another"), !dryRun && result.imported_rows > 0 ? /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: {
      ...styles.actionBtn,
      borderColor: '#14b8a6',
      color: '#14b8a6'
    },
    onClick: onImported
  }, "Done - View Data") : dryRun && !error ? /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: {
      ...styles.actionBtn,
      borderColor: '#6366f1',
      color: '#818cf8'
    },
    onClick: () => {
      setDryRun(false);
      setResult(null);
    }
  }, "Run Actual Import") : /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: styles.actionBtn,
    onClick: onClose
  }, "Close")) : /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: styles.actionBtn,
    onClick: onClose
  }, "Cancel"), /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: {
      ...styles.actionBtn,
      borderColor: '#6366f1',
      color: '#818cf8',
      opacity: uploading || !file ? 0.5 : 1
    },
    onClick: doImport,
    disabled: uploading || !file
  }, uploading ? 'Importing...' : dryRun ? 'Validate' : 'Import')))));
}

// Shared form modal for Create / Edit / Add-Units
function UWFormModal({
  columns,
  onClose,
  onSaved,
  mode,
  initialData,
  communityId
}) {
  const [form, setForm] = useState(() => {
    const init = {};
    columns.forEach(c => {
      init[c.key] = initialData && initialData[c.key] || '';
    });
    return init;
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [activeSection, setActiveSection] = useState('location');
  const set = (key, val) => setForm(prev => ({
    ...prev,
    [key]: val
  }));
  const highlightKeys = mode === 'add-units' ? ['number_of_units', 'buildings_values', 'contents_values', 'bi_values_12m', 'total_bi_values', 'premium_taxes_12m', 'premium_14m', 'inception_date'] : [];
  const save = async () => {
    setSaving(true);
    setError('');
    try {
      let url, body;
      if (mode === 'create') {
        url = `${API_BASE}/api/underwriting/communities`;
        body = {
          location_name: form.location_name,
          row: form
        };
      } else if (mode === 'edit') {
        url = `${API_BASE}/api/underwriting/rows/${initialData.id}`;
        body = form;
      } else {
        url = `${API_BASE}/api/underwriting/communities/${communityId}/add-units`;
        body = {
          row: form
        };
      }
      const res = await fetch(url, {
        method: mode === 'edit' ? 'PATCH' : 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
      });
      const d = await res.json();
      if (d.ok) {
        onSaved();
      } else {
        setError(d.error || d.message || `Save failed (HTTP ${res.status})`);
      }
    } catch (e) {
      setError('Request failed: ' + e.message);
    }
    setSaving(false);
  };

  // Group columns by section
  const sections = {};
  columns.forEach(c => {
    const sec = c.section || 'other';
    if (!sections[sec]) sections[sec] = [];
    sections[sec].push(c);
  });
  const title = mode === 'create' ? 'New Community' : mode === 'edit' ? 'Edit Row' : 'Add Units / Phase';
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'fixed',
      inset: 0,
      zIndex: 9999,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'rgba(0,0,0,0.3)'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#F1F5F9',
      border: '1px solid #e2e8f0',
      borderRadius: '1rem',
      width: '95vw',
      maxWidth: '900px',
      maxHeight: '90vh',
      display: 'flex',
      flexDirection: 'column'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '1.25rem 1.5rem',
      borderBottom: '1px solid #e2e8f0',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center'
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      margin: 0,
      color: '#0f172a',
      fontSize: '1.1rem'
    }
  }, title), /*#__PURE__*/React.createElement("button", {
    onClick: onClose,
    style: {
      background: 'none',
      border: 'none',
      color: '#64748b',
      fontSize: '1.5rem',
      cursor: 'pointer'
    }
  }, "\xD7")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0',
      borderBottom: '1px solid #e2e8f0',
      overflowX: 'auto',
      flexShrink: 0
    }
  }, Object.entries(UW_SECTIONS).filter(([k]) => sections[k]).map(([key, label]) => /*#__PURE__*/React.createElement("button", {
    key: key,
    onClick: () => setActiveSection(key),
    style: {
      padding: '0.6rem 1rem',
      fontSize: '0.78rem',
      fontWeight: activeSection === key ? 700 : 400,
      color: activeSection === key ? '#34d399' : '#64748b',
      background: 'transparent',
      border: 'none',
      borderBottom: activeSection === key ? '2px solid #14b8a6' : '2px solid transparent',
      cursor: 'pointer',
      whiteSpace: 'nowrap'
    }
  }, label))), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '1.25rem 1.5rem',
      overflowY: 'auto',
      flex: 1
    }
  }, error && /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '0.5rem 0.75rem',
      background: 'rgba(239,68,68,0.1)',
      border: '1px solid rgba(239,68,68,0.3)',
      borderRadius: '6px',
      color: '#f87171',
      fontSize: '0.85rem',
      marginBottom: '1rem'
    }
  }, error), mode === 'add-units' && /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '0.5rem 0.75rem',
      background: 'rgba(245,158,11,0.1)',
      border: '1px solid rgba(245,158,11,0.3)',
      borderRadius: '6px',
      color: '#fcd34d',
      fontSize: '0.85rem',
      marginBottom: '1rem'
    }
  }, "Prefilled from latest row (v", initialData?.row_version, "). Edit the highlighted fields for the new phase, then save."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: '1fr 1fr',
      gap: '0.75rem'
    }
  }, (sections[activeSection] || []).map(col => /*#__PURE__*/React.createElement("div", {
    key: col.key,
    style: {
      ...(highlightKeys.includes(col.key) ? {
        background: 'rgba(245,158,11,0.08)',
        border: '1px solid rgba(245,158,11,0.25)',
        borderRadius: '6px',
        padding: '0.5rem'
      } : {})
    }
  }, /*#__PURE__*/React.createElement("label", {
    style: {
      display: 'block',
      fontSize: '0.7rem',
      color: col.required ? '#f59e0b' : '#64748b',
      fontWeight: 600,
      marginBottom: '0.25rem',
      textTransform: 'uppercase',
      letterSpacing: '0.03em'
    }
  }, col.header, col.required ? ' *' : ''), /*#__PURE__*/React.createElement("input", {
    type: col.type === 'integer' || col.type === 'numeric' || col.type === 'currency' || col.type === 'percent' ? 'number' : col.type === 'date' ? 'date' : 'text',
    step: col.type === 'currency' || col.type === 'numeric' || col.type === 'percent' ? 'any' : undefined,
    value: form[col.key] || '',
    onChange: e => set(col.key, e.target.value),
    style: {
      ...styles.select,
      width: '100%',
      boxSizing: 'border-box'
    },
    placeholder: col.header
  }))))), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '1rem 1.5rem',
      borderTop: '1px solid #e2e8f0',
      display: 'flex',
      justifyContent: 'flex-end',
      gap: '0.5rem'
    }
  }, /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: styles.actionBtn,
    onClick: onClose
  }, "Cancel"), /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: {
      ...styles.actionBtn,
      borderColor: '#14b8a6',
      color: '#14b8a6'
    },
    onClick: save,
    disabled: saving
  }, saving ? 'Saving...' : mode === 'add-units' ? 'Add Phase' : 'Save'))));
}

// ======= DEAL BOARD PAGE (Broker) =======
// ===================================================================
// PREDICTED DEVELOPMENTS — Dashboard Component
// ===================================================================
function PredictedDevelopments() {
  const [predictions, setPredictions] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const loadPredictions = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (filter === 'confirmed') params.set('confirmed', 'true');
      if (filter === 'unconfirmed') params.set('confirmed', 'false');
      params.set('limit', '100');
      const resp = await fetch(`/api/predicted-projects?${params}`, {
        credentials: 'include'
      });
      const data = await resp.json();
      setPredictions(data.predictions || []);
    } catch (e) {
      console.error('Error loading predictions:', e);
    }
    setLoading(false);
  };
  const loadStats = async () => {
    try {
      const resp = await fetch('/api/predicted-projects/stats', {
        credentials: 'include'
      });
      const data = await resp.json();
      setStats(data);
    } catch (e) {
      console.error('Error loading prediction stats:', e);
    }
  };
  useEffect(() => {
    loadPredictions();
    loadStats();
  }, [filter]);
  const confidenceColor = c => {
    if (c >= 80) return '#14b8a6';
    if (c >= 60) return '#f59e0b';
    if (c >= 40) return '#f97316';
    return '#ef4444';
  };
  const confidenceBadge = c => ({
    display: 'inline-block',
    padding: '0.2rem 0.6rem',
    borderRadius: '9999px',
    fontSize: '0.8rem',
    fontWeight: 700,
    color: '#fff',
    background: confidenceColor(c)
  });
  const smallBadge = (label, color, bgAlpha) => React.createElement('span', {
    style: {
      display: 'inline-block',
      padding: '0.15rem 0.5rem',
      borderRadius: '9999px',
      fontSize: '0.65rem',
      fontWeight: 600,
      color: color,
      background: `rgba(${bgAlpha})`,
      border: `1px solid ${color}22`,
      marginRight: '0.35rem'
    }
  }, label);
  const patternStyle = {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.3rem',
    fontSize: '0.7rem',
    color: '#64748b',
    fontFamily: 'monospace'
  };
  const arrowStyle = {
    color: '#3b82f6',
    fontWeight: 700
  };
  const formatPattern = p => {
    if (!p) return '\u2014';
    const parts = p.split(' -> ');
    return React.createElement('span', {
      style: patternStyle
    }, ...parts.flatMap((part, i) => {
      const elements = [React.createElement('span', {
        key: `p${i}`,
        style: {
          color: '#1e293b'
        }
      }, part)];
      if (i < parts.length - 1) elements.push(React.createElement('span', {
        key: `a${i}`,
        style: arrowStyle
      }, ' \u2192 '));
      return elements;
    }));
  };
  const statCard = (val, label, color) => React.createElement('div', {
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      borderRadius: '0.75rem',
      padding: '0.85rem',
      textAlign: 'center'
    }
  }, React.createElement('div', {
    style: {
      fontSize: '1.4rem',
      fontWeight: 700,
      color
    }
  }, val), React.createElement('div', {
    style: {
      fontSize: '0.7rem',
      color: '#64748b',
      marginTop: '0.2rem'
    }
  }, label));
  return React.createElement('div', {
    style: {
      padding: '1.5rem'
    }
  },
  // Header
  React.createElement('div', {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '1.5rem'
    }
  }, React.createElement('h2', {
    style: {
      fontSize: '1.4rem',
      fontWeight: 700,
      color: '#0f172a',
      margin: 0
    }
  }, 'Predicted Developments'), React.createElement('div', {
    style: {
      display: 'flex',
      gap: '0.5rem'
    }
  }, ['all', 'unconfirmed', 'confirmed'].map(f => React.createElement('button', {
    key: f,
    onClick: () => setFilter(f),
    style: {
      padding: '0.4rem 0.8rem',
      borderRadius: '6px',
      cursor: 'pointer',
      border: filter === f ? '1px solid #3b82f6' : '1px solid #cbd5e1',
      background: filter === f ? 'rgba(34,211,238,0.1)' : 'transparent',
      color: filter === f ? '#3b82f6' : '#94a3b8',
      fontSize: '0.8rem',
      fontWeight: 500,
      textTransform: 'capitalize'
    }
  }, f)))),
  // Stats row
  stats && React.createElement('div', {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(6, 1fr)',
      gap: '0.75rem',
      marginBottom: '1.5rem'
    }
  }, statCard(stats.total?.count || 0, 'Predictions', '#3b82f6'), statCard(stats.confirmed?.count || 0, 'Confirmed', '#14b8a6'), statCard(stats.unconfirmed?.count || 0, 'Unconfirmed', '#f59e0b'), statCard(stats.events_total?.count || 0, 'Dev Events', '#a78bfa'), statCard(stats.clusters_detected?.count || 0, 'Clusters', '#f472b6'), statCard(stats.high_convergence?.count || 0, 'High Convergence', '#14b8a6')),
  // Prediction cards
  loading ? React.createElement('div', {
    style: {
      textAlign: 'center',
      padding: '3rem',
      color: '#64748b'
    }
  }, 'Loading predictions...') : predictions.length === 0 ? React.createElement('div', {
    style: {
      textAlign: 'center',
      padding: '3rem',
      color: '#64748b'
    }
  }, 'No predicted developments yet. The pattern engine scans every 12 hours.') : React.createElement('div', {
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: '0.75rem'
    }
  }, predictions.map(pred => React.createElement('div', {
    key: pred.id,
    style: {
      background: '#FFFFFF',
      border: pred.confirmed ? '1px solid #14b8a6' : '1px solid #e2e8f0',
      borderRadius: '0.75rem',
      padding: '1.25rem'
    }
  },
  // Top row: city/developer + convergence score + confidence
  React.createElement('div', {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'flex-start',
      marginBottom: '0.75rem'
    }
  }, React.createElement('div', null, React.createElement('div', {
    style: {
      fontSize: '1.05rem',
      fontWeight: 600,
      color: '#0f172a'
    }
  }, `${pred.city || '?'}, ${pred.state || '?'}`), React.createElement('div', {
    style: {
      fontSize: '0.85rem',
      color: '#64748b',
      marginTop: '0.15rem'
    }
  }, `Developer: ${pred.developer || 'Unknown'}`)), React.createElement('div', {
    style: {
      display: 'flex',
      gap: '1rem',
      alignItems: 'flex-start'
    }
  }, pred.convergence_score > 0 && React.createElement('div', {
    style: {
      textAlign: 'center'
    }
  }, React.createElement('div', {
    style: {
      fontSize: '1.3rem',
      fontWeight: 700,
      color: pred.convergence_score >= 80 ? '#14b8a6' : pred.convergence_score >= 60 ? '#3b82f6' : pred.convergence_score >= 40 ? '#f59e0b' : '#94a3b8',
      fontFamily: "'Orbitron', sans-serif"
    }
  }, pred.convergence_score), React.createElement('div', {
    style: {
      fontSize: '0.55rem',
      color: '#64748b',
      marginTop: '0.1rem',
      textTransform: 'uppercase',
      letterSpacing: '0.05em'
    }
  }, 'Opportunity Score')), React.createElement('div', {
    style: {
      textAlign: 'center'
    }
  }, React.createElement('span', {
    style: confidenceBadge(pred.confidence)
  }, `${pred.confidence}%`), React.createElement('div', {
    style: {
      fontSize: '0.6rem',
      color: '#64748b',
      marginTop: '0.2rem'
    }
  }, 'confidence')))),
  // Middle row: enriched data grid
  React.createElement('div', {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(6, 1fr)',
      gap: '0.75rem',
      marginBottom: '0.75rem',
      background: '#F1F5F9',
      borderRadius: '8px',
      padding: '0.75rem'
    }
  }, React.createElement('div', null, React.createElement('div', {
    style: {
      fontSize: '0.65rem',
      color: '#64748b',
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
      marginBottom: '0.2rem'
    }
  }, 'Convergence'), React.createElement('div', {
    style: {
      fontSize: '1.1rem',
      fontWeight: 700,
      color: pred.convergence_score >= 70 ? '#14b8a6' : pred.convergence_score >= 40 ? '#f59e0b' : '#94a3b8'
    }
  }, pred.convergence_score || 0)), React.createElement('div', null, React.createElement('div', {
    style: {
      fontSize: '0.65rem',
      color: '#64748b',
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
      marginBottom: '0.2rem'
    }
  }, 'Signal Count'), React.createElement('div', {
    style: {
      fontSize: '1.1rem',
      fontWeight: 700,
      color: '#1e293b'
    }
  }, pred.convergence_signal_count || pred.signal_count || 0)), React.createElement('div', null, React.createElement('div', {
    style: {
      fontSize: '0.65rem',
      color: '#64748b',
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
      marginBottom: '0.2rem'
    }
  }, 'Relationships'), React.createElement('div', {
    style: {
      fontSize: '1.1rem',
      fontWeight: 700,
      color: pred.relationship_count > 0 ? '#a78bfa' : '#94a3b8'
    }
  }, pred.relationship_count || 0)), React.createElement('div', null, React.createElement('div', {
    style: {
      fontSize: '0.65rem',
      color: '#64748b',
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
      marginBottom: '0.2rem'
    }
  }, 'Cluster'), React.createElement('div', {
    style: {
      fontSize: '1.1rem',
      fontWeight: 700,
      color: pred.cluster_detected ? '#14b8a6' : '#94a3b8'
    }
  }, pred.cluster_detected ? 'Yes' : 'No')), React.createElement('div', {
    style: {
      gridColumn: 'span 2'
    }
  }, React.createElement('div', {
    style: {
      fontSize: '0.65rem',
      color: '#64748b',
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
      marginBottom: '0.2rem'
    }
  }, 'Construction Timeline'), React.createElement('div', {
    style: {
      fontSize: '0.85rem',
      fontWeight: 600,
      color: '#3b82f6'
    }
  }, pred.expected_construction_window || 'Estimating...'))),
  // Convergence signal types
  pred.convergence_signal_types && pred.convergence_signal_types.length > 0 && React.createElement('div', {
    style: {
      display: 'flex',
      flexWrap: 'wrap',
      gap: '0.3rem',
      marginBottom: '0.75rem'
    }
  }, React.createElement('span', {
    style: {
      fontSize: '0.6rem',
      color: '#64748b',
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
      marginRight: '0.3rem',
      alignSelf: 'center'
    }
  }, 'Signals:'), ...pred.convergence_signal_types.filter(Boolean).map((st, si) => React.createElement('span', {
    key: si,
    style: {
      fontSize: '0.65rem',
      color: '#3b82f6',
      background: 'rgba(34,211,238,0.1)',
      padding: '0.12rem 0.45rem',
      borderRadius: '0.25rem',
      fontWeight: 600
    }
  }, st))),
  // Bottom row: pattern + badges
  React.createElement('div', {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center'
    }
  }, React.createElement('div', {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '0.5rem'
    }
  }, formatPattern(pred.pattern_detected), pred.pattern_name && React.createElement('span', {
    style: {
      fontSize: '0.65rem',
      color: '#3b82f6',
      background: 'rgba(34,211,238,0.1)',
      padding: '0.1rem 0.4rem',
      borderRadius: '0.25rem',
      fontFamily: 'monospace'
    }
  }, pred.pattern_name), pred.pattern_confidence > 0 && React.createElement('span', {
    style: {
      fontSize: '0.65rem',
      color: '#a78bfa',
      fontWeight: 600
    }
  }, pred.pattern_confidence + '%')), React.createElement('div', {
    style: {
      display: 'flex',
      alignItems: 'center',
      flexWrap: 'wrap',
      gap: '0.25rem'
    }
  }, pred.confirmed && smallBadge('CONFIRMED', '#14b8a6', '16,185,129,0.15'), pred.cluster_detected && smallBadge('CLUSTER', '#f472b6', '244,114,182,0.15'), pred.freshness_boost > 0 && smallBadge('FRESH', '#3b82f6', '34,211,238,0.15'), pred.developer_linked && smallBadge('DEV LINKED', '#a78bfa', '167,139,250,0.15'), pred.contractor_linked && smallBadge('CONTRACTOR', '#fb923c', '251,146,60,0.15'), pred.consultant_linked && smallBadge('CONSULTANT', '#2dd4bf', '45,212,191,0.15'), pred.developer_expansion_signal && smallBadge('DNA MATCH', '#f59e0b', '245,158,11,0.15'), pred.contractor_activity_detected && smallBadge('CONTRACTOR INTEL', '#ef4444', '239,68,68,0.15'), pred.temporal_boost > 0 && smallBadge('TEMPORAL +' + pred.temporal_boost, '#8b5cf6', '139,92,246,0.15'), React.createElement('span', {
    style: {
      fontSize: '0.7rem',
      color: '#64748b'
    }
  }, pred.prediction_date ? new Date(pred.prediction_date).toLocaleDateString() : ''))),
  // Developer Intelligence section
  pred.developer_expansion_signal && React.createElement('div', {
    style: {
      marginTop: '0.6rem',
      padding: '0.6rem',
      background: 'rgba(245,158,11,0.08)',
      border: '1px solid rgba(245,158,11,0.2)',
      borderRadius: '0.5rem'
    }
  }, React.createElement('div', {
    style: {
      fontSize: '0.6rem',
      color: '#f59e0b',
      textTransform: 'uppercase',
      letterSpacing: '0.08em',
      fontWeight: 700,
      marginBottom: '0.3rem'
    }
  }, 'Developer Intelligence'), React.createElement('div', {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center'
    }
  }, React.createElement('div', {
    style: {
      fontSize: '0.75rem',
      color: '#1e293b'
    }
  }, pred.developer_expansion_reasoning || 'Expansion signal detected'), pred.developer_dna_confidence > 0 && React.createElement('div', {
    style: {
      fontSize: '0.85rem',
      fontWeight: 700,
      color: '#f59e0b'
    }
  }, pred.developer_dna_confidence + '%'))),
  // Contractor Intelligence section
  pred.contractor_activity_detected && React.createElement('div', {
    style: {
      marginTop: '0.6rem',
      padding: '0.6rem',
      background: 'rgba(239,68,68,0.08)',
      border: '1px solid rgba(239,68,68,0.2)',
      borderRadius: '0.5rem'
    }
  }, React.createElement('div', {
    style: {
      fontSize: '0.6rem',
      color: '#ef4444',
      textTransform: 'uppercase',
      letterSpacing: '0.08em',
      fontWeight: 700,
      marginBottom: '0.4rem'
    }
  }, 'Contractor Intelligence'), pred.contractor_firms && pred.contractor_firms.length > 0 && React.createElement('div', {
    style: {
      display: 'flex',
      flexWrap: 'wrap',
      gap: '0.3rem',
      marginBottom: '0.3rem'
    }
  }, ...pred.contractor_firms.map((firm, i) => React.createElement('span', {
    key: i,
    style: {
      fontSize: '0.65rem',
      color: '#fca5a5',
      background: 'rgba(239,68,68,0.12)',
      padding: '0.1rem 0.4rem',
      borderRadius: '0.25rem',
      fontFamily: 'monospace'
    }
  }, firm))), React.createElement('div', {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center'
    }
  }, pred.contractor_developer_inference && React.createElement('div', {
    style: {
      fontSize: '0.75rem',
      color: '#1e293b'
    }
  }, 'Developer Likely: ', React.createElement('span', {
    style: {
      fontWeight: 700,
      color: '#fca5a5'
    }
  }, pred.contractor_developer_inference)), pred.contractor_confidence > 0 && React.createElement('div', {
    style: {
      fontSize: '0.85rem',
      fontWeight: 700,
      color: '#ef4444'
    }
  }, pred.contractor_confidence + '%'))),
  // Parcel Intelligence section
  pred.parcel_probability_score > 0 && React.createElement('div', {
    style: {
      marginTop: '0.6rem',
      padding: '0.6rem',
      background: 'rgba(20,184,166,0.06)',
      border: '1px solid rgba(16,185,129,0.2)',
      borderRadius: '0.5rem'
    }
  }, React.createElement('div', {
    style: {
      fontSize: '0.6rem',
      color: '#14b8a6',
      textTransform: 'uppercase',
      letterSpacing: '0.08em',
      fontWeight: 700,
      marginBottom: '0.4rem'
    }
  }, 'Parcel Intelligence'), React.createElement('div', {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center'
    }
  }, React.createElement('div', {
    style: {
      display: 'flex',
      gap: '0.8rem',
      alignItems: 'center'
    }
  }, React.createElement('div', null, React.createElement('div', {
    style: {
      fontSize: '0.55rem',
      color: '#64748b',
      textTransform: 'uppercase'
    }
  }, 'Probability'), React.createElement('div', {
    style: {
      fontSize: '1rem',
      fontWeight: 700,
      color: '#14b8a6'
    }
  }, pred.parcel_probability_score + '%')), React.createElement('div', null, React.createElement('div', {
    style: {
      fontSize: '0.55rem',
      color: '#64748b',
      textTransform: 'uppercase'
    }
  }, 'Likelihood'), React.createElement('div', {
    style: {
      fontSize: '0.8rem',
      fontWeight: 600,
      color: pred.parcel_development_likelihood === 'Very High' ? '#14b8a6' : pred.parcel_development_likelihood === 'High' ? '#3b82f6' : '#f59e0b'
    }
  }, pred.parcel_development_likelihood || 'Pending'))), pred.parcel_probability_score >= 70 && React.createElement('span', {
    style: {
      fontSize: '0.6rem',
      color: '#14b8a6',
      background: 'rgba(20,184,166,0.08)',
      padding: '0.15rem 0.5rem',
      borderRadius: '0.25rem',
      fontWeight: 600
    }
  }, 'HIGH PROBABILITY'))),
  // Temporal Pattern section
  pred.temporal_boost > 0 && React.createElement('div', {
    style: {
      marginTop: '0.6rem',
      padding: '0.6rem',
      background: 'rgba(139,92,246,0.08)',
      border: '1px solid rgba(139,92,246,0.2)',
      borderRadius: '0.5rem'
    }
  }, React.createElement('div', {
    style: {
      fontSize: '0.6rem',
      color: '#8b5cf6',
      textTransform: 'uppercase',
      letterSpacing: '0.08em',
      fontWeight: 700,
      marginBottom: '0.4rem'
    }
  }, 'Temporal Pattern Match'), React.createElement('div', {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '0.4rem'
    }
  }, React.createElement('div', {
    style: {
      display: 'flex',
      gap: '0.8rem',
      alignItems: 'center'
    }
  }, React.createElement('div', null, React.createElement('div', {
    style: {
      fontSize: '0.55rem',
      color: '#64748b',
      textTransform: 'uppercase'
    }
  }, 'Boost'), React.createElement('div', {
    style: {
      fontSize: '1rem',
      fontWeight: 700,
      color: '#8b5cf6'
    }
  }, '+' + pred.temporal_boost)), pred.temporal_match_stage && React.createElement('div', null, React.createElement('div', {
    style: {
      fontSize: '0.55rem',
      color: '#64748b',
      textTransform: 'uppercase'
    }
  }, 'Stage'), React.createElement('div', {
    style: {
      fontSize: '0.8rem',
      fontWeight: 600,
      color: '#c4b5fd'
    }
  }, pred.temporal_match_stage))), pred.temporal_boost >= 30 && React.createElement('span', {
    style: {
      fontSize: '0.6rem',
      color: '#8b5cf6',
      background: 'rgba(139,92,246,0.12)',
      padding: '0.15rem 0.5rem',
      borderRadius: '0.25rem',
      fontWeight: 600
    }
  }, 'STRONG PATTERN')), pred.temporal_pattern_match && React.createElement('div', {
    style: {
      marginTop: '0.3rem',
      fontSize: '0.7rem',
      color: '#a78bfa',
      fontFamily: 'monospace',
      background: 'rgba(139,92,246,0.06)',
      padding: '0.3rem 0.5rem',
      borderRadius: '0.25rem'
    }
  }, ...pred.temporal_pattern_match.split(' -> ').flatMap((step, si, arr) => {
    const els = [React.createElement('span', {
      key: 's' + si,
      style: {
        color: '#1e293b'
      }
    }, step)];
    if (si < arr.length - 1) els.push(React.createElement('span', {
      key: 'a' + si,
      style: {
        color: '#8b5cf6',
        fontWeight: 700
      }
    }, ' \u2192 '));
    return els;
  })))))));
}

// ===================================================================
// MARKET EXPANSION — Dashboard Component
// ===================================================================
function MarketExpansion() {
  const [markets, setMarkets] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filterState, setFilterState] = useState('');
  const loadMarkets = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (filterState) params.set('state', filterState);
      params.set('limit', '100');
      const resp = await fetch(`/api/markets?${params}`, {
        credentials: 'include'
      });
      const data = await resp.json();
      setMarkets(data.markets || []);
    } catch (e) {
      console.error('Error loading markets:', e);
    }
    setLoading(false);
  };
  const loadStats = async () => {
    try {
      const resp = await fetch('/api/markets/stats', {
        credentials: 'include'
      });
      const data = await resp.json();
      setStats(data);
    } catch (e) {
      console.error('Error loading market stats:', e);
    }
  };
  useEffect(() => {
    loadMarkets();
    loadStats();
  }, [filterState]);
  const scoreColor = s => {
    if (s >= 85) return '#14b8a6';
    if (s >= 70) return '#f59e0b';
    if (s >= 50) return '#f97316';
    return '#ef4444';
  };
  const scoreBadge = s => ({
    display: 'inline-block',
    padding: '0.2rem 0.6rem',
    borderRadius: '9999px',
    fontSize: '0.8rem',
    fontWeight: 700,
    color: '#fff',
    background: scoreColor(s)
  });
  const pctDisplay = (val, suffix) => {
    if (val == null) return '\u2014';
    return `${Number(val).toFixed(1)}${suffix || '%'}`;
  };
  const statCard = (val, label, color) => React.createElement('div', {
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      borderRadius: '0.75rem',
      padding: '0.85rem',
      textAlign: 'center'
    }
  }, React.createElement('div', {
    style: {
      fontSize: '1.4rem',
      fontWeight: 700,
      color
    }
  }, val), React.createElement('div', {
    style: {
      fontSize: '0.7rem',
      color: '#64748b',
      marginTop: '0.2rem'
    }
  }, label));
  return React.createElement('div', {
    style: {
      padding: '1.5rem'
    }
  },
  // Header
  React.createElement('div', {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '1.5rem'
    }
  }, React.createElement('h2', {
    style: {
      fontSize: '1.4rem',
      fontWeight: 700,
      color: '#0f172a',
      margin: 0
    }
  }, 'Market Expansion'), React.createElement('div', {
    style: {
      display: 'flex',
      gap: '0.5rem',
      alignItems: 'center'
    }
  }, React.createElement('span', {
    style: {
      fontSize: '0.75rem',
      color: '#64748b'
    }
  }, 'Filter State:'), React.createElement('input', {
    type: 'text',
    placeholder: 'e.g. AZ',
    value: filterState,
    onChange: e => setFilterState(e.target.value.toUpperCase()),
    style: {
      padding: '0.35rem 0.6rem',
      borderRadius: '6px',
      width: '60px',
      border: '1px solid #cbd5e1',
      background: '#F1F5F9',
      color: '#1e293b',
      fontSize: '0.8rem',
      textAlign: 'center'
    }
  }))),
  // Stats row
  stats && React.createElement('div', {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(4, 1fr)',
      gap: '0.75rem',
      marginBottom: '1.5rem'
    }
  }, statCard(stats.total_markets?.count || 0, 'Total Markets', '#3b82f6'), statCard(stats.active_markets?.count || 0, 'Active', '#14b8a6'), statCard(stats.pending_markets?.count || 0, 'Pending', '#f59e0b'), statCard(stats.avg_score?.avg || 0, 'Avg Score', '#a78bfa')),
  // Market cards
  loading ? React.createElement('div', {
    style: {
      textAlign: 'center',
      padding: '3rem',
      color: '#64748b'
    }
  }, 'Loading markets...') : markets.length === 0 ? React.createElement('div', {
    style: {
      textAlign: 'center',
      padding: '3rem',
      color: '#64748b'
    }
  }, 'No markets detected yet. The expansion engine scans weekly.') : React.createElement('div', {
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: '0.75rem'
    }
  }, markets.map(m => React.createElement('div', {
    key: m.id,
    style: {
      background: '#FFFFFF',
      border: m.collectors_active ? '1px solid #14b8a6' : '1px solid #e2e8f0',
      borderRadius: '0.75rem',
      padding: '1.25rem'
    }
  },
  // Top row: city + score
  React.createElement('div', {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'flex-start',
      marginBottom: '0.75rem'
    }
  }, React.createElement('div', null, React.createElement('div', {
    style: {
      fontSize: '1.05rem',
      fontWeight: 600,
      color: '#0f172a'
    }
  }, `${m.city || '?'}, ${m.state || '?'}`), React.createElement('div', {
    style: {
      fontSize: '0.8rem',
      color: '#64748b',
      marginTop: '0.15rem'
    }
  }, m.population ? `Pop: ${Number(m.population).toLocaleString()}` : '')), React.createElement('div', {
    style: {
      textAlign: 'center'
    }
  }, React.createElement('span', {
    style: scoreBadge(m.market_score)
  }, m.market_score), React.createElement('div', {
    style: {
      fontSize: '0.6rem',
      color: '#64748b',
      marginTop: '0.2rem'
    }
  }, 'market score'))),
  // Metrics grid
  React.createElement('div', {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(4, 1fr)',
      gap: '0.75rem',
      marginBottom: '0.75rem',
      background: '#F1F5F9',
      borderRadius: '8px',
      padding: '0.75rem'
    }
  }, React.createElement('div', null, React.createElement('div', {
    style: {
      fontSize: '0.65rem',
      color: '#64748b',
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
      marginBottom: '0.2rem'
    }
  }, 'Pop Growth'), React.createElement('div', {
    style: {
      fontSize: '1.1rem',
      fontWeight: 700,
      color: m.population_growth > 2 ? '#14b8a6' : '#1e293b'
    }
  }, pctDisplay(m.population_growth))), React.createElement('div', null, React.createElement('div', {
    style: {
      fontSize: '0.65rem',
      color: '#64748b',
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
      marginBottom: '0.2rem'
    }
  }, 'Permit Growth'), React.createElement('div', {
    style: {
      fontSize: '1.1rem',
      fontWeight: 700,
      color: m.permit_growth > 15 ? '#14b8a6' : '#1e293b'
    }
  }, pctDisplay(m.permit_growth))), React.createElement('div', null, React.createElement('div', {
    style: {
      fontSize: '0.65rem',
      color: '#64748b',
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
      marginBottom: '0.2rem'
    }
  }, 'Rent Growth'), React.createElement('div', {
    style: {
      fontSize: '1.1rem',
      fontWeight: 700,
      color: m.rent_growth > 5 ? '#14b8a6' : '#1e293b'
    }
  }, pctDisplay(m.rent_growth))), React.createElement('div', null, React.createElement('div', {
    style: {
      fontSize: '0.65rem',
      color: '#64748b',
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
      marginBottom: '0.2rem'
    }
  }, 'Collectors'), React.createElement('div', {
    style: {
      fontSize: '1.1rem',
      fontWeight: 700,
      color: m.collectors_active ? '#14b8a6' : '#f59e0b'
    }
  }, m.collectors_active ? 'Active' : 'Pending')))))));
}
function DealBoardPage({
  user
}) {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editId, setEditId] = useState(null);
  const [editNotes, setEditNotes] = useState('');
  const [editStatus, setEditStatus] = useState('');
  const statusOptions = ['saved', 'reviewing', 'contacted', 'negotiating', 'closed', 'passed'];
  const loadItems = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/broker/saved`);
      const d = await res.json();
      if (d.success) setItems(d.items);
    } catch (e) {
      console.error('Failed to load deal board', e);
    }
    setLoading(false);
  };
  useEffect(() => {
    loadItems();
  }, []);
  const deleteItem = async id => {
    if (!confirm('Remove from Deal Board?')) return;
    try {
      await fetch(`${API_BASE}/api/broker/saved/${id}`, {
        method: 'DELETE'
      });
      setItems(prev => prev.filter(i => i.id !== id));
    } catch (e) {
      alert('Error removing item');
    }
  };
  const saveEdit = async id => {
    try {
      await fetch(`${API_BASE}/api/broker/saved/${id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          notes: editNotes,
          status: editStatus
        })
      });
      setEditId(null);
      loadItems();
    } catch (e) {
      alert('Error saving');
    }
  };
  const exportCsv = () => {
    window.open(`${API_BASE}/api/broker/export-csv`, '_blank');
  };
  const statusColor = s => {
    const map = {
      saved: '#94a3b8',
      reviewing: '#60a5fa',
      contacted: '#fbbf24',
      negotiating: '#a78bfa',
      closed: '#34d399',
      passed: '#ef4444'
    };
    return map[s] || '#94a3b8';
  };
  if (loading) return /*#__PURE__*/React.createElement("div", {
    style: {
      textAlign: 'center',
      padding: '3rem',
      color: '#64748b'
    }
  }, "Loading Deal Board...");
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '1.5rem'
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h2", {
    style: {
      ...styles.sectionTitle,
      fontSize: '1.3rem',
      margin: 0
    }
  }, "Deal Board"), /*#__PURE__*/React.createElement("p", {
    style: {
      color: '#64748b',
      fontSize: '0.85rem',
      margin: '0.25rem 0 0'
    }
  }, items.length, " saved ", items.length === 1 ? 'deal' : 'deals')), /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: {
      ...styles.actionBtn,
      borderColor: '#14b8a6',
      color: '#14b8a6'
    },
    onClick: exportCsv
  }, "Export CSV")), items.length === 0 ? /*#__PURE__*/React.createElement(EmptyState, {
    title: "No saved deals yet",
    subtitle: "Use \"Save to Deal Board\" on prospect cards to start building your list",
    icon: /*#__PURE__*/React.createElement("svg", {
      width: "36",
      height: "36",
      viewBox: "0 0 24 24",
      fill: "none",
      stroke: "currentColor",
      strokeWidth: "1.5",
      className: "text-slate-600"
    }, /*#__PURE__*/React.createElement("rect", {
      x: "3",
      y: "3",
      width: "18",
      height: "18",
      rx: "2"
    }), /*#__PURE__*/React.createElement("path", {
      d: "M3 9h18M9 21V9"
    }))
  }) : /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: '0.75rem'
    }
  }, items.map(item => /*#__PURE__*/React.createElement("div", {
    key: item.id,
    style: {
      ...styles.card,
      borderRadius: '0.75rem',
      padding: '1rem 1.25rem'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'flex-start',
      gap: '1rem'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      minWidth: 0
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '0.5rem',
      flexWrap: 'wrap'
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      ...styles.companyName,
      marginBottom: 0,
      fontSize: '1rem'
    }
  }, item.company || 'Unknown'), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.65rem',
      padding: '0.15rem 0.45rem',
      borderRadius: '4px',
      fontWeight: 600,
      background: `${statusColor(item.status)}20`,
      color: statusColor(item.status),
      textTransform: 'uppercase',
      letterSpacing: '0.03em'
    }
  }, item.status)), /*#__PURE__*/React.createElement("p", {
    style: {
      color: '#64748b',
      fontSize: '0.78rem',
      margin: '0.25rem 0 0'
    }
  }, "Saved ", item.created_at ? new Date(item.created_at).toLocaleDateString() : '')), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.5rem',
      flexShrink: 0
    }
  }, /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: styles.actionBtn,
    onClick: () => {
      setEditId(item.id);
      setEditNotes(item.notes || '');
      setEditStatus(item.status);
    }
  }, "Edit"), /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: {
      ...styles.actionBtn,
      borderColor: '#ef4444',
      color: '#f87171'
    },
    onClick: () => deleteItem(item.id)
  }, "Remove"))), item.notes && /*#__PURE__*/React.createElement("p", {
    style: {
      color: '#334155',
      fontSize: '0.85rem',
      margin: '0.5rem 0 0',
      lineHeight: '1.5'
    }
  }, item.notes), editId === item.id && /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: '0.75rem',
      padding: '0.75rem',
      background: '#F7F9FC',
      borderRadius: '8px',
      border: '1px solid #e2e8f0'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      marginBottom: '0.5rem'
    }
  }, /*#__PURE__*/React.createElement("label", {
    style: {
      fontSize: '0.7rem',
      color: '#64748b',
      fontWeight: 600,
      display: 'block',
      marginBottom: '0.25rem',
      textTransform: 'uppercase'
    }
  }, "Status"), /*#__PURE__*/React.createElement("select", {
    style: styles.select,
    value: editStatus,
    onChange: e => setEditStatus(e.target.value)
  }, statusOptions.map(s => /*#__PURE__*/React.createElement("option", {
    key: s,
    value: s
  }, s.charAt(0).toUpperCase() + s.slice(1))))), /*#__PURE__*/React.createElement("div", {
    style: {
      marginBottom: '0.5rem'
    }
  }, /*#__PURE__*/React.createElement("label", {
    style: {
      fontSize: '0.7rem',
      color: '#64748b',
      fontWeight: 600,
      display: 'block',
      marginBottom: '0.25rem',
      textTransform: 'uppercase'
    }
  }, "Notes"), /*#__PURE__*/React.createElement("textarea", {
    style: {
      ...styles.select,
      height: '4rem',
      resize: 'vertical'
    },
    value: editNotes,
    onChange: e => setEditNotes(e.target.value)
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.5rem'
    }
  }, /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: {
      ...styles.actionBtn,
      borderColor: '#14b8a6',
      color: '#14b8a6'
    },
    onClick: () => saveEdit(item.id)
  }, "Save"), /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: styles.actionBtn,
    onClick: () => setEditId(null)
  }, "Cancel")))))));
}

// ======= ADMIN PAGE (Super Admin Only) =======
function AdminPage({
  user
}) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [createForm, setCreateForm] = useState({
    name: '',
    email: '',
    password: '',
    role: 'producer'
  });
  const [createError, setCreateError] = useState('');
  const [actionMsg, setActionMsg] = useState('');
  const [confirmDelete, setConfirmDelete] = useState(null); // user obj
  const [deleteConfirmText, setDeleteConfirmText] = useState('');
  const [resetTarget, setResetTarget] = useState(null);
  const [resetPassword, setResetPassword] = useState('');
  const fetchUsers = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/admin/users`);
      const data = await res.json();
      if (data.success) setUsers(data.users || []);
    } catch (e) {
      console.error('Admin users fetch error:', e);
    }
    setLoading(false);
  };
  useEffect(() => {
    fetchUsers();
  }, []);
  const handleCreate = async e => {
    e.preventDefault();
    setCreateError('');
    try {
      const res = await fetch(`${API_BASE}/api/admin/users`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(createForm)
      });
      const data = await res.json();
      if (data.success) {
        setShowCreate(false);
        setCreateForm({
          name: '',
          email: '',
          password: '',
          role: 'producer'
        });
        setActionMsg('User created successfully');
        setTimeout(() => setActionMsg(''), 3000);
        fetchUsers();
      } else {
        setCreateError(data.message || 'Failed to create user');
      }
    } catch (e) {
      setCreateError('Network error');
    }
  };
  const handleDisable = async uid => {
    try {
      const res = await fetch(`${API_BASE}/api/admin/users/${uid}/disable`, {
        method: 'POST'
      });
      const data = await res.json();
      if (data.success) {
        setActionMsg(data.is_disabled ? 'User disabled' : 'User re-enabled');
        setTimeout(() => setActionMsg(''), 3000);
        fetchUsers();
      } else {
        setActionMsg(data.message || 'Action failed');
      }
    } catch (e) {
      setActionMsg('Network error');
    }
  };
  const handleDelete = async uid => {
    try {
      const res = await fetch(`${API_BASE}/api/admin/users/${uid}`, {
        method: 'DELETE'
      });
      const data = await res.json();
      if (data.success) {
        setConfirmDelete(null);
        setDeleteConfirmText('');
        setActionMsg('User deleted');
        setTimeout(() => setActionMsg(''), 3000);
        fetchUsers();
      } else {
        setActionMsg(data.message || 'Delete failed');
      }
    } catch (e) {
      setActionMsg('Network error');
    }
  };
  const handleResetPassword = async () => {
    if (!resetTarget) return;
    try {
      const res = await fetch(`${API_BASE}/api/admin/users/${resetTarget.id}/reset-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          password: resetPassword
        })
      });
      const data = await res.json();
      if (data.success) {
        setResetTarget(null);
        setResetPassword('');
        setActionMsg('Password reset successfully');
        setTimeout(() => setActionMsg(''), 3000);
      } else {
        setActionMsg(data.message || 'Reset failed');
      }
    } catch (e) {
      setActionMsg('Network error');
    }
  };
  const tbl = {
    table: {
      width: '100%',
      borderCollapse: 'collapse',
      fontSize: '0.9rem'
    },
    th: {
      textAlign: 'left',
      padding: '0.75rem 1rem',
      borderBottom: '2px solid #e2e8f0',
      color: '#64748b',
      fontWeight: 600,
      fontSize: '0.75rem',
      textTransform: 'uppercase',
      letterSpacing: '0.05em'
    },
    td: {
      padding: '0.75rem 1rem',
      borderBottom: '1px solid #e2e8f0',
      color: '#0f172a'
    },
    badge: (color, bg) => ({
      display: 'inline-block',
      padding: '0.15rem 0.55rem',
      borderRadius: '12px',
      fontSize: '0.75rem',
      fontWeight: 600,
      color,
      background: bg
    })
  };
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '1.5rem'
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '1.5rem',
      fontWeight: 700,
      color: '#14b8a6',
      margin: 0
    }
  }, "User Management"), /*#__PURE__*/React.createElement("button", {
    style: styles.btnPrimary,
    onClick: () => setShowCreate(true)
  }, "+ Create User")), actionMsg && /*#__PURE__*/React.createElement("div", {
    style: {
      background: 'rgba(16,185,129,0.1)',
      border: '1px solid rgba(16,185,129,0.3)',
      borderRadius: '8px',
      padding: '0.75rem 1rem',
      marginBottom: '1rem',
      color: '#14b8a6',
      fontSize: '0.9rem'
    }
  }, actionMsg), loading ? /*#__PURE__*/React.createElement("div", {
    style: ds.loadingMsg
  }, "Loading users...") : /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      borderRadius: '12px',
      overflow: 'hidden'
    }
  }, /*#__PURE__*/React.createElement("table", {
    style: tbl.table
  }, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", {
    style: tbl.th
  }, "Name"), /*#__PURE__*/React.createElement("th", {
    style: tbl.th
  }, "Email"), /*#__PURE__*/React.createElement("th", {
    style: tbl.th
  }, "Role"), /*#__PURE__*/React.createElement("th", {
    style: tbl.th
  }, "Created"), /*#__PURE__*/React.createElement("th", {
    style: tbl.th
  }, "Last Login"), /*#__PURE__*/React.createElement("th", {
    style: tbl.th
  }, "Status"), /*#__PURE__*/React.createElement("th", {
    style: tbl.th
  }, "Actions"))), /*#__PURE__*/React.createElement("tbody", null, users.map(u => /*#__PURE__*/React.createElement("tr", {
    key: u.id,
    style: {
      opacity: u.is_disabled ? 0.5 : 1
    }
  }, /*#__PURE__*/React.createElement("td", {
    style: tbl.td
  }, u.name, u.is_super_admin && /*#__PURE__*/React.createElement("span", {
    style: {
      ...tbl.badge('#fbbf24', 'rgba(251,191,36,0.15)'),
      marginLeft: '0.5rem'
    }
  }, "SUPER")), /*#__PURE__*/React.createElement("td", {
    style: {
      ...tbl.td,
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: '0.85rem'
    }
  }, u.email), /*#__PURE__*/React.createElement("td", {
    style: tbl.td
  }, /*#__PURE__*/React.createElement("span", {
    style: tbl.badge(u.role === 'admin' ? '#f59e0b' : u.role === 'broker' ? '#fb923c' : '#34d399', u.role === 'admin' ? 'rgba(245,158,11,0.15)' : u.role === 'broker' ? 'rgba(251,146,60,0.15)' : 'rgba(16,185,129,0.1)')
  }, u.role)), /*#__PURE__*/React.createElement("td", {
    style: {
      ...tbl.td,
      color: '#64748b',
      fontSize: '0.85rem'
    }
  }, u.created_at ? new Date(u.created_at).toLocaleDateString() : '-'), /*#__PURE__*/React.createElement("td", {
    style: {
      ...tbl.td,
      color: '#64748b',
      fontSize: '0.85rem'
    }
  }, u.last_login_at ? new Date(u.last_login_at).toLocaleDateString() : 'Never'), /*#__PURE__*/React.createElement("td", {
    style: tbl.td
  }, u.is_disabled ? /*#__PURE__*/React.createElement("span", {
    style: tbl.badge('#ef4444', 'rgba(239,68,68,0.15)')
  }, "Disabled") : /*#__PURE__*/React.createElement("span", {
    style: tbl.badge('#34d399', 'rgba(16,185,129,0.1)')
  }, "Active")), /*#__PURE__*/React.createElement("td", {
    style: {
      ...tbl.td,
      display: 'flex',
      gap: '0.5rem',
      flexWrap: 'wrap'
    }
  }, !u.is_super_admin && u.id !== user.id && /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("button", {
    style: {
      ...styles.btn,
      fontSize: '0.8rem',
      padding: '0.3rem 0.7rem'
    },
    onClick: () => handleDisable(u.id)
  }, u.is_disabled ? 'Enable' : 'Disable'), /*#__PURE__*/React.createElement("button", {
    style: {
      ...styles.btn,
      fontSize: '0.8rem',
      padding: '0.3rem 0.7rem'
    },
    onClick: () => {
      setResetTarget(u);
      setResetPassword('');
    }
  }, "Reset PW"), /*#__PURE__*/React.createElement("button", {
    style: {
      ...styles.btn,
      fontSize: '0.8rem',
      padding: '0.3rem 0.7rem',
      color: '#ef4444',
      borderColor: '#ef4444'
    },
    onClick: () => {
      setConfirmDelete(u);
      setDeleteConfirmText('');
    }
  }, "Delete")), u.is_super_admin && /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#64748b',
      fontSize: '0.8rem'
    }
  }, "Protected"), u.id === user.id && !u.is_super_admin && /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#64748b',
      fontSize: '0.8rem'
    }
  }, "(You)"))))))), showCreate && /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: 'rgba(0,0,0,0.3)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000
    },
    onClick: e => {
      if (e.target === e.currentTarget) setShowCreate(false);
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      borderRadius: '12px',
      padding: '2rem',
      width: '100%',
      maxWidth: '440px'
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '1.2rem',
      color: '#14b8a6',
      marginTop: 0,
      marginBottom: '1.5rem'
    }
  }, "Create User"), /*#__PURE__*/React.createElement("form", {
    onSubmit: handleCreate
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: '1rem'
    }
  }, /*#__PURE__*/React.createElement("input", {
    style: styles.input,
    placeholder: "Full Name",
    required: true,
    value: createForm.name,
    onChange: e => setCreateForm({
      ...createForm,
      name: e.target.value
    })
  }), /*#__PURE__*/React.createElement("input", {
    style: styles.input,
    type: "email",
    placeholder: "Email",
    required: true,
    value: createForm.email,
    onChange: e => setCreateForm({
      ...createForm,
      email: e.target.value
    })
  }), /*#__PURE__*/React.createElement("input", {
    style: styles.input,
    type: "password",
    placeholder: "Password (8+ chars)",
    required: true,
    minLength: 8,
    value: createForm.password,
    onChange: e => setCreateForm({
      ...createForm,
      password: e.target.value
    })
  }), /*#__PURE__*/React.createElement("select", {
    style: styles.select,
    value: createForm.role,
    onChange: e => setCreateForm({
      ...createForm,
      role: e.target.value
    })
  }, /*#__PURE__*/React.createElement("option", {
    value: "producer"
  }, "Producer"), /*#__PURE__*/React.createElement("option", {
    value: "broker"
  }, "Broker"), /*#__PURE__*/React.createElement("option", {
    value: "admin"
  }, "Admin")), createError && /*#__PURE__*/React.createElement("div", {
    style: {
      color: '#ef4444',
      fontSize: '0.85rem'
    }
  }, createError), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.75rem',
      justifyContent: 'flex-end'
    }
  }, /*#__PURE__*/React.createElement("button", {
    type: "button",
    style: styles.btn,
    onClick: () => setShowCreate(false)
  }, "Cancel"), /*#__PURE__*/React.createElement("button", {
    type: "submit",
    style: styles.btnPrimary
  }, "Create")))))), confirmDelete && /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: 'rgba(0,0,0,0.3)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000
    },
    onClick: e => {
      if (e.target === e.currentTarget) setConfirmDelete(null);
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#FFFFFF',
      border: '1px solid #ef4444',
      borderRadius: '12px',
      padding: '2rem',
      width: '100%',
      maxWidth: '440px'
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '1.2rem',
      color: '#ef4444',
      marginTop: 0,
      marginBottom: '0.75rem'
    }
  }, "Delete User"), /*#__PURE__*/React.createElement("p", {
    style: {
      color: '#64748b',
      fontSize: '0.9rem',
      marginBottom: '1rem'
    }
  }, "This will permanently delete ", /*#__PURE__*/React.createElement("strong", {
    style: {
      color: '#0f172a'
    }
  }, confirmDelete.name), " (", confirmDelete.email, ") and revoke all their sessions immediately."), /*#__PURE__*/React.createElement("p", {
    style: {
      color: '#64748b',
      fontSize: '0.85rem',
      marginBottom: '1rem'
    }
  }, "Type ", /*#__PURE__*/React.createElement("strong", {
    style: {
      color: '#ef4444'
    }
  }, "DELETE"), " to confirm:"), /*#__PURE__*/React.createElement("input", {
    style: {
      ...styles.input,
      width: '100%',
      marginBottom: '1rem',
      boxSizing: 'border-box'
    },
    value: deleteConfirmText,
    onChange: e => setDeleteConfirmText(e.target.value),
    placeholder: "Type DELETE"
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.75rem',
      justifyContent: 'flex-end'
    }
  }, /*#__PURE__*/React.createElement("button", {
    style: styles.btn,
    onClick: () => setConfirmDelete(null)
  }, "Cancel"), /*#__PURE__*/React.createElement("button", {
    style: {
      ...styles.btnPrimary,
      background: '#ef4444',
      opacity: deleteConfirmText === 'DELETE' ? 1 : 0.4
    },
    disabled: deleteConfirmText !== 'DELETE',
    onClick: () => handleDelete(confirmDelete.id)
  }, "Delete User")))), resetTarget && /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: 'rgba(0,0,0,0.3)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000
    },
    onClick: e => {
      if (e.target === e.currentTarget) setResetTarget(null);
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      borderRadius: '12px',
      padding: '2rem',
      width: '100%',
      maxWidth: '440px'
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '1.2rem',
      color: '#14b8a6',
      marginTop: 0,
      marginBottom: '0.75rem'
    }
  }, "Reset Password"), /*#__PURE__*/React.createElement("p", {
    style: {
      color: '#64748b',
      fontSize: '0.9rem',
      marginBottom: '1rem'
    }
  }, "Set a new password for ", /*#__PURE__*/React.createElement("strong", {
    style: {
      color: '#0f172a'
    }
  }, resetTarget.name), " (", resetTarget.email, "). This will log them out of all sessions."), /*#__PURE__*/React.createElement("input", {
    style: {
      ...styles.input,
      width: '100%',
      marginBottom: '1rem',
      boxSizing: 'border-box'
    },
    type: "password",
    placeholder: "New password (8+ chars)",
    minLength: 8,
    value: resetPassword,
    onChange: e => setResetPassword(e.target.value)
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.75rem',
      justifyContent: 'flex-end'
    }
  }, /*#__PURE__*/React.createElement("button", {
    style: styles.btn,
    onClick: () => setResetTarget(null)
  }, "Cancel"), /*#__PURE__*/React.createElement("button", {
    style: {
      ...styles.btnPrimary,
      opacity: resetPassword.length >= 8 ? 1 : 0.4
    },
    disabled: resetPassword.length < 8,
    onClick: handleResetPassword
  }, "Reset Password")))));
}

// ======= TOUCHPOINT MODAL =======
function TouchpointModal({
  target,
  onClose,
  onSaved
}) {
  const [type, setType] = useState('Call');
  const [outcome, setOutcome] = useState('');
  const [notes, setNotes] = useState('');
  const [nextFollowup, setNextFollowup] = useState('');
  const [saving, setSaving] = useState(false);
  const handleSave = async () => {
    setSaving(true);
    try {
      const body = {
        type,
        outcome: outcome || null,
        notes: notes || null
      };
      if (nextFollowup) body.next_followup_at = new Date(nextFollowup).toISOString();
      const res = await fetch(`${API_BASE}/api/crm/leads/${target.lead_id}/touchpoints`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (data.success) {
        onSaved();
        onClose();
      }
    } catch (e) {
      console.error('Touchpoint save error:', e);
    }
    setSaving(false);
  };
  return /*#__PURE__*/React.createElement("div", {
    style: styles.modalOverlay,
    onClick: onClose
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      ...styles.modal,
      maxWidth: '480px'
    },
    onClick: e => e.stopPropagation()
  }, /*#__PURE__*/React.createElement("div", {
    style: styles.modalHeader
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontSize: '1.1rem'
    }
  }, "Log Touchpoint \u2014 ", target.company_name), /*#__PURE__*/React.createElement("button", {
    style: styles.closeBtn,
    onClick: onClose
  }, "\u2715")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: '0.85rem'
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    style: {
      fontSize: '0.75rem',
      color: '#64748b',
      fontWeight: 600,
      textTransform: 'uppercase',
      display: 'block',
      marginBottom: '0.3rem'
    }
  }, "Type"), /*#__PURE__*/React.createElement("select", {
    style: {
      ...styles.select,
      width: '100%'
    },
    value: type,
    onChange: e => setType(e.target.value)
  }, /*#__PURE__*/React.createElement("option", {
    value: "Call"
  }, "Call"), /*#__PURE__*/React.createElement("option", {
    value: "Email"
  }, "Email"), /*#__PURE__*/React.createElement("option", {
    value: "LinkedIn"
  }, "LinkedIn"), /*#__PURE__*/React.createElement("option", {
    value: "Meeting"
  }, "Meeting"), /*#__PURE__*/React.createElement("option", {
    value: "Quote"
  }, "Quote"), /*#__PURE__*/React.createElement("option", {
    value: "Other"
  }, "Other"))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    style: {
      fontSize: '0.75rem',
      color: '#64748b',
      fontWeight: 600,
      textTransform: 'uppercase',
      display: 'block',
      marginBottom: '0.3rem'
    }
  }, "Outcome"), /*#__PURE__*/React.createElement("select", {
    style: {
      ...styles.select,
      width: '100%'
    },
    value: outcome,
    onChange: e => setOutcome(e.target.value)
  }, /*#__PURE__*/React.createElement("option", {
    value: ""
  }, "\u2014 Select \u2014"), /*#__PURE__*/React.createElement("option", {
    value: "Connected"
  }, "Connected"), /*#__PURE__*/React.createElement("option", {
    value: "Left Voicemail"
  }, "Left Voicemail"), /*#__PURE__*/React.createElement("option", {
    value: "No Answer"
  }, "No Answer"), /*#__PURE__*/React.createElement("option", {
    value: "Meeting Set"
  }, "Meeting Set"), /*#__PURE__*/React.createElement("option", {
    value: "Sent Info"
  }, "Sent Info"), /*#__PURE__*/React.createElement("option", {
    value: "Not Interested"
  }, "Not Interested"), /*#__PURE__*/React.createElement("option", {
    value: "Follow Up Later"
  }, "Follow Up Later"))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    style: {
      fontSize: '0.75rem',
      color: '#64748b',
      fontWeight: 600,
      textTransform: 'uppercase',
      display: 'block',
      marginBottom: '0.3rem'
    }
  }, "Notes"), /*#__PURE__*/React.createElement("textarea", {
    rows: 3,
    value: notes,
    onChange: e => setNotes(e.target.value),
    placeholder: "Call notes...",
    style: {
      ...styles.input,
      width: '100%',
      minWidth: 0,
      resize: 'vertical',
      fontFamily: "'Inter',sans-serif"
    }
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    style: {
      fontSize: '0.75rem',
      color: '#64748b',
      fontWeight: 600,
      textTransform: 'uppercase',
      display: 'block',
      marginBottom: '0.3rem'
    }
  }, "Next Follow-up"), /*#__PURE__*/React.createElement("input", {
    type: "date",
    value: nextFollowup,
    onChange: e => setNextFollowup(e.target.value),
    style: {
      ...styles.input,
      width: '100%',
      minWidth: 0
    }
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.75rem',
      justifyContent: 'flex-end'
    }
  }, /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: styles.btn,
    onClick: onClose
  }, "Cancel"), /*#__PURE__*/React.createElement("button", {
    className: "action-btn",
    style: {
      ...styles.btnPrimary,
      ...(saving ? {
        opacity: 0.5
      } : {})
    },
    onClick: handleSave,
    disabled: saving
  }, saving ? 'Saving...' : 'Save Touchpoint')))));
}

// ======= ACTIVITY TIMELINE MODAL =======
function ActivityModal({
  leadId,
  companyName,
  onClose,
  user
}) {
  const [activities, setActivities] = useState([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    fetch(`${API_BASE}/api/crm/leads/${leadId}/activity`).then(r => r.json()).then(d => {
      if (d.success) setActivities(d.activities || []);
    }).catch(() => {}).finally(() => setLoading(false));
  }, [leadId]);
  const ACTION_LABELS = {
    'SAVED': 'saved this lead',
    'STATUS_CHANGED': a => `changed status from "${a.old_value || '—'}" to "${a.new_value || '—'}"`,
    'NOTE_ADDED': a => {
      const nv = a.new_value || {};
      return `logged ${nv.type || 'touchpoint'}${nv.outcome ? ` (${nv.outcome})` : ''}${nv.notes ? `: "${nv.notes.length > 80 ? nv.notes.slice(0, 80) + '...' : nv.notes}"` : ''}`;
    },
    'FOLLOWUP_SET': a => `set follow-up to ${a.new_value ? new Date(a.new_value).toLocaleDateString() : '—'}`,
    'FOLLOWUP_CLEARED': 'cleared follow-up date',
    'OWNER_ASSIGNED': a => `assigned ownership`,
    'OWNER_CLEARED': 'removed ownership (unassigned)'
  };
  const describeAction = a => {
    const label = ACTION_LABELS[a.action_type];
    if (!label) return a.action_type.toLowerCase().replace(/_/g, ' ');
    return typeof label === 'function' ? label(a) : label;
  };
  const timeAgo = ts => {
    if (!ts) return '';
    const diff = Date.now() - new Date(ts).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    if (days < 30) return `${days}d ago`;
    return new Date(ts).toLocaleDateString();
  };
  const ACTION_COLORS = {
    'SAVED': '#34d399',
    'STATUS_CHANGED': '#3b82f6',
    'NOTE_ADDED': '#a5b4fc',
    'FOLLOWUP_SET': '#fbbf24',
    'FOLLOWUP_CLEARED': '#94a3b8',
    'OWNER_ASSIGNED': '#c4b5fd',
    'OWNER_CLEARED': '#f87171'
  };
  return /*#__PURE__*/React.createElement("div", {
    style: styles.modalOverlay,
    onClick: onClose
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      ...styles.modal,
      maxWidth: '560px',
      maxHeight: '80vh'
    },
    onClick: e => e.stopPropagation()
  }, /*#__PURE__*/React.createElement("div", {
    style: styles.modalHeader
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontSize: '1.1rem',
      margin: 0
    }
  }, "Activity: ", companyName), /*#__PURE__*/React.createElement("button", {
    style: styles.closeBtn,
    onClick: onClose
  }, "\u2715")), /*#__PURE__*/React.createElement("div", {
    style: {
      overflowY: 'auto',
      maxHeight: '60vh',
      padding: '1rem'
    }
  }, loading && /*#__PURE__*/React.createElement("div", {
    style: {
      color: '#64748b',
      textAlign: 'center',
      padding: '2rem'
    }
  }, "Loading..."), !loading && activities.length === 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      color: '#94a3b8',
      textAlign: 'center',
      padding: '2rem',
      fontStyle: 'italic'
    }
  }, "No activity recorded yet."), !loading && activities.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'relative',
      paddingLeft: '1.5rem'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: '6px',
      top: '8px',
      bottom: '8px',
      width: '2px',
      background: '#e2e8f0'
    }
  }), activities.map((a, i) => /*#__PURE__*/React.createElement("div", {
    key: a.id,
    style: {
      position: 'relative',
      marginBottom: '1rem',
      paddingLeft: '1rem'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: '-1.5rem',
      top: '6px',
      width: '12px',
      height: '12px',
      borderRadius: '50%',
      background: ACTION_COLORS[a.action_type] || '#64748b',
      border: '2px solid #0f172a',
      zIndex: 1
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'flex-start',
      gap: '0.5rem'
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#0f172a',
      fontSize: '0.85rem',
      fontWeight: 600
    }
  }, a.actor.id === user?.id ? 'You' : a.actor.name), /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#64748b',
      fontSize: '0.85rem'
    }
  }, " ", describeAction(a))), /*#__PURE__*/React.createElement("span", {
    style: {
      color: '#94a3b8',
      fontSize: '0.7rem',
      whiteSpace: 'nowrap',
      flexShrink: 0
    }
  }, timeAgo(a.created_at))), a.actor.role === 'admin' && a.actor.id !== user?.id && /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.65rem',
      color: '#64748b',
      fontStyle: 'italic'
    }
  }, "(", a.actor.role, ")")))))));
}

// ======= PIPELINE PAGE =======
if (typeof document !== 'undefined' && !document.getElementById('pipeline-panel-anim')) {
  var _s = document.createElement('style'); _s.id = 'pipeline-panel-anim';
  _s.textContent = '@keyframes slideInRight{from{transform:translateX(100%)}to{transform:translateX(0)}}' +
    '.pl-row .pl-hover-actions{opacity:0;pointer-events:none;transition:opacity 0.15s}' +
    '.pl-row:hover .pl-hover-actions{opacity:1;pointer-events:auto}' +
    '.pl-row{transition:box-shadow 0.15s,transform 0.15s}' +
    '.pl-row:hover{box-shadow:0 4px 12px rgba(0,0,0,0.08)!important;transform:translateY(-1px)}';
  document.head.appendChild(_s);
}
function PipelinePage({
  user
}) {
  const [leads, setLeads] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all'); // status filter
  const [ownerFilter, setOwnerFilter] = useState('me');
  const [touchpointTarget, setTouchpointTarget] = useState(null);
  const [activityTarget, setActivityTarget] = useState(null);
  const [workspaceUsers, setWorkspaceUsers] = useState([]);
  const [panelLead, setPanelLead] = useState(null);
  useEffect(() => {
    loadLeads();
    if (user?.role === 'admin') {
      fetch(`${API_BASE}/api/crm/workspace-users`).then(r => r.json()).then(d => {
        if (d.success) setWorkspaceUsers(d.users || []);
      }).catch(() => {});
    }
  }, [filter, ownerFilter]);
  const loadLeads = async () => {
    setLoading(true);
    let url = `${API_BASE}/api/crm/leads?owner=${ownerFilter}`;
    if (filter !== 'all') url += `&status=${filter}`;
    try {
      const res = await fetch(url);
      const data = await res.json();
      if (data.success) setLeads(data.leads);
    } catch (e) {
      console.error('Pipeline load error:', e);
    }
    setLoading(false);
  };
  const updateLead = async (leadId, field, value) => {
    try {
      await fetch(`${API_BASE}/api/crm/leads/${leadId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          [field]: value
        })
      });
      loadLeads();
    } catch (e) {
      console.error('Lead update error:', e);
    }
  };
  const _panelRow = (label, val) => /*#__PURE__*/React.createElement("div", {
    style: { display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem' }
  },
    /*#__PURE__*/React.createElement("span", { style: { color: '#94a3b8' } }, label),
    /*#__PURE__*/React.createElement("span", { style: { color: '#64748b' } }, val || '\u2014')
  );
  const statusPill = (active, label) => ({
    fontSize: '0.8rem',
    padding: '0.35rem 0.75rem',
    borderRadius: '9999px',
    border: `1px solid ${active ? '#34d399' : '#e2e8f0'}`,
    background: active ? 'rgba(20,184,166,0.1)' : 'transparent',
    color: active ? '#34d399' : '#94a3b8',
    cursor: 'pointer',
    fontFamily: 'Inter,sans-serif',
    fontWeight: 500
  });
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.5rem',
      flexWrap: 'wrap',
      marginBottom: '1.5rem',
      alignItems: 'center'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.75rem',
      color: '#64748b',
      textTransform: 'uppercase',
      fontWeight: 600,
      marginRight: '0.25rem'
    }
  }, "Owner"), /*#__PURE__*/React.createElement("button", {
    className: "filter-pill",
    style: statusPill(ownerFilter === 'me', 'Me'),
    onClick: () => setOwnerFilter('me')
  }, "My Leads"), user?.role === 'admin' && /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("button", {
    className: "filter-pill",
    style: statusPill(ownerFilter === 'unassigned', 'Unassigned'),
    onClick: () => setOwnerFilter('unassigned')
  }, "Unassigned"), /*#__PURE__*/React.createElement("button", {
    className: "filter-pill",
    style: statusPill(ownerFilter === 'all', 'All'),
    onClick: () => setOwnerFilter('all')
  }, "All")), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.75rem',
      color: '#64748b',
      textTransform: 'uppercase',
      fontWeight: 600,
      marginLeft: '1rem',
      marginRight: '0.25rem'
    }
  }, "Status"), /*#__PURE__*/React.createElement("button", {
    className: "filter-pill",
    style: statusPill(filter === 'all', 'All'),
    onClick: () => setFilter('all')
  }, "All"), CRM_STATUSES.map(s => /*#__PURE__*/React.createElement("button", {
    key: s,
    className: "filter-pill",
    style: statusPill(filter === s, s),
    onClick: () => setFilter(s)
  }, s))), loading && /*#__PURE__*/React.createElement("div", {
    style: styles.loading
  }, /*#__PURE__*/React.createElement("div", {
    style: styles.loadingText
  }, "Loading pipeline...")), !loading && leads.length === 0 && /*#__PURE__*/React.createElement(EmptyState, {
    title: "No leads in pipeline",
    subtitle: "Save prospects to your pipeline from the search tab",
    icon: /*#__PURE__*/React.createElement("svg", {
      width: "36",
      height: "36",
      viewBox: "0 0 24 24",
      fill: "none",
      stroke: "currentColor",
      strokeWidth: "1.5",
      className: "text-slate-600"
    }, /*#__PURE__*/React.createElement("rect", {
      x: "3",
      y: "3",
      width: "7",
      height: "7"
    }), /*#__PURE__*/React.createElement("rect", {
      x: "14",
      y: "3",
      width: "7",
      height: "7"
    }), /*#__PURE__*/React.createElement("rect", {
      x: "14",
      y: "14",
      width: "7",
      height: "7"
    }), /*#__PURE__*/React.createElement("rect", {
      x: "3",
      y: "14",
      width: "7",
      height: "7"
    }))
  }), !loading && leads.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: '0.75rem'
    }
  }, leads.map(lead => {
    const contactName = [lead.contact_first_name, lead.contact_last_name].filter(Boolean).join(' ');
    const heatColor = lead.warmth_score >= 70 ? '#34d399' : lead.warmth_score >= 40 ? '#fbbf24' : lead.warmth_score >= 1 ? '#fb923c' : '#94a3b8';
    const stageMeta = { cold: 'Cold', initial_outreach: 'Outreach', light_conversation: 'Follow-Up', active: 'Active', warm: 'Warm', strategic: 'Strategic', dormant: 'Dormant' };
    return /*#__PURE__*/React.createElement("div", {
    key: lead.id,
    className: 'pl-row',
    onClick: () => setPanelLead(lead),
    style: {
      background: '#FFFFFF',
      border: '1px solid #e2e8f0',
      borderRadius: '12px',
      padding: '1rem',
      display: 'flex',
      alignItems: 'center',
      gap: '1rem',
      flexWrap: 'wrap',
      cursor: 'pointer',
      boxShadow: '0 1px 3px rgba(0,0,0,0.04)',
      position: 'relative',
      transition: 'border-color 0.15s'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      minWidth: '200px'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "'Orbitron',sans-serif",
      fontSize: '1rem',
      fontWeight: 700,
      color: '#0f172a',
      marginBottom: '0.2rem'
    }
  }, lead.company_name), /*#__PURE__*/React.createElement("div", {
    style: { display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap', marginBottom: '0.2rem' }
  },
    /*#__PURE__*/React.createElement("span", {
      style: { fontSize: '0.75rem', color: '#64748b' }
    }, lead.owner_user_id === user?.id ? 'Me' : lead.owner_name || 'Unassigned'),
    contactName && /*#__PURE__*/React.createElement("span", {
      style: { fontSize: '0.72rem', color: '#64748b' }
    }, '\u00B7 ' + contactName + (lead.contact_title ? ' (' + lead.contact_title + ')' : '')),
    lead.relationship_stage && /*#__PURE__*/React.createElement("span", {
      style: { fontSize: '0.6rem', padding: '0.1rem 0.4rem', borderRadius: '9999px', background: 'rgba(96,165,250,0.15)', color: '#60a5fa', fontWeight: 600 }
    }, stageMeta[lead.relationship_stage] || lead.relationship_stage),
    lead.warmth_score > 0 && /*#__PURE__*/React.createElement("span", {
      style: { fontSize: '0.6rem', padding: '0.1rem 0.4rem', borderRadius: '9999px', background: heatColor + '22', color: heatColor, fontWeight: 600 }
    }, 'Heat ' + lead.warmth_score),
    lead.source && lead.source !== 'manual' && /*#__PURE__*/React.createElement("span", {
      style: { fontSize: '0.58rem', padding: '0.1rem 0.35rem', borderRadius: '0.2rem', background: 'rgba(167,139,250,0.15)', color: '#a78bfa', fontWeight: 500 }
    }, lead.source)
  ),
    /*#__PURE__*/React.createElement("div", {
      style: {
        display: 'inline-flex', alignItems: 'center', gap: '0.3rem', marginTop: '0.15rem',
        fontSize: '0.64rem', fontWeight: 600, fontFamily: "'Inter',sans-serif",
        padding: '0.15rem 0.45rem', borderRadius: '0.3rem',
        background: lead.last_signal_title ? 'rgba(251,191,36,0.12)' : 'rgba(226,232,240,0.3)',
        color: lead.last_signal_title ? '#fbbf24' : '#94a3b8'
      }
    },
      /*#__PURE__*/React.createElement("span", {
        style: { fontSize: '0.72rem', lineHeight: 1 }
      }, lead.last_signal_title ? '\u26A1' : '\u25CB'),
      lead.last_signal_title
        ? (lead.last_signal_title.length > 38 ? lead.last_signal_title.slice(0, 38) + '\u2026' : lead.last_signal_title)
        : 'No recent signals'
    )
  ), /*#__PURE__*/React.createElement("select", {
    style: {
      ...styles.select,
      fontSize: '0.8rem',
      padding: '0.35rem 0.5rem'
    },
    value: lead.status,
    onChange: e => updateLead(lead.id, 'status', e.target.value)
  }, CRM_STATUSES.map(s => /*#__PURE__*/React.createElement("option", {
    key: s,
    value: s
  }, s))), user?.role === 'admin' && /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '0.5rem'
    }
  }, /*#__PURE__*/React.createElement("label", {
    style: {
      fontSize: '0.7rem',
      color: '#64748b'
    }
  }, "Assign:"), /*#__PURE__*/React.createElement("select", {
    style: {
      ...styles.select,
      fontSize: '0.8rem',
      padding: '0.35rem 0.5rem',
      minWidth: '120px'
    },
    value: lead.owner_user_id || '',
    onChange: async e => {
      const newOwnerId = e.target.value || null;
      try {
        await fetch(`${API_BASE}/api/crm/leads/${lead.id}/assign`, {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            owner_id: newOwnerId
          })
        });
        loadLeads();
      } catch (err) {
        console.error('Reassign error:', err);
      }
    }
  }, /*#__PURE__*/React.createElement("option", {
    value: ""
  }, "Unassigned"), workspaceUsers.map(u => /*#__PURE__*/React.createElement("option", {
    key: u.id,
    value: u.id
  }, u.name)))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '0.5rem'
    }
  }, /*#__PURE__*/React.createElement("label", {
    style: {
      fontSize: '0.7rem',
      color: '#64748b'
    }
  }, "Follow-up:"), /*#__PURE__*/React.createElement("input", {
    type: "date",
    style: {
      ...styles.input,
      minWidth: '130px',
      fontSize: '0.8rem',
      padding: '0.3rem 0.5rem'
    },
    value: lead.next_followup_at ? lead.next_followup_at.split('T')[0] : '',
    onChange: e => updateLead(lead.id, 'next_followup_at', e.target.value ? new Date(e.target.value).toISOString() : null)
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.72rem',
      fontWeight: 600,
      color: '#fbbf24',
      background: 'rgba(251,191,36,0.1)',
      padding: '0.2rem 0.55rem',
      borderRadius: '0.35rem',
      whiteSpace: 'nowrap',
      fontFamily: "'Inter',sans-serif"
    }
  }, (() => {
    const s = lead.status;
    if (s === 'New') return 'Initial outreach';
    if (s === 'Contacted') return 'Follow up';
    if (s === 'InDiscussion') return 'Continue conversation';
    if (s === 'Quoted') return 'Check decision status';
    if (s === 'Nurture') return 'Re-engage after inactivity';
    if (s === 'Won' || s === 'Lost') return 'Review account';
    return 'Review account';
  })()), lead.last_activity_at && /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: '0.7rem',
      color: '#94a3b8'
    }
  }, (() => {
    const diff = Date.now() - new Date(lead.last_activity_at).getTime();
    const d = Math.floor(diff / 86400000);
    const label = (lead.last_action_type || '').replace(/_/g, ' ').toLowerCase();
    return `${d === 0 ? 'Today' : d + 'd ago'} · ${label}`;
  })()), /*#__PURE__*/React.createElement("div", {
    className: 'pl-hover-actions',
    style: {
      display: 'flex', gap: '0.35rem', alignItems: 'center',
      marginLeft: 'auto', flexShrink: 0
    }
  },
    /*#__PURE__*/React.createElement("button", {
      onClick: e => { e.stopPropagation(); const cn = [lead.contact_first_name, lead.contact_last_name].filter(Boolean).join(' '); _launchSignalStack({ contact: { first_name: lead.contact_first_name, last_name: lead.contact_last_name, title: lead.contact_title }, group: lead.group_name ? { name: lead.group_name } : { name: lead.company_name }, relationship_stage: lead.relationship_stage, channel: 'email', title: 'Outreach \u2014 ' + (cn || lead.company_name) }); },
      style: { background: 'rgba(20,184,166,0.1)', border: '1px solid #e2e8f0', color: '#0d9488', padding: '0.25rem 0.55rem', borderRadius: '0.35rem', fontSize: '0.68rem', fontWeight: 600, cursor: 'pointer', fontFamily: "'Inter',sans-serif", whiteSpace: 'nowrap' }
    }, "Draft"),
    /*#__PURE__*/React.createElement("button", {
      onClick: e => { e.stopPropagation(); setTouchpointTarget({ lead_id: lead.id, company_name: lead.company_name }); },
      style: { background: 'transparent', border: '1px solid #e2e8f0', color: '#64748b', padding: '0.25rem 0.55rem', borderRadius: '0.35rem', fontSize: '0.68rem', fontWeight: 600, cursor: 'pointer', fontFamily: "'Inter',sans-serif", whiteSpace: 'nowrap' }
    }, "Log Touch"),
    /*#__PURE__*/React.createElement("button", {
      onClick: e => { e.stopPropagation(); const d = prompt('Follow-up date (YYYY-MM-DD):'); if (d) updateLead(lead.id, 'next_followup_at', new Date(d).toISOString()); },
      style: { background: 'transparent', border: '1px solid #e2e8f0', color: '#64748b', padding: '0.25rem 0.55rem', borderRadius: '0.35rem', fontSize: '0.68rem', fontWeight: 600, cursor: 'pointer', fontFamily: "'Inter',sans-serif", whiteSpace: 'nowrap' }
    }, "Follow-Up"),
    /*#__PURE__*/React.createElement("select", {
      value: lead.status,
      onClick: e => e.stopPropagation(),
      onChange: e => { e.stopPropagation(); updateLead(lead.id, 'status', e.target.value); },
      style: { background: '#F1F5F9', border: '1px solid #e2e8f0', color: '#64748b', padding: '0.25rem 0.4rem', borderRadius: '0.35rem', fontSize: '0.68rem', fontWeight: 600, cursor: 'pointer', fontFamily: "'Inter',sans-serif" }
    }, CRM_STATUSES.map(s => /*#__PURE__*/React.createElement("option", { key: s, value: s }, s)))
  )
  )})), touchpointTarget && /*#__PURE__*/React.createElement(TouchpointModal, {
    target: touchpointTarget,
    onClose: () => setTouchpointTarget(null),
    onSaved: loadLeads
  }), activityTarget && /*#__PURE__*/React.createElement(ActivityModal, {
    leadId: activityTarget.lead_id,
    companyName: activityTarget.company_name,
    onClose: () => setActivityTarget(null),
    user: user
  }),

  panelLead && /*#__PURE__*/React.createElement("div", {
    onClick: () => setPanelLead(null),
    style: {
      position: 'fixed', inset: 0, zIndex: 999,
      background: 'rgba(0,0,0,0.1)',
      transition: 'opacity 0.2s'
    }
  },
    /*#__PURE__*/React.createElement("div", {
      onClick: e => e.stopPropagation(),
      style: {
        position: 'absolute', top: 0, right: 0, bottom: 0,
        width: '420px', maxWidth: '90vw',
        background: '#F1F5F9',
        borderLeft: '1px solid #e2e8f0',
        boxShadow: '-8px 0 30px rgba(0,0,0,0.12)',
        display: 'flex', flexDirection: 'column',
        overflow: 'hidden',
        animation: 'slideInRight 0.2s ease-out'
      }
    },

      /*#__PURE__*/React.createElement("div", {
        style: {
          padding: '1rem 1.25rem',
          borderBottom: '1px solid #e2e8f0',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center'
        }
      },
        /*#__PURE__*/React.createElement("div", {
          style: { fontFamily: "'Orbitron',sans-serif", fontSize: '1rem', fontWeight: 700, color: '#0f172a' }
        }, panelLead.company_name),
        /*#__PURE__*/React.createElement("button", {
          onClick: () => setPanelLead(null),
          style: {
            background: 'transparent', border: 'none', color: '#64748b',
            fontSize: '1.2rem', cursor: 'pointer', padding: '0.25rem', lineHeight: 1
          }
        }, '\u2715')
      ),

      /*#__PURE__*/React.createElement("div", {
        style: {
          padding: '0.75rem 1.25rem',
          borderBottom: '1px solid #e2e8f0',
          display: 'flex', gap: '0.5rem', flexWrap: 'wrap'
        }
      },
        /*#__PURE__*/React.createElement("button", {
          onClick: () => {
            const cn = [panelLead.contact_first_name, panelLead.contact_last_name].filter(Boolean).join(' ');
            _launchSignalStack({
              contact: { first_name: panelLead.contact_first_name, last_name: panelLead.contact_last_name, title: panelLead.contact_title },
              group: panelLead.group_name ? { name: panelLead.group_name } : { name: panelLead.company_name },
              relationship_stage: panelLead.relationship_stage,
              channel: 'email',
              title: 'Outreach \u2014 ' + (cn || panelLead.company_name)
            });
          },
          style: { background: 'rgba(20,184,166,0.1)', border: '1px solid #e2e8f0', color: '#0d9488', padding: '0.35rem 0.7rem', borderRadius: '0.4rem', fontSize: '0.72rem', fontWeight: 600, cursor: 'pointer', fontFamily: "'Inter',sans-serif" }
        }, "Draft in SignalStack"),
        /*#__PURE__*/React.createElement("button", {
          onClick: () => { setPanelLead(null); setTouchpointTarget({ lead_id: panelLead.id, company_name: panelLead.company_name }); },
          style: { background: 'transparent', border: '1px solid #e2e8f0', color: '#64748b', padding: '0.35rem 0.7rem', borderRadius: '0.4rem', fontSize: '0.72rem', fontWeight: 600, cursor: 'pointer', fontFamily: "'Inter',sans-serif" }
        }, "Log Touch"),
        /*#__PURE__*/React.createElement("button", {
          onClick: () => {
            const d = prompt('Follow-up date (YYYY-MM-DD):');
            if (d) updateLead(panelLead.id, 'next_followup_at', new Date(d).toISOString());
          },
          style: { background: 'transparent', border: '1px solid #e2e8f0', color: '#64748b', padding: '0.35rem 0.7rem', borderRadius: '0.4rem', fontSize: '0.72rem', fontWeight: 600, cursor: 'pointer', fontFamily: "'Inter',sans-serif" }
        }, "Set Follow-Up"),
        /*#__PURE__*/React.createElement("select", {
          value: panelLead.status,
          onChange: e => { updateLead(panelLead.id, 'status', e.target.value); setPanelLead(Object.assign({}, panelLead, { status: e.target.value })); },
          style: { background: '#FFFFFF', border: '1px solid #e2e8f0', color: '#64748b', padding: '0.35rem 0.5rem', borderRadius: '0.4rem', fontSize: '0.72rem', fontWeight: 600, cursor: 'pointer', fontFamily: "'Inter',sans-serif" }
        }, CRM_STATUSES.map(s => /*#__PURE__*/React.createElement("option", { key: s, value: s }, s)))
      ),

      /*#__PURE__*/React.createElement("div", {
        style: { flex: 1, overflowY: 'auto', padding: '1rem 1.25rem' }
      },

        /*#__PURE__*/React.createElement("div", { style: { marginBottom: '1.25rem' } },
          /*#__PURE__*/React.createElement("div", {
            style: { fontSize: '0.65rem', textTransform: 'uppercase', color: '#94a3b8', fontWeight: 700, letterSpacing: '0.06em', marginBottom: '0.4rem' }
          }, "Details"),
          /*#__PURE__*/React.createElement("div", { style: { display: 'flex', flexDirection: 'column', gap: '0.35rem' } },
            _panelRow('Status', panelLead.status),
            _panelRow('Owner', panelLead.owner_user_id === user?.id ? 'Me' : panelLead.owner_name || 'Unassigned'),
            _panelRow('Source', panelLead.source || 'manual'),
            _panelRow('Created', panelLead.created_at ? new Date(panelLead.created_at).toLocaleDateString() : '\u2014')
          )
        ),

        panelLead.group_name && /*#__PURE__*/React.createElement("div", { style: { marginBottom: '1.25rem' } },
          /*#__PURE__*/React.createElement("div", {
            style: { fontSize: '0.65rem', textTransform: 'uppercase', color: '#94a3b8', fontWeight: 700, letterSpacing: '0.06em', marginBottom: '0.4rem' }
          }, "Group / Account"),
          /*#__PURE__*/React.createElement("div", { style: { fontSize: '0.85rem', color: '#1e293b', marginBottom: '0.15rem' } }, panelLead.group_name),
          panelLead.warmth_score > 0 && /*#__PURE__*/React.createElement("span", {
            style: { fontSize: '0.68rem', color: panelLead.warmth_score >= 70 ? '#34d399' : panelLead.warmth_score >= 40 ? '#fbbf24' : '#fb923c' }
          }, 'Warmth: ' + panelLead.warmth_score)
        ),

        /*#__PURE__*/React.createElement("div", { style: { marginBottom: '1.25rem' } },
          /*#__PURE__*/React.createElement("div", {
            style: { fontSize: '0.65rem', textTransform: 'uppercase', color: '#94a3b8', fontWeight: 700, letterSpacing: '0.06em', marginBottom: '0.4rem' }
          }, "Contact"),
          (() => {
            const cn = [panelLead.contact_first_name, panelLead.contact_last_name].filter(Boolean).join(' ');
            return cn
              ? /*#__PURE__*/React.createElement("div", null,
                  /*#__PURE__*/React.createElement("div", { style: { fontSize: '0.85rem', color: '#1e293b' } }, cn),
                  panelLead.contact_title && /*#__PURE__*/React.createElement("div", { style: { fontSize: '0.75rem', color: '#64748b' } }, panelLead.contact_title),
                  panelLead.relationship_stage && /*#__PURE__*/React.createElement("div", { style: { fontSize: '0.68rem', color: '#60a5fa', marginTop: '0.2rem' } }, 'Stage: ' + (({ cold:'Cold', initial_outreach:'Outreach', light_conversation:'Follow-Up', active:'Active', warm:'Warm', strategic:'Strategic', dormant:'Dormant' })[panelLead.relationship_stage] || panelLead.relationship_stage))
                )
              : /*#__PURE__*/React.createElement("div", { style: { fontSize: '0.78rem', color: '#94a3b8', fontStyle: 'italic' } }, 'No contact linked');
          })()
        ),

        /*#__PURE__*/React.createElement("div", { style: { marginBottom: '1.25rem' } },
          /*#__PURE__*/React.createElement("div", {
            style: { fontSize: '0.65rem', textTransform: 'uppercase', color: '#94a3b8', fontWeight: 700, letterSpacing: '0.06em', marginBottom: '0.4rem' }
          }, "Last Touch"),
          panelLead.last_activity_at
            ? /*#__PURE__*/React.createElement("div", null,
                /*#__PURE__*/React.createElement("div", { style: { fontSize: '0.82rem', color: '#64748b' } },
                  (() => {
                    const diff = Date.now() - new Date(panelLead.last_activity_at).getTime();
                    const d = Math.floor(diff / 86400000);
                    return (d === 0 ? 'Today' : d + 'd ago');
                  })()
                ),
                panelLead.last_action_type && /*#__PURE__*/React.createElement("div", {
                  style: { fontSize: '0.72rem', color: '#94a3b8' }
                }, (panelLead.last_action_type || '').replace(/_/g, ' ').toLowerCase())
              )
            : /*#__PURE__*/React.createElement("div", { style: { fontSize: '0.78rem', color: '#94a3b8', fontStyle: 'italic' } }, 'No activity recorded')
        ),

        panelLead.next_followup_at && /*#__PURE__*/React.createElement("div", { style: { marginBottom: '1.25rem' } },
          /*#__PURE__*/React.createElement("div", {
            style: { fontSize: '0.65rem', textTransform: 'uppercase', color: '#94a3b8', fontWeight: 700, letterSpacing: '0.06em', marginBottom: '0.4rem' }
          }, "Follow-Up"),
          /*#__PURE__*/React.createElement("div", { style: { fontSize: '0.82rem', color: '#fbbf24' } },
            new Date(panelLead.next_followup_at).toLocaleDateString()
          )
        ),

        /*#__PURE__*/React.createElement("div", { style: { marginBottom: '1.25rem' } },
          /*#__PURE__*/React.createElement("div", {
            style: { fontSize: '0.65rem', textTransform: 'uppercase', color: '#94a3b8', fontWeight: 700, letterSpacing: '0.06em', marginBottom: '0.4rem' }
          }, "Signals"),
          panelLead.last_signal_title
            ? /*#__PURE__*/React.createElement("div", { style: { fontSize: '0.78rem', color: '#64748b' } }, panelLead.last_signal_title)
            : /*#__PURE__*/React.createElement("div", { style: { fontSize: '0.78rem', color: '#94a3b8', fontStyle: 'italic' } }, 'No signals detected')
        ),

        /*#__PURE__*/React.createElement("div", null,
          /*#__PURE__*/React.createElement("div", {
            style: { fontSize: '0.65rem', textTransform: 'uppercase', color: '#94a3b8', fontWeight: 700, letterSpacing: '0.06em', marginBottom: '0.4rem' }
          }, "Notes"),
          /*#__PURE__*/React.createElement("div", { style: { fontSize: '0.78rem', color: '#94a3b8', fontStyle: 'italic' } }, 'No notes yet')
        )
      )
    )
  )

  );
}

// ======= FOLLOW-UPS DUE PAGE =======
function FollowUpsPage({
  user
}) {
  const [leads, setLeads] = useState([]);
  const [loading, setLoading] = useState(true);
  const [touchpointTarget, setTouchpointTarget] = useState(null);
  const [activityTarget, setActivityTarget] = useState(null);
  useEffect(() => {
    loadDueLeads();
  }, []);
  const loadDueLeads = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/crm/leads?due=1`);
      const data = await res.json();
      if (data.success) setLeads(data.leads);
    } catch (e) {
      console.error('Follow-ups load error:', e);
    }
    setLoading(false);
  };
  const updateLead = async (leadId, field, value) => {
    try {
      await fetch(`${API_BASE}/api/crm/leads/${leadId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          [field]: value
        })
      });
      loadDueLeads();
    } catch (e) {
      console.error('Lead update error:', e);
    }
  };
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement(SectionHeader, {
    title: "Follow-ups Due",
    subtitle: "Leads with follow-up dates at or before today",
    icon: "followups"
  }), /*#__PURE__*/React.createElement(Divider, null), loading && /*#__PURE__*/React.createElement("div", {
    style: styles.loading
  }, /*#__PURE__*/React.createElement("div", {
    style: styles.loadingText
  }, "Loading...")), !loading && leads.length === 0 && /*#__PURE__*/React.createElement(EmptyState, {
    title: "No follow-ups due",
    subtitle: "All caught up! Set follow-up dates on your pipeline leads.",
    icon: /*#__PURE__*/React.createElement("svg", {
      width: "36",
      height: "36",
      viewBox: "0 0 24 24",
      fill: "none",
      stroke: "currentColor",
      strokeWidth: "1.5",
      className: "text-slate-600"
    }, /*#__PURE__*/React.createElement("circle", {
      cx: "12",
      cy: "12",
      r: "10"
    }), /*#__PURE__*/React.createElement("polyline", {
      points: "12,6 12,12 16,14"
    }))
  }), !loading && leads.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: '0.75rem'
    }
  }, leads.map(lead => {
    const dueDate = lead.next_followup_at ? new Date(lead.next_followup_at) : null;
    const isOverdue = dueDate && dueDate < new Date(new Date().toDateString());
    return /*#__PURE__*/React.createElement("div", {
      key: lead.id,
      style: {
        background: '#FFFFFF',
        border: `1px solid ${isOverdue ? 'rgba(239,68,68,0.4)' : '#e2e8f0'}`,
        borderLeft: isOverdue ? '4px solid #ef4444' : '4px solid #fbbf24',
        borderRadius: '12px',
        padding: '1rem',
        display: 'flex',
        alignItems: 'center',
        gap: '1rem',
        flexWrap: 'wrap'
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        flex: 1,
        minWidth: '200px'
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "'Orbitron',sans-serif",
        fontSize: '1rem',
        fontWeight: 700,
        color: '#0f172a',
        marginBottom: '0.2rem'
      }
    }, lead.company_name), /*#__PURE__*/React.createElement("div", {
      style: {
        display: 'flex',
        gap: '0.5rem',
        alignItems: 'center'
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontSize: '0.75rem',
        padding: '0.15rem 0.45rem',
        borderRadius: '4px',
        fontWeight: 600,
        background: (CRM_STATUS_COLORS[lead.status] || CRM_STATUS_COLORS.New).bg,
        color: (CRM_STATUS_COLORS[lead.status] || CRM_STATUS_COLORS.New).color
      }
    }, lead.status), /*#__PURE__*/React.createElement("span", {
      style: {
        fontSize: '0.75rem',
        color: '#64748b'
      }
    }, lead.owner_user_id === user?.id ? 'Owned by: Me' : lead.owner_name ? `Owned by: ${lead.owner_name}` : 'Unassigned'))), /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: '0.85rem',
        color: isOverdue ? '#f87171' : '#fbbf24',
        fontWeight: 600
      }
    }, isOverdue ? 'OVERDUE' : 'DUE TODAY', ": ", dueDate ? dueDate.toLocaleDateString() : '—'), /*#__PURE__*/React.createElement("input", {
      type: "date",
      style: {
        ...styles.input,
        minWidth: '130px',
        fontSize: '0.8rem',
        padding: '0.3rem 0.5rem'
      },
      value: lead.next_followup_at ? lead.next_followup_at.split('T')[0] : '',
      onChange: e => updateLead(lead.id, 'next_followup_at', e.target.value ? new Date(e.target.value).toISOString() : null)
    }), /*#__PURE__*/React.createElement("button", {
      className: "action-btn",
      style: styles.actionBtn,
      onClick: () => setTouchpointTarget({
        lead_id: lead.id,
        company_name: lead.company_name
      })
    }, "Log Touchpoint"), /*#__PURE__*/React.createElement("button", {
      className: "action-btn",
      style: {
        ...styles.actionBtn,
        fontSize: '0.75rem'
      },
      onClick: () => setActivityTarget({
        lead_id: lead.id,
        company_name: lead.company_name
      })
    }, "View Activity"));
  })), touchpointTarget && /*#__PURE__*/React.createElement(TouchpointModal, {
    target: touchpointTarget,
    onClose: () => setTouchpointTarget(null),
    onSaved: loadDueLeads
  }), activityTarget && /*#__PURE__*/React.createElement(ActivityModal, {
    leadId: activityTarget.lead_id,
    companyName: activityTarget.company_name,
    onClose: () => setActivityTarget(null),
    user: user
  }));
}

// Discovery styles
const ds = {
  tabBar: {
    display: 'flex',
    gap: '0.25rem',
    marginBottom: '2rem',
    borderBottom: '2px solid #e2e8f0',
    paddingBottom: '0'
  },
  tab: {
    background: 'transparent',
    border: 'none',
    color: '#64748b',
    padding: '0.75rem 1.5rem',
    fontSize: '0.95rem',
    fontWeight: 600,
    cursor: 'pointer',
    borderBottom: '2px solid transparent',
    marginBottom: '-2px',
    fontFamily: "'Orbitron', sans-serif",
    transition: 'color 0.2s, border-color 0.2s'
  },
  tabActive: {
    color: '#14b8a6',
    borderBottomColor: '#34d399'
  },
  loadingMsg: {
    textAlign: 'center',
    padding: '3rem',
    color: '#64748b'
  },
  configPanel: {
    background: '#FFFFFF',
    border: '1px solid rgba(226,232,240,0.5)',
    borderRadius: '1rem',
    padding: '1.5rem',
    marginBottom: '2rem'
  },
  configHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '1rem',
    flexWrap: 'wrap',
    gap: '0.5rem'
  },
  sectionTitle: {
    fontFamily: "'Orbitron', sans-serif",
    fontSize: '1.3rem',
    fontWeight: 700,
    color: '#14b8a6'
  },
  schedule: {
    color: '#64748b',
    fontSize: '0.9rem'
  },
  configGrid: {
    display: 'grid',
    gap: '1rem'
  },
  configLabel: {
    fontSize: '0.75rem',
    color: '#64748b',
    textTransform: 'uppercase',
    fontWeight: 600,
    marginBottom: '0.5rem',
    letterSpacing: '0.05em'
  },
  chipGroup: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '0.5rem'
  },
  chip: {
    background: 'rgba(16,185,129,0.1)',
    border: '1px solid rgba(16,185,129,0.3)',
    borderRadius: '20px',
    padding: '0.3rem 0.8rem',
    fontSize: '0.85rem',
    color: '#14b8a6'
  },
  keywordChip: {
    background: 'rgba(6,182,212,0.1)',
    border: '1px solid rgba(6,182,212,0.2)',
    borderRadius: '20px',
    padding: '0.3rem 0.8rem',
    fontSize: '0.8rem',
    color: '#3b82f6'
  },
  sourceChip: {
    background: 'rgba(251,191,36,0.1)',
    border: '1px solid rgba(251,191,36,0.3)',
    borderRadius: '20px',
    padding: '0.3rem 0.8rem',
    fontSize: '0.8rem',
    color: '#fbbf24'
  },
  operatorChip: {
    background: 'rgba(239,68,68,0.1)',
    border: '1px solid rgba(239,68,68,0.3)',
    borderRadius: '20px',
    padding: '0.3rem 0.8rem',
    fontSize: '0.8rem',
    color: '#f87171'
  },
  filterRow: {
    display: 'flex',
    gap: '1.5rem',
    flexWrap: 'wrap'
  },
  filterItem: {
    color: '#0f172a',
    fontSize: '0.9rem'
  },
  actionBar: {
    display: 'flex',
    gap: '1rem',
    alignItems: 'center',
    marginBottom: '2rem',
    flexWrap: 'wrap'
  },
  lastRun: {
    color: '#64748b',
    fontSize: '0.85rem'
  },
  digestBox: {
    background: '#F1F5F9',
    border: '1px solid #e2e8f0',
    borderRadius: '1rem',
    padding: '1.5rem',
    marginBottom: '2rem',
    overflow: 'auto',
    maxHeight: '600px'
  },
  digestText: {
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: '0.85rem',
    color: '#0f172a',
    whiteSpace: 'pre-wrap',
    lineHeight: '1.5',
    margin: 0
  },
  citySection: {
    marginBottom: '2rem'
  },
  cityHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    marginBottom: '1rem',
    paddingBottom: '0.5rem',
    borderBottom: '1px solid #e2e8f0'
  },
  cityTitle: {
    fontFamily: "'Orbitron', sans-serif",
    fontSize: '1.1rem',
    fontWeight: 700,
    color: '#3b82f6'
  },
  newBadge: {
    background: 'rgba(20,184,166,0.1)',
    border: '1px solid #14b8a6',
    borderRadius: '12px',
    padding: '0.15rem 0.6rem',
    fontSize: '0.75rem',
    color: '#14b8a6',
    fontWeight: 600
  },
  errorText: {
    color: '#ef4444',
    fontSize: '0.9rem'
  },
  noResults: {
    color: '#64748b',
    fontSize: '0.9rem',
    fontStyle: 'italic'
  },
  signalGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))',
    gap: '1rem'
  },
  signalCard: {
    background: '#FFFFFF',
    border: '1px solid rgba(226,232,240,0.5)',
    borderRadius: '1rem',
    padding: '1.25rem',
    transition: 'all 0.2s'
  },
  signalCardHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    marginBottom: '0.75rem',
    flexWrap: 'wrap'
  },
  signalTypeBadge: {
    border: '1px solid',
    borderRadius: '20px',
    padding: '0.2rem 0.7rem',
    fontSize: '0.75rem',
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '0.03em'
  },
  entityName: {
    fontFamily: "'Orbitron', sans-serif",
    fontSize: '0.95rem',
    fontWeight: 600,
    color: '#0f172a'
  },
  signalTitle: {
    fontSize: '0.9rem',
    color: '#0f172a',
    marginBottom: '0.5rem',
    lineHeight: '1.4'
  },
  signalSummary: {
    fontSize: '0.85rem',
    color: '#64748b',
    marginBottom: '0.75rem',
    lineHeight: '1.5'
  },
  signalMeta: {
    display: 'flex',
    gap: '1rem',
    marginBottom: '0.5rem',
    flexWrap: 'wrap'
  },
  signalSource: {
    fontSize: '0.8rem',
    color: '#fbbf24'
  },
  signalDate: {
    fontSize: '0.8rem',
    color: '#64748b'
  },
  signalLink: {
    color: '#3b82f6',
    textDecoration: 'none',
    fontSize: '0.85rem',
    display: 'inline-block',
    marginTop: '0.25rem'
  },
  historySection: {
    marginTop: '2rem',
    background: '#FFFFFF',
    border: '1px solid #e2e8f0',
    borderRadius: '1rem',
    padding: '1.5rem'
  },
  historyList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem',
    marginTop: '1rem'
  },
  historyItem: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '0.75rem 1rem',
    borderRadius: '8px',
    cursor: 'pointer',
    background: '#F1F5F9',
    border: '1px solid transparent',
    transition: 'all 0.2s'
  },
  historyItemActive: {
    border: '1px solid #14b8a6',
    background: 'rgba(20,184,166,0.04)'
  },
  historyDate: {
    fontSize: '0.85rem',
    color: '#0f172a'
  },
  historyStats: {
    fontSize: '0.85rem',
    color: '#64748b'
  },
  historyStatus: {
    fontSize: '0.8rem',
    fontWeight: 600,
    textTransform: 'uppercase'
  },
  sourceRefreshBar: {
    background: '#FFFFFF',
    border: '1px solid #e2e8f0',
    borderRadius: '1rem',
    padding: '1rem 1.25rem',
    marginBottom: '1.5rem'
  },
  filterBar: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    marginBottom: '1.5rem',
    flexWrap: 'wrap'
  },
  filterToggle: {
    background: 'transparent',
    border: '1px solid #e2e8f0',
    borderRadius: '20px',
    padding: '0.3rem 0.8rem',
    fontSize: '0.8rem',
    cursor: 'pointer',
    fontFamily: "'Inter', sans-serif",
    transition: 'all 0.2s'
  },
  sourceTypeBadge: {
    border: '1px solid',
    borderRadius: '20px',
    padding: '0.15rem 0.55rem',
    fontSize: '0.7rem',
    fontWeight: 600
  },
  confidenceBadge: {
    fontSize: '0.65rem',
    fontWeight: 700,
    letterSpacing: '0.05em',
    padding: '0.15rem 0.4rem',
    borderRadius: '4px',
    background: 'rgba(255,255,255,0.05)'
  },
  adapterStatsBar: {
    display: 'flex',
    gap: '0.75rem',
    flexWrap: 'wrap',
    marginBottom: '1.5rem'
  }
};

// Main styles
const styles = {
  container: {
    maxWidth: '1400px',
    margin: '0 auto',
    padding: '2rem',
    minHeight: '100vh'
  },
  header: {
    marginBottom: '2.5rem',
    textAlign: 'center'
  },
  title: {
    fontFamily: "'Orbitron', sans-serif",
    fontSize: '2.5rem',
    fontWeight: 900,
    background: 'linear-gradient(135deg, #14b8a6 0%, #3b82f6 100%)',
    WebkitBackgroundClip: 'text',
    WebkitTextFillColor: 'transparent',
    marginBottom: '0.5rem',
    letterSpacing: '0.05em'
  },
  subtitle: {
    fontSize: '1rem',
    color: '#64748b',
    fontWeight: 400
  },
  statsBar: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: '1rem',
    marginBottom: '2rem'
  },
  statCard: {
    background: '#FFFFFF',
    border: '1px solid rgba(226,232,240,0.5)',
    borderRadius: '1rem',
    padding: '1.25rem'
  },
  statLabel: {
    fontSize: '0.75rem',
    color: '#64748b',
    textTransform: 'uppercase',
    marginBottom: '0.4rem',
    fontWeight: 600,
    letterSpacing: '0.05em'
  },
  statValue: {
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: '1.8rem',
    fontWeight: 700,
    color: '#14b8a6',
    lineHeight: '1.2',
    display: 'block',
    minHeight: '2.2rem'
  },
  pulse: {
    animation: 'pulse 2s ease-in-out infinite'
  },
  controls: {
    position: 'sticky',
    top: 0,
    zIndex: 20,
    background: 'rgba(255,255,255,0.85)',
    backdropFilter: 'blur(12px)',
    WebkitBackdropFilter: 'blur(12px)',
    borderBottom: '1px solid #e2e8f0',
    padding: '0.75rem 1rem',
    marginBottom: '2rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.65rem'
  },
  btn: {
    background: 'transparent',
    border: '1px solid #e2e8f0',
    color: '#64748b',
    padding: '0.6rem 1.2rem',
    borderRadius: '0.5rem',
    fontSize: '0.85rem',
    cursor: 'pointer',
    fontFamily: "'Inter', sans-serif",
    transition: 'all 0.2s'
  },
  btnPrimary: {
    background: '#14b8a6',
    border: 'none',
    color: '#0f172a',
    padding: '0.6rem 1.5rem',
    borderRadius: '0.5rem',
    fontSize: '0.9rem',
    fontWeight: 600,
    cursor: 'pointer',
    fontFamily: "'Inter', sans-serif",
    transition: 'all 0.2s'
  },
  input: {
    background: '#FFFFFF',
    border: '1px solid #e2e8f0',
    color: '#0f172a',
    padding: '0.6rem 1rem',
    borderRadius: '0.5rem',
    fontSize: '0.85rem',
    minWidth: '220px',
    fontFamily: "'Inter', sans-serif",
    outline: 'none'
  },
  select: {
    background: '#FFFFFF',
    border: '1px solid #e2e8f0',
    color: '#0f172a',
    padding: '0.6rem 0.75rem',
    borderRadius: '0.5rem',
    fontSize: '0.85rem',
    cursor: 'pointer',
    fontFamily: "'Inter', sans-serif",
    outline: 'none'
  },
  searchStatus: {
    background: 'rgba(20,184,166,0.06)',
    border: '1px solid rgba(16,185,129,0.3)',
    borderRadius: '0.5rem',
    padding: '0.85rem',
    marginBottom: '1.5rem',
    textAlign: 'center',
    fontWeight: 500,
    color: '#14b8a6',
    fontSize: '0.9rem'
  },
  loading: {
    textAlign: 'center',
    padding: '2rem'
  },
  loadingText: {
    fontFamily: "'Orbitron', sans-serif",
    fontSize: '1rem',
    color: '#14b8a6',
    animation: 'pulse 1.5s ease-in-out infinite'
  },
  empty: {
    textAlign: 'center',
    padding: '4rem 2rem'
  },
  emptyTitle: {
    fontSize: '1.6rem',
    marginBottom: '0.75rem',
    color: '#64748b',
    fontFamily: "'Orbitron', sans-serif"
  },
  emptyText: {
    fontSize: '1rem',
    color: '#64748b',
    marginBottom: '0.5rem'
  },
  emptySubtext: {
    fontSize: '0.85rem',
    color: '#94a3b8'
  },
  grid: {
    display: 'grid',
    gap: '1.25rem'
  },
  card: {
    background: '#FFFFFF',
    border: '1px solid rgba(226,232,240,0.5)',
    borderRadius: '1rem',
    padding: '1rem',
    boxShadow: '0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04)',
    display: 'grid',
    gap: '0.75rem'
  },
  cardHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    gap: '1rem'
  },
  companyName: {
    fontFamily: "'Orbitron', sans-serif",
    fontSize: '1.15rem',
    fontWeight: 700,
    color: '#0f172a',
    marginBottom: '0.2rem'
  },
  location: {
    color: '#64748b',
    fontSize: '0.85rem'
  },
  executive: {
    paddingBottom: '0.5rem',
    borderBottom: '1px solid #e2e8f0',
    fontSize: '0.9rem',
    color: '#64748b'
  },
  linkedinLink: {
    marginLeft: '0.75rem',
    color: '#3b82f6',
    textDecoration: 'none',
    fontSize: '0.85rem',
    fontWeight: 500
  },
  details: {
    display: 'grid',
    gridTemplateColumns: 'repeat(2, 1fr)',
    gap: '0.4rem',
    fontSize: '0.85rem',
    color: '#334155'
  },
  whyNow: {
    background: 'rgba(239,68,68,0.06)',
    border: '1px solid rgba(239,68,68,0.2)',
    borderRadius: '8px',
    padding: '0.85rem'
  },
  signals: {
    background: 'rgba(6,182,212,0.04)',
    border: '1px solid rgba(6,182,212,0.15)',
    borderRadius: '8px',
    padding: '0.85rem'
  },
  signalList: {
    listStyle: 'none',
    marginTop: '0.35rem'
  },
  signalItem: {
    marginBottom: '0.35rem',
    fontSize: '0.85rem',
    color: '#64748b'
  },
  cardActions: {
    display: 'flex',
    gap: '0.5rem',
    flexWrap: 'wrap',
    paddingTop: '0.5rem',
    borderTop: '1px solid #e2e8f0'
  },
  actionBtn: {
    fontSize: '0.75rem',
    padding: '0.35rem 0.75rem',
    borderRadius: '6px',
    border: '1px solid #cbd5e1',
    background: 'transparent',
    color: '#334155',
    cursor: 'pointer',
    fontFamily: "'Inter', sans-serif",
    fontWeight: 500
  },
  emailOptions: {
    background: 'rgba(20,184,166,0.04)',
    border: '1px solid rgba(20,184,166,0.1)',
    borderRadius: '8px',
    padding: '1rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.65rem'
  },
  emailOptionRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem'
  },
  emailOptionLabel: {
    fontWeight: 600,
    fontSize: '0.75rem',
    color: '#64748b',
    minWidth: '80px',
    textTransform: 'uppercase',
    letterSpacing: '0.03em'
  },
  modalOverlay: {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    background: 'rgba(0,0,0,0.3)',
    backdropFilter: 'blur(4px)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1000
  },
  modal: {
    background: '#FFFFFF',
    border: '1px solid #e2e8f0',
    borderRadius: '1rem',
    padding: '2rem',
    maxWidth: '600px',
    width: '90%',
    maxHeight: '80vh',
    overflow: 'auto'
  },
  modalHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '1rem'
  },
  closeBtn: {
    background: 'none',
    border: 'none',
    color: '#64748b',
    fontSize: '1.3rem',
    cursor: 'pointer'
  },
  subjectRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    background: 'rgba(6,182,212,0.08)',
    border: '1px solid rgba(6,182,212,0.2)',
    borderRadius: '8px',
    padding: '0.75rem 1rem',
    marginBottom: '1rem'
  },
  subjectLabel: {
    fontWeight: 700,
    fontSize: '0.75rem',
    color: '#3b82f6',
    textTransform: 'uppercase',
    flexShrink: 0
  },
  subjectText: {
    fontSize: '0.95rem',
    fontWeight: 600,
    flex: 1,
    color: '#0f172a'
  },
  copySmall: {
    background: 'none',
    border: 'none',
    cursor: 'pointer',
    fontSize: '1rem',
    padding: '0.25rem',
    flexShrink: 0,
    color: '#64748b'
  },
  emailBody: {
    background: '#F1F5F9',
    padding: '1.5rem',
    borderRadius: '8px',
    fontSize: '0.9rem',
    lineHeight: '1.7',
    marginBottom: '1rem',
    fontFamily: "'Inter', -apple-system, sans-serif",
    color: '#334155'
  },
  modalActions: {
    display: 'flex',
    gap: '1rem'
  }
};

// ===================================================================
// DEVELOPER NETWORK PANEL
// ===================================================================
function DeveloperNetworkPanel() {
  const e = React.createElement;
  const [edges, setEdges] = useState([]);
  const [stats, setStats] = useState(null);
  const [searchEntity, setSearchEntity] = useState('');
  const [connections, setConnections] = useState([]);
  const [loading, setLoading] = useState(true);
  const REL_COLORS = {
    DEVELOPER_CONTRACTOR: '#f97316',
    DEVELOPER_ENGINEER: '#3b82f6',
    DEVELOPER_ARCHITECT: '#a855f7',
    DEVELOPER_LENDER: '#eab308',
    CONTRACTOR_SUPPLIER: '#22c55e',
    DEVELOPER_SUPPLIER: '#06b6d4',
    CONTRACTOR_ENGINEER: '#ec4899'
  };
  const REL_LABELS = {
    DEVELOPER_CONTRACTOR: 'Dev-Contractor',
    DEVELOPER_ENGINEER: 'Dev-Engineer',
    DEVELOPER_ARCHITECT: 'Dev-Architect',
    DEVELOPER_LENDER: 'Dev-Lender',
    CONTRACTOR_SUPPLIER: 'Contractor-Supplier',
    DEVELOPER_SUPPLIER: 'Dev-Supplier',
    CONTRACTOR_ENGINEER: 'Contractor-Engineer'
  };
  function strColor(s) {
    return s >= 80 ? '#22c55e' : s >= 50 ? '#eab308' : s >= 25 ? '#f97316' : '#64748b';
  }
  function strLabel(s) {
    return s >= 80 ? 'STRONG' : s >= 50 ? 'MODERATE' : s >= 25 ? 'EMERGING' : 'WEAK';
  }
  const fetchData = useCallback(async () => {
    try {
      const [cRes, sRes] = await Promise.all([fetch('/api/developer-network/clusters?limit=30'), fetch('/api/developer-network/stats')]);
      if (cRes.ok) {
        const d = await cRes.json();
        setEdges(d.clusters || []);
      }
      if (sRes.ok) {
        const d = await sRes.json();
        setStats(d);
      }
    } catch (err) {
      console.error('[DevNetwork]', err);
    } finally {
      setLoading(false);
    }
  }, []);
  const searchNet = useCallback(async () => {
    if (!searchEntity.trim()) return;
    try {
      const res = await fetch('/api/developer-network/' + encodeURIComponent(searchEntity));
      if (res.ok) {
        const d = await res.json();
        setConnections(d.connections || []);
      }
    } catch {
      setConnections([]);
    }
  }, [searchEntity]);
  useEffect(() => {
    fetchData();
    const iv = setInterval(fetchData, 60000);
    return () => clearInterval(iv);
  }, [fetchData]);
  if (loading) return e('div', {
    style: {
      textAlign: 'center',
      padding: '3rem',
      color: '#06b6d4',
      fontFamily: "'Orbitron', sans-serif"
    }
  }, 'LOADING DEVELOPER NETWORKS...');
  return e('div', {
    style: {
      maxWidth: '1000px',
      margin: '0 auto'
    }
  }, e('div', {
    style: {
      marginBottom: '1.5rem'
    }
  }, e('h2', {
    style: {
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '1.3rem',
      fontWeight: 900,
      background: 'linear-gradient(135deg, #06b6d4 0%, #a855f7 100%)',
      WebkitBackgroundClip: 'text',
      WebkitTextFillColor: 'transparent',
      margin: 0
    }
  }, 'DEVELOPER NETWORK INTELLIGENCE'), e('p', {
    style: {
      color: '#64748b',
      fontSize: '0.8rem',
      margin: '0.25rem 0 0'
    }
  }, 'Relationship graph: developers, contractors, engineers, architects, lenders, suppliers')), stats && e('div', {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(3, 1fr)',
      gap: '12px',
      marginBottom: '1.5rem'
    }
  }, [{
    l: 'NETWORK EDGES',
    v: stats.total_edges,
    c: '#06b6d4'
  }, {
    l: 'STRONG LINKS',
    v: stats.strong_edges,
    c: '#22c55e'
  }, {
    l: 'REL TYPES',
    v: (stats.by_type || []).length,
    c: '#a855f7'
  }].map(s => e('div', {
    key: s.l,
    style: {
      background: 'rgba(15,22,36,0.95)',
      border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: '8px',
      padding: '14px',
      textAlign: 'center'
    }
  }, e('div', {
    style: {
      fontSize: '1.4rem',
      fontWeight: 900,
      color: s.c,
      fontFamily: "'Orbitron', sans-serif"
    }
  }, s.v), e('div', {
    style: {
      fontSize: '0.6rem',
      color: '#64748b',
      fontFamily: "'Orbitron', sans-serif",
      letterSpacing: '0.05em',
      marginTop: '4px'
    }
  }, s.l)))), e('div', {
    style: {
      display: 'flex',
      gap: '8px',
      marginBottom: '1rem'
    }
  }, e('input', {
    type: 'text',
    value: searchEntity,
    onChange: ev => setSearchEntity(ev.target.value),
    onKeyDown: ev => ev.key === 'Enter' && searchNet(),
    placeholder: 'Search entity network...',
    style: {
      flex: 1,
      background: 'rgba(15,22,36,0.95)',
      border: '1px solid rgba(100,116,139,0.3)',
      borderRadius: '6px',
      padding: '8px 12px',
      color: '#1e293b',
      fontSize: '0.85rem'
    }
  }), e('button', {
    onClick: searchNet,
    style: {
      background: 'rgba(6,182,212,0.2)',
      border: '1px solid rgba(6,182,212,0.4)',
      borderRadius: '6px',
      padding: '8px 16px',
      color: '#06b6d4',
      cursor: 'pointer',
      fontSize: '0.8rem',
      fontWeight: 700
    }
  }, 'SEARCH')), connections.length > 0 && e('div', {
    style: {
      marginBottom: '1rem'
    }
  }, e('h3', {
    style: {
      color: '#06b6d4',
      fontSize: '0.85rem',
      fontWeight: 700,
      marginBottom: '8px',
      fontFamily: "'Orbitron', sans-serif"
    }
  }, 'CONNECTIONS: ' + searchEntity), connections.map((c, i) => e('div', {
    key: i,
    style: {
      background: 'rgba(15,22,36,0.95)',
      border: '1px solid ' + (REL_COLORS[c.relationship_type] || '#64748b') + '40',
      borderLeft: '3px solid ' + (REL_COLORS[c.relationship_type] || '#64748b'),
      borderRadius: '6px',
      padding: '10px 14px',
      marginBottom: '6px',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center'
    }
  }, e('div', null, e('div', {
    style: {
      color: '#1e293b',
      fontSize: '0.85rem',
      fontWeight: 600
    }
  }, c.partner), e('div', {
    style: {
      color: '#64748b',
      fontSize: '0.7rem'
    }
  }, (REL_LABELS[c.relationship_type] || c.relationship_type) + ' · ' + c.co_occurrence_count + ' co-occurrences')), e('div', {
    style: {
      background: strColor(c.relationship_strength) + '20',
      border: '1px solid ' + strColor(c.relationship_strength) + '40',
      borderRadius: '4px',
      padding: '2px 8px',
      fontSize: '0.65rem',
      fontWeight: 700,
      color: strColor(c.relationship_strength),
      fontFamily: "'Orbitron', sans-serif"
    }
  }, strLabel(c.relationship_strength) + ' (' + c.relationship_strength + ')')))), e('h3', {
    style: {
      color: '#a855f7',
      fontSize: '0.85rem',
      fontWeight: 700,
      marginBottom: '8px',
      fontFamily: "'Orbitron', sans-serif"
    }
  }, 'TOP NETWORK CLUSTERS'), edges.map((edge, i) => e('div', {
    key: i,
    style: {
      background: 'rgba(15,22,36,0.95)',
      border: '1px solid ' + (REL_COLORS[edge.relationship_type] || '#64748b') + '40',
      borderLeft: '3px solid ' + (REL_COLORS[edge.relationship_type] || '#64748b'),
      borderRadius: '8px',
      padding: '12px 16px',
      marginBottom: '8px',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center'
    }
  }, e('div', null, e('div', {
    style: {
      display: 'flex',
      gap: '8px',
      alignItems: 'center',
      marginBottom: '4px'
    }
  }, e('span', {
    style: {
      color: '#1e293b',
      fontSize: '0.85rem',
      fontWeight: 600
    }
  }, edge.entity_a), e('span', {
    style: {
      color: '#64748b',
      fontSize: '0.75rem'
    }
  }, '\u2194'), e('span', {
    style: {
      color: '#1e293b',
      fontSize: '0.85rem',
      fontWeight: 600
    }
  }, edge.entity_b)), e('div', {
    style: {
      display: 'flex',
      gap: '12px'
    }
  }, e('span', {
    style: {
      background: (REL_COLORS[edge.relationship_type] || '#64748b') + '20',
      border: '1px solid ' + (REL_COLORS[edge.relationship_type] || '#64748b') + '40',
      borderRadius: '4px',
      padding: '1px 6px',
      fontSize: '0.6rem',
      fontWeight: 700,
      color: REL_COLORS[edge.relationship_type] || '#64748b',
      fontFamily: "'Orbitron', sans-serif"
    }
  }, REL_LABELS[edge.relationship_type] || edge.relationship_type), e('span', {
    style: {
      color: '#64748b',
      fontSize: '0.7rem'
    }
  }, edge.co_occurrence_count + ' co-occurrences'))), e('div', {
    style: {
      textAlign: 'right'
    }
  }, e('div', {
    style: {
      color: strColor(edge.relationship_strength),
      fontSize: '1.1rem',
      fontWeight: 900,
      fontFamily: "'Orbitron', sans-serif"
    }
  }, edge.relationship_strength), e('div', {
    style: {
      color: strColor(edge.relationship_strength),
      fontSize: '0.6rem',
      fontWeight: 700,
      fontFamily: "'Orbitron', sans-serif"
    }
  }, strLabel(edge.relationship_strength))))));
}

// ===================================================================
// DEVELOPMENT CORRIDORS PANEL
// ===================================================================
function DevelopmentCorridorsPanel() {
  const e = React.createElement;
  const [corridors, setCorridors] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const fetchData = useCallback(async () => {
    try {
      const [cRes, sRes] = await Promise.all([fetch('/api/corridors?limit=30'), fetch('/api/corridors/stats')]);
      if (cRes.ok) {
        const d = await cRes.json();
        setCorridors(d.corridors || []);
      }
      if (sRes.ok) {
        const d = await sRes.json();
        setStats(d);
      }
    } catch (err) {
      console.error('[Corridors]', err);
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    fetchData();
    const iv = setInterval(fetchData, 60000);
    return () => clearInterval(iv);
  }, [fetchData]);
  function growthColor(g) {
    return g > 50 ? '#22c55e' : g > 0 ? '#eab308' : g === 0 ? '#64748b' : '#ef4444';
  }
  if (loading) return e('div', {
    style: {
      textAlign: 'center',
      padding: '3rem',
      color: '#06b6d4',
      fontFamily: "'Orbitron', sans-serif"
    }
  }, 'SCANNING DEVELOPMENT CORRIDORS...');
  return e('div', {
    style: {
      maxWidth: '1000px',
      margin: '0 auto'
    }
  }, e('div', {
    style: {
      marginBottom: '1.5rem'
    }
  }, e('h2', {
    style: {
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '1.3rem',
      fontWeight: 900,
      background: 'linear-gradient(135deg, #22c55e 0%, #06b6d4 100%)',
      WebkitBackgroundClip: 'text',
      WebkitTextFillColor: 'transparent',
      margin: 0
    }
  }, 'DEVELOPMENT CORRIDOR INTELLIGENCE'), e('p', {
    style: {
      color: '#64748b',
      fontSize: '0.8rem',
      margin: '0.25rem 0 0'
    }
  }, 'Geographic regions where development activity is clustering')), stats && e('div', {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(3, 1fr)',
      gap: '12px',
      marginBottom: '1.5rem'
    }
  }, [{
    l: 'CORRIDORS',
    v: stats.total_corridors,
    c: '#06b6d4'
  }, {
    l: 'GROWING',
    v: stats.growing_corridors,
    c: '#22c55e'
  }, {
    l: 'STATES',
    v: (stats.by_state || []).length,
    c: '#a855f7'
  }].map(s => e('div', {
    key: s.l,
    style: {
      background: 'rgba(15,22,36,0.95)',
      border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: '8px',
      padding: '14px',
      textAlign: 'center'
    }
  }, e('div', {
    style: {
      fontSize: '1.4rem',
      fontWeight: 900,
      color: s.c,
      fontFamily: "'Orbitron', sans-serif"
    }
  }, s.v), e('div', {
    style: {
      fontSize: '0.6rem',
      color: '#64748b',
      fontFamily: "'Orbitron', sans-serif",
      letterSpacing: '0.05em',
      marginTop: '4px'
    }
  }, s.l)))), corridors.length === 0 && e('div', {
    style: {
      textAlign: 'center',
      padding: '2rem',
      color: '#64748b'
    }
  }, 'No development corridors detected yet. Corridors are detected when signal clustering exceeds threshold.'), corridors.map((c, i) => e('div', {
    key: i,
    style: {
      background: 'rgba(15,22,36,0.95)',
      border: '1px solid rgba(6,182,212,0.3)',
      borderLeft: '3px solid #06b6d4',
      borderRadius: '8px',
      padding: '14px 18px',
      marginBottom: '10px'
    }
  }, e('div', {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'flex-start',
      marginBottom: '8px'
    }
  }, e('div', null, e('div', {
    style: {
      color: '#1e293b',
      fontSize: '0.95rem',
      fontWeight: 700
    }
  }, c.corridor_name), e('div', {
    style: {
      color: '#64748b',
      fontSize: '0.75rem'
    }
  }, (c.city || '') + ', ' + (c.state || ''))), e('div', {
    style: {
      textAlign: 'right'
    }
  }, e('div', {
    style: {
      color: growthColor(c.growth_rate),
      fontSize: '1rem',
      fontWeight: 900,
      fontFamily: "'Orbitron', sans-serif"
    }
  }, (c.growth_rate > 0 ? '+' : '') + c.growth_rate + '%'), e('div', {
    style: {
      color: '#64748b',
      fontSize: '0.6rem',
      fontFamily: "'Orbitron', sans-serif"
    }
  }, 'GROWTH RATE'))), e('div', {
    style: {
      display: 'flex',
      gap: '16px'
    }
  }, e('span', {
    style: {
      color: '#06b6d4',
      fontSize: '0.75rem',
      fontWeight: 600
    }
  }, c.signal_density + ' signals'), e('span', {
    style: {
      background: 'rgba(6,182,212,0.15)',
      border: '1px solid rgba(6,182,212,0.3)',
      borderRadius: '4px',
      padding: '1px 6px',
      fontSize: '0.6rem',
      fontWeight: 700,
      color: '#06b6d4',
      fontFamily: "'Orbitron', sans-serif"
    }
  }, c.dominant_development_type || 'MIXED')))));
}

// ===================================================================
// MOMENTUM ENGINE PANEL
// ===================================================================
function MomentumEnginePanel() {
  const e = React.createElement;
  const [parcels, setParcels] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const fetchData = useCallback(async () => {
    try {
      const [pRes, sRes] = await Promise.all([fetch('/api/momentum?min_momentum=20&limit=30'), fetch('/api/momentum/stats')]);
      if (pRes.ok) {
        const d = await pRes.json();
        setParcels(d.parcels || []);
      }
      if (sRes.ok) {
        const d = await sRes.json();
        setStats(d);
      }
    } catch (err) {
      console.error('[Momentum]', err);
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    fetchData();
    const iv = setInterval(fetchData, 60000);
    return () => clearInterval(iv);
  }, [fetchData]);
  function momColor(m) {
    return m >= 80 ? '#22c55e' : m >= 60 ? '#eab308' : m >= 40 ? '#f97316' : '#64748b';
  }
  function momLabel(m) {
    return m >= 80 ? 'ACCELERATING' : m >= 60 ? 'HIGH' : m >= 40 ? 'BUILDING' : 'LOW';
  }
  if (loading) return e('div', {
    style: {
      textAlign: 'center',
      padding: '3rem',
      color: '#f59e0b',
      fontFamily: "'Orbitron', sans-serif"
    }
  }, 'ANALYZING DEVELOPMENT MOMENTUM...');
  return e('div', {
    style: {
      maxWidth: '1000px',
      margin: '0 auto'
    }
  }, e('div', {
    style: {
      marginBottom: '1.5rem'
    }
  }, e('h2', {
    style: {
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '1.3rem',
      fontWeight: 900,
      background: 'linear-gradient(135deg, #f59e0b 0%, #ef4444 100%)',
      WebkitBackgroundClip: 'text',
      WebkitTextFillColor: 'transparent',
      margin: 0
    }
  }, 'OPPORTUNITY MOMENTUM ENGINE'), e('p', {
    style: {
      color: '#64748b',
      fontSize: '0.8rem',
      margin: '0.25rem 0 0'
    }
  }, 'Signal accumulation velocity — parcels with accelerating development activity')), stats && e('div', {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(3, 1fr)',
      gap: '12px',
      marginBottom: '1.5rem'
    }
  }, [{
    l: 'TRACKED PARCELS',
    v: stats.parcels_with_momentum,
    c: '#f59e0b'
  }, {
    l: 'HIGH MOMENTUM',
    v: stats.high_momentum_count,
    c: '#ef4444'
  }, {
    l: 'AVG MOMENTUM',
    v: stats.avg_momentum_score,
    c: '#eab308'
  }].map(s => e('div', {
    key: s.l,
    style: {
      background: 'rgba(15,22,36,0.95)',
      border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: '8px',
      padding: '14px',
      textAlign: 'center'
    }
  }, e('div', {
    style: {
      fontSize: '1.4rem',
      fontWeight: 900,
      color: s.c,
      fontFamily: "'Orbitron', sans-serif"
    }
  }, s.v), e('div', {
    style: {
      fontSize: '0.6rem',
      color: '#64748b',
      fontFamily: "'Orbitron', sans-serif",
      letterSpacing: '0.05em',
      marginTop: '4px'
    }
  }, s.l)))), parcels.length === 0 && e('div', {
    style: {
      textAlign: 'center',
      padding: '2rem',
      color: '#64748b'
    }
  }, 'No parcels with significant momentum detected yet.'), parcels.map((p, i) => e('div', {
    key: i,
    style: {
      background: 'rgba(15,22,36,0.95)',
      border: '1px solid ' + momColor(p.development_momentum_score) + '40',
      borderLeft: '3px solid ' + momColor(p.development_momentum_score),
      borderRadius: '8px',
      padding: '12px 16px',
      marginBottom: '8px',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center'
    }
  }, e('div', null, e('div', {
    style: {
      color: '#1e293b',
      fontSize: '0.85rem',
      fontWeight: 600
    }
  }, p.address || p.parcel_id || 'Parcel'), e('div', {
    style: {
      color: '#64748b',
      fontSize: '0.7rem'
    }
  }, (p.city || '') + (p.state ? ', ' + p.state : '') + ' · ' + (p.signal_sequence_length || 0) + ' signals'), p.development_probability > 0 && e('div', {
    style: {
      color: '#06b6d4',
      fontSize: '0.7rem'
    }
  }, 'Dev probability: ' + p.development_probability + '%')), e('div', {
    style: {
      textAlign: 'right'
    }
  }, e('div', {
    style: {
      color: momColor(p.development_momentum_score),
      fontSize: '1.3rem',
      fontWeight: 900,
      fontFamily: "'Orbitron', sans-serif"
    }
  }, p.development_momentum_score), e('div', {
    style: {
      color: momColor(p.development_momentum_score),
      fontSize: '0.55rem',
      fontWeight: 700,
      fontFamily: "'Orbitron', sans-serif"
    }
  }, momLabel(p.development_momentum_score))))));
}

// ===================================================================
// SIGNAL DISCOVERY PANEL (Admin only)
// ===================================================================
function SignalDiscoveryPanel() {
  const e = React.createElement;
  const [sources, setSources] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const fetchData = useCallback(async () => {
    try {
      const [srcRes, stRes] = await Promise.all([fetch('/api/signal-discovery/sources?limit=30'), fetch('/api/signal-discovery/stats')]);
      if (srcRes.ok) {
        const d = await srcRes.json();
        setSources(d.sources || []);
      }
      if (stRes.ok) {
        const d = await stRes.json();
        setStats(d);
      }
    } catch (err) {
      console.error('[SignalDiscovery]', err);
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    fetchData();
    const iv = setInterval(fetchData, 60000);
    return () => clearInterval(iv);
  }, [fetchData]);
  function statusColor(s) {
    return s === 'active' ? '#22c55e' : s === 'discovered' ? '#06b6d4' : '#64748b';
  }
  if (loading) return e('div', {
    style: {
      textAlign: 'center',
      padding: '3rem',
      color: '#a855f7',
      fontFamily: "'Orbitron', sans-serif"
    }
  }, 'SCANNING DATA SOURCES...');
  return e('div', {
    style: {
      maxWidth: '1000px',
      margin: '0 auto'
    }
  }, e('div', {
    style: {
      marginBottom: '1.5rem'
    }
  }, e('h2', {
    style: {
      fontFamily: "'Orbitron', sans-serif",
      fontSize: '1.3rem',
      fontWeight: 900,
      background: 'linear-gradient(135deg, #a855f7 0%, #ec4899 100%)',
      WebkitBackgroundClip: 'text',
      WebkitTextFillColor: 'transparent',
      margin: 0
    }
  }, 'AUTONOMOUS SIGNAL DISCOVERY AI'), e('p', {
    style: {
      color: '#64748b',
      fontSize: '0.8rem',
      margin: '0.25rem 0 0'
    }
  }, 'Auto-discovered government data sources for development intelligence')), stats && e('div', {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(3, 1fr)',
      gap: '12px',
      marginBottom: '1.5rem'
    }
  }, [{
    l: 'TOTAL SOURCES',
    v: stats.total_sources,
    c: '#a855f7'
  }, {
    l: 'SOURCE TYPES',
    v: (stats.by_type || []).length,
    c: '#ec4899'
  }, {
    l: 'CITIES COVERED',
    v: (stats.by_city || []).length,
    c: '#06b6d4'
  }].map(s => e('div', {
    key: s.l,
    style: {
      background: 'rgba(15,22,36,0.95)',
      border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: '8px',
      padding: '14px',
      textAlign: 'center'
    }
  }, e('div', {
    style: {
      fontSize: '1.4rem',
      fontWeight: 900,
      color: s.c,
      fontFamily: "'Orbitron', sans-serif"
    }
  }, s.v), e('div', {
    style: {
      fontSize: '0.6rem',
      color: '#64748b',
      fontFamily: "'Orbitron', sans-serif",
      letterSpacing: '0.05em',
      marginTop: '4px'
    }
  }, s.l)))), stats && stats.by_status && stats.by_status.length > 0 && e('div', {
    style: {
      display: 'flex',
      gap: '8px',
      marginBottom: '1rem',
      flexWrap: 'wrap'
    }
  }, stats.by_status.map((s, i) => e('span', {
    key: i,
    style: {
      background: statusColor(s.status) + '15',
      border: '1px solid ' + statusColor(s.status) + '40',
      borderRadius: '20px',
      padding: '4px 12px',
      fontSize: '0.7rem',
      color: statusColor(s.status),
      fontWeight: 600
    }
  }, s.status + ': ' + s.count))), sources.length === 0 && e('div', {
    style: {
      textAlign: 'center',
      padding: '2rem',
      color: '#64748b'
    }
  }, 'No data sources discovered yet. The discovery AI will populate this automatically.'), sources.map((s, i) => e('div', {
    key: i,
    style: {
      background: 'rgba(15,22,36,0.95)',
      border: '1px solid rgba(168,85,247,0.2)',
      borderLeft: '3px solid ' + statusColor(s.status),
      borderRadius: '8px',
      padding: '12px 16px',
      marginBottom: '8px'
    }
  }, e('div', {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'flex-start',
      marginBottom: '6px'
    }
  }, e('div', {
    style: {
      flex: 1,
      minWidth: 0
    }
  }, e('div', {
    style: {
      color: '#1e293b',
      fontSize: '0.85rem',
      fontWeight: 600,
      overflow: 'hidden',
      textOverflow: 'ellipsis',
      whiteSpace: 'nowrap'
    }
  }, s.title || s.url), e('div', {
    style: {
      color: '#64748b',
      fontSize: '0.7rem'
    }
  }, (s.city || '') + (s.state ? ', ' + s.state : '') + ' · ' + (s.source_type || ''))), e('div', {
    style: {
      display: 'flex',
      gap: '8px',
      alignItems: 'center',
      flexShrink: 0
    }
  }, e('span', {
    style: {
      background: statusColor(s.status) + '15',
      border: '1px solid ' + statusColor(s.status) + '40',
      borderRadius: '4px',
      padding: '2px 8px',
      fontSize: '0.6rem',
      fontWeight: 700,
      color: statusColor(s.status),
      fontFamily: "'Orbitron', sans-serif"
    }
  }, s.status), e('span', {
    style: {
      color: '#f59e0b',
      fontSize: '0.75rem',
      fontWeight: 700,
      fontFamily: "'Orbitron', sans-serif"
    }
  }, 'P' + s.priority))), s.url && e('div', {
    style: {
      fontSize: '0.7rem',
      color: '#94a3b8',
      overflow: 'hidden',
      textOverflow: 'ellipsis',
      whiteSpace: 'nowrap'
    }
  }, s.url))));
}
ReactDOM.render(/*#__PURE__*/React.createElement(DensityProvider, null, /*#__PURE__*/React.createElement(Root, null)), document.getElementById('root'));
