/**
 * CommandPalette - BTR Command global search and navigation
 *
 * Keyboard shortcut: Cmd+K (Mac) / Ctrl+K (Windows)
 *
 * Searches across: Navigation Pages, Developers, Cities/Markets,
 * Projects, Parcels, Signals, and Quick-Action Tools.
 *
 * The rendering implementation lives inline in static/index.html.
 * This file is the canonical TypeScript reference for the component
 * architecture and can be used when migrating to a bundled React setup.
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';

// ---- Types ----

interface CommandItem {
  id: string;
  label: string;
  category: string;
  icon?: string;
  action: () => void;
}

interface CommandPaletteProps {
  activeTab: string;
  setActiveTab: (id: string) => void;
  user: { role?: string; is_super_admin?: boolean } | null;
  prospects: Array<{ company?: string; city?: string; state?: string }>;
}

// ---- Category Definitions ----

type CategoryKey = 'pages' | 'developers' | 'cities' | 'projects' | 'parcels' | 'signals' | 'tools';

const CATEGORY_LABELS: Record<CategoryKey, string> = {
  pages: 'Pages',
  developers: 'Developers',
  cities: 'Cities / Markets',
  projects: 'Projects',
  parcels: 'Parcels',
  signals: 'Signals',
  tools: 'Tools',
};

const CATEGORY_ICONS: Record<CategoryKey, string> = {
  pages: '\u{1F4C4}',
  developers: '\u{1F3D7}',
  cities: '\u{1F306}',
  projects: '\u{1F4CD}',
  parcels: '\u{1F4D0}',
  signals: '\u{1F4E1}',
  tools: '\u{26A1}',
};

// ---- Styles ----

export const commandPaletteStyles = {
  overlay: {
    position: 'fixed' as const,
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    background: 'rgba(0,0,0,0.6)',
    backdropFilter: 'blur(4px)',
    WebkitBackdropFilter: 'blur(4px)',
    display: 'flex',
    alignItems: 'flex-start',
    justifyContent: 'center',
    paddingTop: '15vh',
    zIndex: 9999,
    animation: 'cmdPaletteOverlayIn 180ms ease-out forwards',
  },
  modal: {
    background: 'rgba(15,22,36,0.95)',
    backdropFilter: 'blur(16px)',
    WebkitBackdropFilter: 'blur(16px)',
    border: '1px solid rgba(255,255,255,0.08)',
    borderRadius: '12px',
    boxShadow: '0 30px 80px rgba(0,0,0,0.5)',
    width: '720px',
    maxWidth: '92vw',
    maxHeight: '70vh',
    display: 'flex',
    flexDirection: 'column' as const,
    animation: 'cmdPaletteIn 180ms ease-out forwards',
    overflow: 'hidden',
  },
  input: {
    background: 'transparent',
    border: 'none',
    borderBottom: '1px solid rgba(255,255,255,0.06)',
    color: '#f1f5f9',
    padding: '1rem 1.25rem',
    fontSize: '1.05rem',
    fontFamily: "'Inter', sans-serif",
    outline: 'none',
    width: '100%',
  },
  results: {
    overflowY: 'auto' as const,
    padding: '0.5rem 0',
    flex: 1,
  },
  categoryLabel: {
    padding: '0.5rem 1.25rem 0.25rem',
    fontSize: '0.65rem',
    color: '#64748b',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.1em',
    fontWeight: 700,
    fontFamily: "'Orbitron', sans-serif",
  },
  resultItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    padding: '0.55rem 1.25rem',
    cursor: 'pointer',
    fontSize: '0.9rem',
    color: '#cbd5e1',
    fontFamily: "'Inter', sans-serif",
    transition: 'background 0.1s, color 0.1s',
    border: 'none',
    background: 'transparent',
    width: '100%',
    textAlign: 'left' as const,
  },
  resultItemSelected: {
    background: 'rgba(0,255,180,0.08)',
    color: '#00FFC6',
  },
  footer: {
    borderTop: '1px solid rgba(255,255,255,0.06)',
    padding: '0.5rem 1.25rem',
    display: 'flex',
    gap: '1rem',
    fontSize: '0.7rem',
    color: '#475569',
    fontFamily: "'Inter', sans-serif",
  },
  kbd: {
    background: 'rgba(255,255,255,0.06)',
    border: '1px solid rgba(255,255,255,0.08)',
    borderRadius: '4px',
    padding: '0.1rem 0.35rem',
    fontSize: '0.65rem',
    color: '#64748b',
    fontFamily: 'monospace',
  },
};

// ---- CSS Keyframes (injected in <style>) ----
// @keyframes cmdPaletteIn {
//   from { opacity: 0; transform: scale(0.96); }
//   to { opacity: 1; transform: scale(1); }
// }
// @keyframes cmdPaletteOverlayIn {
//   from { opacity: 0; }
//   to { opacity: 1; }
// }

// ---- Component ----

export default function CommandPalette({ activeTab, setActiveTab, user, prospects }: CommandPaletteProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const resultsRef = useRef<HTMLDivElement>(null);

  // Global keyboard listener
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setOpen((prev) => !prev);
        setQuery('');
        setSelectedIndex(0);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // Focus input when opened
  useEffect(() => {
    if (open) inputRef.current?.focus();
  }, [open]);

  // Build searchable items
  const allItems = useCallback((): CommandItem[] => {
    const items: CommandItem[] = [];

    // Pages
    const pages = [
      { id: 'search', label: 'Prospect Search' },
      { id: 'discovery', label: 'Daily Discovery' },
      { id: 'statewide', label: 'Statewide' },
      { id: 'intelligence', label: 'Sunbelt Intelligence' },
      { id: 'predictions', label: 'Predicted Devs' },
      { id: 'markets', label: 'Market Expansion' },
      { id: 'pipeline', label: 'My Pipeline' },
      { id: 'followups', label: 'Follow-ups Due' },
      { id: 'quoting', label: 'Quoting' },
      { id: 'underwriting', label: 'Underwriting Sheet' },
    ];
    pages.forEach((p) =>
      items.push({ ...p, category: 'pages', action: () => { setActiveTab(p.id); setOpen(false); } })
    );

    // Developers (from prospects)
    const devSet = new Set<string>();
    prospects.forEach((p) => {
      if (p.company && !devSet.has(p.company)) {
        devSet.add(p.company);
        items.push({
          id: `dev-${p.company}`,
          label: p.company,
          category: 'developers',
          action: () => { setActiveTab('search'); setOpen(false); },
        });
      }
    });

    // Cities
    const citySet = new Set<string>();
    prospects.forEach((p) => {
      const city = p.city && p.state ? `${p.city}, ${p.state}` : p.city;
      if (city && !citySet.has(city)) {
        citySet.add(city);
        items.push({
          id: `city-${city}`,
          label: city,
          category: 'cities',
          action: () => { setActiveTab('markets'); setOpen(false); },
        });
      }
    });

    // Tools
    const tools = [
      { id: 'tool-create-prospect', label: 'Create Prospect', tabId: 'search' },
      { id: 'tool-open-pipeline', label: 'Open Pipeline', tabId: 'pipeline' },
      { id: 'tool-run-discovery', label: 'Run Discovery Scan', tabId: 'discovery' },
      { id: 'tool-intel-brief', label: 'Generate Intelligence Brief', tabId: 'intelligence' },
    ];
    tools.forEach((t) =>
      items.push({
        id: t.id,
        label: t.label,
        category: 'tools',
        action: () => { setActiveTab(t.tabId); setOpen(false); },
      })
    );

    return items;
  }, [prospects, setActiveTab]);

  // Filter results
  const filtered = allItems().filter((item) =>
    item.label.toLowerCase().includes(query.toLowerCase())
  );

  // Group by category
  const grouped: Record<string, CommandItem[]> = {};
  filtered.forEach((item) => {
    if (!grouped[item.category]) grouped[item.category] = [];
    grouped[item.category].push(item);
  });

  // Flat list for keyboard navigation
  const flatResults = Object.values(grouped).flat();

  // Keyboard navigation inside modal
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((i) => Math.min(i + 1, flatResults.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === 'Enter' && flatResults[selectedIndex]) {
      e.preventDefault();
      flatResults[selectedIndex].action();
    } else if (e.key === 'Escape') {
      setOpen(false);
    }
  };

  if (!open) return null;

  return (
    <div style={commandPaletteStyles.overlay} onClick={() => setOpen(false)} role="dialog" aria-modal="true" aria-label="Command palette">
      <div style={commandPaletteStyles.modal} onClick={(e) => e.stopPropagation()} onKeyDown={handleKeyDown}>
        <input
          ref={inputRef}
          type="text"
          value={query}
          onChange={(e) => { setQuery(e.target.value); setSelectedIndex(0); }}
          placeholder="Search developers, markets, parcels, tools\u2026"
          style={commandPaletteStyles.input}
          aria-label="Search command palette"
        />
        <div ref={resultsRef} style={commandPaletteStyles.results} role="listbox">
          {Object.entries(grouped).map(([cat, items]) => (
            <div key={cat}>
              <div style={commandPaletteStyles.categoryLabel}>
                {CATEGORY_ICONS[cat as CategoryKey]} {CATEGORY_LABELS[cat as CategoryKey] || cat}
              </div>
              {items.map((item) => {
                const idx = flatResults.indexOf(item);
                return (
                  <button
                    key={item.id}
                    role="option"
                    aria-selected={idx === selectedIndex}
                    style={{
                      ...commandPaletteStyles.resultItem,
                      ...(idx === selectedIndex ? commandPaletteStyles.resultItemSelected : {}),
                    }}
                    onClick={item.action}
                    onMouseEnter={() => setSelectedIndex(idx)}
                  >
                    {item.label}
                  </button>
                );
              })}
            </div>
          ))}
          {flatResults.length === 0 && (
            <div style={{ padding: '2rem', textAlign: 'center', color: '#475569', fontSize: '0.9rem' }}>
              No results found
            </div>
          )}
        </div>
        <div style={commandPaletteStyles.footer}>
          <span><span style={commandPaletteStyles.kbd}>&uarr;&darr;</span> navigate</span>
          <span><span style={commandPaletteStyles.kbd}>Enter</span> select</span>
          <span><span style={commandPaletteStyles.kbd}>Esc</span> close</span>
        </div>
      </div>
    </div>
  );
}
