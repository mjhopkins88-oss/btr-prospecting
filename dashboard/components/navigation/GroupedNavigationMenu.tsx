/**
 * GroupedNavigationMenu - BTR Command workflow-based navigation
 *
 * Canonical reference for the Command Center navigation architecture.
 * The live implementation is inlined in static/vendor/app.js as the
 * TopNav / SubNav / CommandCenter components (see NAV_SECTIONS there).
 *
 * Navigation model:
 *   - 5 top-level sections (Command Center, Deals, Market Intel, Pipeline, Admin)
 *   - Each section has 1..n child pages rendered as a secondary tab strip
 *   - Child `id` values map 1:1 to the existing `activeTab` routes so no
 *     downstream page component needs to change.
 *
 * Role visibility:
 *   - broker:   Command Center, Deals, Market Intel (Sunbelt Intelligence only)
 *   - producer: Command Center, Deals, Market Intel, Pipeline (My Pipeline)
 *   - admin:    Command Center, Deals, Market Intel, Pipeline (full), Admin*
 *   - *Admin section only shows when user.is_super_admin === true
 */

import React from 'react';

// ---- Types ----

export interface NavChild {
  id: string;
  label: string;
}

export interface NavSection {
  id: string;
  label: string;
  icon: string;
  children: NavChild[];
}

export interface User {
  role?: 'broker' | 'producer' | 'admin';
  is_super_admin?: boolean;
  name?: string;
}

// ---- Section definitions (source of truth) ----

export const NAV_SECTIONS: NavSection[] = [
  {
    id: 'command',
    label: 'Command Center',
    icon: '\u25C8', // ◈
    children: [
      { id: 'command', label: 'Overview' },
      { id: 'followups', label: 'Follow-ups Due' },
    ],
  },
  {
    id: 'deals',
    label: 'Deals',
    icon: '\u25B2', // ▲
    children: [
      { id: 'search', label: 'Prospect Search' },
      { id: 'linkedinhub', label: 'LinkedIn Hub' },
      { id: 'dealboard', label: 'Saved Prospects' },
    ],
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
      { id: 'markets', label: 'Market Expansion' },
    ],
  },
  {
    id: 'pipeline_section',
    label: 'Pipeline',
    icon: '\u25B3', // △
    children: [
      { id: 'pipeline', label: 'My Pipeline' },
      { id: 'quoting', label: 'Quoting' },
      { id: 'underwriting', label: 'Underwriting Sheet' },
    ],
  },
  {
    id: 'admin_section',
    label: 'Admin',
    icon: '\u2699', // ⚙
    children: [{ id: 'admin', label: 'Admin' }],
  },
];

// ---- Role-aware filtering ----

export function getNavForUser(user: User | null | undefined): NavSection[] {
  const role = user?.role || 'producer';
  const isSuperAdmin = !!user?.is_super_admin;

  const hiddenTabs = new Set<string>();
  if (role === 'broker') {
    [
      'discovery',
      'statewide',
      'predictions',
      'markets',
      'pipeline',
      'followups',
      'quoting',
      'underwriting',
    ].forEach((t) => hiddenTabs.add(t));
  } else if (role === 'producer') {
    ['quoting', 'underwriting'].forEach((t) => hiddenTabs.add(t));
  }

  const hiddenSections = new Set<string>();
  if (!isSuperAdmin) hiddenSections.add('admin_section');
  if (role === 'broker') hiddenSections.add('pipeline_section');

  return NAV_SECTIONS.filter((s) => !hiddenSections.has(s.id))
    .map((s) => ({
      ...s,
      children: s.children.filter((c) => !hiddenTabs.has(c.id)),
    }))
    .filter((s) => s.children.length > 0);
}

export function findSectionForTab(tabId: string, sections: NavSection[]): string {
  for (const s of sections) {
    if (s.children.some((c) => c.id === tabId)) return s.id;
  }
  return sections[0]?.id || 'command';
}

// ---- Props ----

interface TopNavProps {
  activeTab: string;
  setActiveTab: (id: string) => void;
  user: User | null;
}

// ---- TopNav ----

const topNavStyles = {
  row: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.4rem',
    padding: '0.5rem 0 0.85rem',
    marginBottom: '1.25rem',
    borderBottom: '1px solid rgba(51,65,85,0.5)',
    flexWrap: 'wrap' as const,
  },
  cta: {
    background: '#10b981',
    border: 'none',
    color: '#0f172a',
    padding: '0.6rem 1.1rem',
    borderRadius: '0.5rem',
    fontSize: '0.9rem',
    fontWeight: 600,
    cursor: 'pointer',
    fontFamily: "'Inter', sans-serif",
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.35rem',
    boxShadow: '0 0 18px rgba(16,185,129,0.25)',
  },
};

function sectionBtnStyle(isActive: boolean) {
  return {
    display: 'inline-flex' as const,
    alignItems: 'center' as const,
    gap: '0.5rem',
    padding: '0.6rem 1.1rem',
    background: isActive ? 'rgba(16,185,129,0.12)' : 'transparent',
    border: '1px solid ' + (isActive ? 'rgba(16,185,129,0.4)' : 'rgba(51,65,85,0.4)'),
    color: isActive ? '#34d399' : '#94a3b8',
    borderRadius: '0.75rem',
    cursor: 'pointer' as const,
    fontFamily: "'Orbitron', sans-serif",
    fontSize: '0.82rem',
    fontWeight: 700,
    letterSpacing: '0.03em',
    transition: 'all 0.2s',
    boxShadow: isActive ? '0 0 18px rgba(16,185,129,0.12)' : 'none',
  };
}

export function TopNav({ activeTab, setActiveTab, user }: TopNavProps) {
  const sections = getNavForUser(user);
  const activeSectionId = findSectionForTab(activeTab, sections);

  return (
    <div style={topNavStyles.row}>
      {sections.map((s) => {
        const isActive = s.id === activeSectionId;
        return (
          <button
            key={s.id}
            style={sectionBtnStyle(isActive)}
            onClick={() => {
              if (s.children.length > 0) setActiveTab(s.children[0].id);
            }}
          >
            <span style={{ fontSize: '0.95rem', opacity: 0.85 }}>{s.icon}</span>
            {s.label}
          </button>
        );
      })}
      <div style={{ marginLeft: 'auto', display: 'flex', gap: '0.5rem' }}>
        <button style={topNavStyles.cta} onClick={() => setActiveTab('search')}>
          + Run Prospect Search
        </button>
      </div>
    </div>
  );
}

// ---- SubNav ----

function subNavItemStyle(isActive: boolean) {
  return {
    background: 'transparent',
    border: 'none',
    color: isActive ? '#34d399' : '#64748b',
    padding: '0.5rem 0.95rem',
    fontSize: '0.8rem',
    fontWeight: 600,
    cursor: 'pointer' as const,
    borderBottom: isActive ? '2px solid #34d399' : '2px solid transparent',
    marginBottom: '-1px',
    fontFamily: "'Inter', sans-serif",
    letterSpacing: '0.01em',
    transition: 'color 0.2s, border-color 0.2s',
  };
}

export function SubNav({ activeTab, setActiveTab, user }: TopNavProps) {
  const sections = getNavForUser(user);
  const activeSectionId = findSectionForTab(activeTab, sections);
  const section = sections.find((s) => s.id === activeSectionId);
  if (!section || section.children.length <= 1) return null;

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '0.25rem',
        marginBottom: '1.5rem',
        borderBottom: '1px solid rgba(51,65,85,0.35)',
        flexWrap: 'wrap',
      }}
    >
      <span
        style={{
          fontFamily: "'Orbitron', sans-serif",
          fontSize: '0.68rem',
          color: '#64748b',
          textTransform: 'uppercase',
          letterSpacing: '0.12em',
          padding: '0.25rem 0.7rem 0.25rem 0',
          borderRight: '1px solid rgba(51,65,85,0.4)',
          marginRight: '0.5rem',
        }}
      >
        {section.label}
      </span>
      {section.children.map((c) => (
        <button
          key={c.id}
          style={subNavItemStyle(c.id === activeTab)}
          onClick={() => setActiveTab(c.id)}
        >
          {c.label}
        </button>
      ))}
    </div>
  );
}

// ---- Default export: combined nav menu ----

interface GroupedNavigationMenuProps {
  activeTab: string;
  setActiveTab: (id: string) => void;
  user: User | null;
}

export default function GroupedNavigationMenu({
  activeTab,
  setActiveTab,
  user,
}: GroupedNavigationMenuProps) {
  return (
    <>
      <TopNav activeTab={activeTab} setActiveTab={setActiveTab} user={user} />
      <SubNav activeTab={activeTab} setActiveTab={setActiveTab} user={user} />
    </>
  );
}
