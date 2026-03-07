/**
 * GroupedNavigationMenu - BTR Command grouped dropdown navigation
 *
 * This component defines the navigation group structure and types used by the
 * inline TabBar/NavDropdown components in static/index.html.
 *
 * The actual rendering lives in static/index.html as part of the single-page
 * React app (loaded via CDN). This file serves as the canonical reference for
 * the navigation architecture and can be used if the project migrates to a
 * bundled React setup.
 */

import React, { useState, useRef, useEffect } from 'react';

// ---- Types ----

interface NavItem {
  id: string;
  label: string;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

interface NavDropdownProps {
  group: NavGroup;
  activeTab: string;
  setActiveTab: (id: string) => void;
}

interface GroupedNavigationMenuProps {
  activeTab: string;
  setActiveTab: (id: string) => void;
  user: { role?: string; is_super_admin?: boolean } | null;
}

// ---- Styles ----

const dropdownStyles = {
  container: {
    position: 'absolute' as const,
    top: '100%',
    left: 0,
    minWidth: '220px',
    zIndex: 1000,
    background: 'rgba(15,22,36,0.95)',
    backdropFilter: 'blur(12px)',
    WebkitBackdropFilter: 'blur(12px)',
    border: '1px solid rgba(255,255,255,0.08)',
    borderRadius: '0.5rem',
    padding: '0.4rem 0',
    marginTop: '2px',
    boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
    animation: 'navDropIn 200ms ease-out forwards',
  },
  item: {
    display: 'block',
    width: '100%',
    textAlign: 'left' as const,
    background: 'transparent',
    border: 'none',
    color: '#cbd5e1',
    padding: '0.6rem 1.1rem',
    fontSize: '0.85rem',
    fontWeight: 500,
    cursor: 'pointer',
    fontFamily: "'Inter', sans-serif",
    transition: 'background 0.15s, color 0.15s',
  },
  itemHover: {
    background: 'rgba(0,255,180,0.08)',
    color: '#00FFC6',
  },
  itemActive: {
    background: 'rgba(0,255,198,0.08)',
    color: '#00FFC6',
  },
};

// ---- Navigation Group Definitions ----

export const NAV_GROUPS: Record<string, NavGroup[]> = {
  broker: [
    {
      label: 'Prospecting',
      items: [
        { id: 'search', label: 'Prospect Search' },
        { id: 'dealboard', label: 'Deal Board' },
      ],
    },
    {
      label: 'Intelligence',
      items: [
        { id: 'intelligence', label: 'Sunbelt Intelligence' },
        { id: 'dev_network', label: 'Developer Networks' },
        { id: 'corridors', label: 'Dev Corridors' },
        { id: 'dev_momentum', label: 'Momentum Engine' },
      ],
    },
  ],
  producer: [
    {
      label: 'Prospecting',
      items: [
        { id: 'search', label: 'Prospect Search' },
        { id: 'discovery', label: 'Daily Discovery' },
        { id: 'statewide', label: 'Statewide' },
        { id: 'predictions', label: 'Predicted Devs' },
        { id: 'markets', label: 'Market Expansion' },
      ],
    },
    {
      label: 'Intelligence',
      items: [
        { id: 'intelligence', label: 'Sunbelt Intelligence' },
        { id: 'dev_network', label: 'Developer Networks' },
        { id: 'corridors', label: 'Dev Corridors' },
        { id: 'dev_momentum', label: 'Momentum Engine' },
      ],
    },
    {
      label: 'Pipeline',
      items: [
        { id: 'pipeline', label: 'My Pipeline' },
        { id: 'followups', label: 'Follow-ups Due' },
      ],
    },
  ],
  admin: [
    {
      label: 'Prospecting',
      items: [
        { id: 'search', label: 'Prospect Search' },
        { id: 'discovery', label: 'Daily Discovery' },
        { id: 'statewide', label: 'Statewide' },
        { id: 'predictions', label: 'Predicted Devs' },
        { id: 'markets', label: 'Market Expansion' },
      ],
    },
    {
      label: 'Intelligence',
      items: [
        { id: 'intelligence', label: 'Sunbelt Intelligence' },
        { id: 'dev_network', label: 'Developer Networks' },
        { id: 'corridors', label: 'Dev Corridors' },
        { id: 'dev_momentum', label: 'Momentum Engine' },
        { id: 'signal_discovery', label: 'Signal Discovery' },
      ],
    },
    {
      label: 'Pipeline',
      items: [
        { id: 'pipeline', label: 'My Pipeline' },
        { id: 'followups', label: 'Follow-ups Due' },
        { id: 'quoting', label: 'Quoting' },
        { id: 'underwriting', label: 'Underwriting Sheet' },
      ],
    },
    {
      label: 'System',
      items: [{ id: 'admin', label: 'Admin' }],
    },
  ],
};

// ---- Components ----

function NavDropdown({ group, activeTab, setActiveTab }: NavDropdownProps) {
  const [open, setOpen] = useState(false);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const hasActive = group.items.some((i) => i.id === activeTab);

  const handleEnter = () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    setOpen(true);
  };
  const handleLeave = () => {
    timeoutRef.current = setTimeout(() => setOpen(false), 120);
  };

  useEffect(() => () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
  }, []);

  return (
    <div style={{ position: 'relative' }} onMouseEnter={handleEnter} onMouseLeave={handleLeave}>
      <button
        style={{
          background: 'transparent',
          border: 'none',
          color: hasActive ? '#00FFC6' : '#94a3b8',
          padding: '0.75rem 1.25rem',
          fontSize: '0.9rem',
          fontWeight: 700,
          cursor: 'pointer',
          fontFamily: "'Orbitron', sans-serif",
          transition: 'color 0.2s',
          borderBottom: hasActive ? '2px solid #00FFC6' : '2px solid transparent',
          marginBottom: '-2px',
          display: 'flex',
          alignItems: 'center',
          gap: '0.35rem',
        }}
        onClick={() => {
          if (group.items.length === 1) setActiveTab(group.items[0].id);
        }}
      >
        {group.label}
        {group.items.length > 1 && (
          <span
            style={{
              fontSize: '0.55rem',
              opacity: 0.6,
              transition: 'transform 0.2s',
              transform: open ? 'rotate(180deg)' : 'rotate(0)',
            }}
          >
            &#9660;
          </span>
        )}
      </button>
      {open && group.items.length > 1 && (
        <div style={dropdownStyles.container}>
          {group.items.map((item) => (
            <button
              key={item.id}
              onClick={() => {
                setActiveTab(item.id);
                setOpen(false);
              }}
              style={{
                ...dropdownStyles.item,
                ...(activeTab === item.id ? dropdownStyles.itemActive : {}),
              }}
              onMouseEnter={(e) => {
                (e.target as HTMLElement).style.background = 'rgba(0,255,198,0.08)';
                (e.target as HTMLElement).style.color = '#00FFC6';
              }}
              onMouseLeave={(e) => {
                (e.target as HTMLElement).style.background =
                  activeTab === item.id ? 'rgba(0,255,198,0.08)' : 'transparent';
                (e.target as HTMLElement).style.color =
                  activeTab === item.id ? '#00FFC6' : '#cbd5e1';
              }}
            >
              {item.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export default function GroupedNavigationMenu({
  activeTab,
  setActiveTab,
  user,
}: GroupedNavigationMenuProps) {
  const role = user?.role || 'producer';
  const [mobileOpen, setMobileOpen] = useState(false);

  let groups = [...(NAV_GROUPS[role] || NAV_GROUPS.producer)];

  if (user?.is_super_admin && !groups.some((g) => g.label === 'System')) {
    groups.push({ label: 'System', items: [{ id: 'admin', label: 'Admin' }] });
  }

  return (
    <>
      {/* Desktop navigation */}
      <div
        className="nav-desktop"
        style={{ display: 'flex', gap: '0.25rem', borderBottom: '2px solid #334155', paddingBottom: '0', marginBottom: '2rem', flexWrap: 'wrap' }}
      >
        {groups.map((group) => (
          <NavDropdown key={group.label} group={group} activeTab={activeTab} setActiveTab={setActiveTab} />
        ))}
      </div>
      {/* Mobile hamburger */}
      <div className="nav-mobile" style={{ display: 'none', marginBottom: '1.5rem' }}>
        <button
          onClick={() => setMobileOpen(!mobileOpen)}
          style={{
            background: 'rgba(15,22,36,0.95)',
            border: '1px solid rgba(255,255,255,0.08)',
            color: '#00FFC6',
            padding: '0.7rem 1rem',
            borderRadius: '0.5rem',
            cursor: 'pointer',
            fontSize: '1.1rem',
            fontFamily: "'Orbitron', sans-serif",
            fontWeight: 700,
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            width: '100%',
            justifyContent: 'space-between',
          }}
        >
          <span>{mobileOpen ? 'Close Menu' : 'Menu'}</span>
          <span style={{ fontSize: '1.2rem' }}>{mobileOpen ? '\u2715' : '\u2630'}</span>
        </button>
        {mobileOpen && (
          <div
            style={{
              background: 'rgba(15,22,36,0.95)',
              backdropFilter: 'blur(12px)',
              WebkitBackdropFilter: 'blur(12px)',
              border: '1px solid rgba(255,255,255,0.08)',
              borderRadius: '0.5rem',
              marginTop: '0.5rem',
              padding: '0.5rem 0',
              animation: 'navDropIn 200ms ease-out forwards',
            }}
          >
            {groups.map((group) => (
              <div key={group.label}>
                <div
                  style={{
                    padding: '0.5rem 1rem',
                    fontSize: '0.65rem',
                    color: '#64748b',
                    textTransform: 'uppercase',
                    letterSpacing: '0.1em',
                    fontWeight: 700,
                    fontFamily: "'Orbitron', sans-serif",
                    borderBottom: '1px solid rgba(255,255,255,0.04)',
                  }}
                >
                  {group.label}
                </div>
                {group.items.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => {
                      setActiveTab(item.id);
                      setMobileOpen(false);
                    }}
                    style={{
                      display: 'block',
                      width: '100%',
                      textAlign: 'left',
                      background: activeTab === item.id ? 'rgba(0,255,198,0.08)' : 'transparent',
                      border: 'none',
                      color: activeTab === item.id ? '#00FFC6' : '#cbd5e1',
                      padding: '0.65rem 1.5rem',
                      fontSize: '0.85rem',
                      fontWeight: 500,
                      cursor: 'pointer',
                      fontFamily: "'Inter', sans-serif",
                    }}
                  >
                    {item.label}
                  </button>
                ))}
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
}
