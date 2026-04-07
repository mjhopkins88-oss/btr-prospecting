/**
 * LiveIntelligenceFeed - BTR Command real-time intelligence terminal
 *
 * Displays a continuously updating feed of development signals detected
 * by the platform's intelligence engines (signal collectors, pattern detection,
 * developer DNA, contractor intelligence, parcel probability, market expansion).
 *
 * Polls /api/intelligence-feed every 10 seconds. Supports event type filtering,
 * pause/resume, and auto-scroll.
 *
 * The rendering implementation lives inline in static/index.html.
 * This file is the canonical TypeScript reference for the component architecture.
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';

// ---- Types ----

interface IntelligenceEvent {
  id: string;
  event_type: string;
  title: string;
  description?: string;
  city?: string;
  state?: string;
  related_entity?: string;
  entity_id?: string;
  created_at: string;
}

type EventType =
  | 'SIGNAL'
  | 'PERMIT'
  | 'PATTERN'
  | 'DEVELOPER_EXPANSION'
  | 'CONTRACTOR_ACTIVITY'
  | 'PARCEL_ALERT'
  | 'SUPPLY_CHAIN'
  | 'GRAPH_INFERENCE'
  | 'SIGNAL_QUALITY'
  | 'PLANNING_SIGNAL'
  | 'PERMIT_SIGNAL'
  | 'LAND_TRANSACTION'
  | 'PLAT_FILING'
  | 'CONSTRUCTION_FINANCING';

interface EventColorScheme {
  accent: string;
  bg: string;
  border: string;
}

// ---- Constants ----

const POLL_INTERVAL_MS = 10_000;
const MAX_EVENTS = 100;

export const FEED_EVENT_COLORS: Record<EventType, EventColorScheme> = {
  SIGNAL: { accent: '#22d3ee', bg: 'rgba(6,182,212,0.08)', border: 'rgba(6,182,212,0.2)' },
  PERMIT: { accent: '#3b82f6', bg: 'rgba(59,130,246,0.08)', border: 'rgba(59,130,246,0.2)' },
  PATTERN: { accent: '#a78bfa', bg: 'rgba(167,139,250,0.08)', border: 'rgba(167,139,250,0.2)' },
  DEVELOPER_EXPANSION: { accent: '#34d399', bg: 'rgba(52,211,153,0.08)', border: 'rgba(52,211,153,0.2)' },
  CONTRACTOR_ACTIVITY: { accent: '#f97316', bg: 'rgba(249,115,22,0.08)', border: 'rgba(249,115,22,0.2)' },
  PARCEL_ALERT: { accent: '#facc15', bg: 'rgba(250,204,21,0.08)', border: 'rgba(250,204,21,0.2)' },
  SUPPLY_CHAIN: { accent: '#fb923c', bg: 'rgba(251,146,60,0.08)', border: 'rgba(251,146,60,0.2)' },
  GRAPH_INFERENCE: { accent: '#c084fc', bg: 'rgba(192,132,252,0.08)', border: 'rgba(192,132,252,0.2)' },
  SIGNAL_QUALITY: { accent: '#06b6d4', bg: 'rgba(6,182,212,0.08)', border: 'rgba(6,182,212,0.2)' },
  PLANNING_SIGNAL: { accent: '#3b82f6', bg: 'rgba(59,130,246,0.08)', border: 'rgba(59,130,246,0.2)' },
  PERMIT_SIGNAL: { accent: '#22c55e', bg: 'rgba(34,197,94,0.08)', border: 'rgba(34,197,94,0.2)' },
  LAND_TRANSACTION: { accent: '#ef4444', bg: 'rgba(239,68,68,0.08)', border: 'rgba(239,68,68,0.2)' },
  PLAT_FILING: { accent: '#a855f7', bg: 'rgba(168,85,247,0.08)', border: 'rgba(168,85,247,0.2)' },
  CONSTRUCTION_FINANCING: { accent: '#eab308', bg: 'rgba(234,179,8,0.08)', border: 'rgba(234,179,8,0.2)' },
};

export const FEED_EVENT_LABELS: Record<EventType, string> = {
  SIGNAL: 'SIGNAL',
  PERMIT: 'PERMIT',
  PATTERN: 'PATTERN',
  DEVELOPER_EXPANSION: 'EXPANSION',
  CONTRACTOR_ACTIVITY: 'CONTRACTOR',
  PARCEL_ALERT: 'PARCEL',
  SUPPLY_CHAIN: 'SUPPLY CHAIN',
  GRAPH_INFERENCE: 'GRAPH',
  SIGNAL_QUALITY: 'QUALITY',
  PLANNING_SIGNAL: 'PLANNING',
  PERMIT_SIGNAL: 'PERMIT',
  LAND_TRANSACTION: 'LAND',
  PLAT_FILING: 'PLAT',
  CONSTRUCTION_FINANCING: 'FINANCING',
};

// ---- Helpers ----

export function timeAgo(dateStr: string): string {
  if (!dateStr) return '';
  const now = new Date();
  const then = new Date(dateStr);
  const secs = Math.floor((now.getTime() - then.getTime()) / 1000);
  if (secs < 60) return 'just now';
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins} minute${mins !== 1 ? 's' : ''} ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs} hour${hrs !== 1 ? 's' : ''} ago`;
  const days = Math.floor(hrs / 24);
  return `${days} day${days !== 1 ? 's' : ''} ago`;
}

// ---- Styles ----

const feedCardStyle = {
  background: 'rgba(15,22,36,0.95)',
  border: '1px solid rgba(255,255,255,0.08)',
  borderRadius: '8px',
  padding: '12px 16px',
  marginBottom: '8px',
};

// ---- Components ----

interface FeedEventCardProps {
  event: IntelligenceEvent;
  isNew: boolean;
}

function FeedEventCard({ event, isNew }: FeedEventCardProps) {
  const colors = FEED_EVENT_COLORS[event.event_type as EventType] || FEED_EVENT_COLORS.SIGNAL;
  const label = FEED_EVENT_LABELS[event.event_type as EventType] || event.event_type;

  return (
    <div
      style={{
        ...feedCardStyle,
        borderLeft: `3px solid ${colors.accent}`,
        animation: isNew ? 'feedSlideIn 200ms ease-out' : 'none',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span
            style={{
              background: colors.bg,
              border: `1px solid ${colors.border}`,
              borderRadius: '4px',
              padding: '2px 8px',
              fontSize: '0.6rem',
              fontWeight: 700,
              color: colors.accent,
              fontFamily: "'Orbitron', sans-serif",
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
            }}
          >
            {label}
          </span>
          <span style={{ fontSize: '0.95rem', fontWeight: 600, color: '#f1f5f9' }}>{event.title}</span>
        </div>
        <span style={{ fontSize: '0.7rem', color: '#475569', whiteSpace: 'nowrap' }}>{timeAgo(event.created_at)}</span>
      </div>
      {event.description && (
        <div style={{ fontSize: '0.82rem', color: '#94a3b8', marginTop: '2px' }}>{event.description}</div>
      )}
      {(event.city || event.related_entity) && (
        <div style={{ display: 'flex', gap: '12px', marginTop: '6px', fontSize: '0.72rem', color: '#64748b' }}>
          {event.city && (
            <span>
              {event.city}
              {event.state ? `, ${event.state}` : ''}
            </span>
          )}
          {event.related_entity && <span>{event.related_entity}</span>}
        </div>
      )}
    </div>
  );
}

// ---- Main Component ----

export default function LiveIntelligenceFeed() {
  const [events, setEvents] = useState<IntelligenceEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [paused, setPaused] = useState(false);
  const [filterType, setFilterType] = useState('');
  const [newIds, setNewIds] = useState<Set<string>>(new Set());
  const previousIdsRef = useRef<Set<string>>(new Set());
  const feedRef = useRef<HTMLDivElement>(null);

  const fetchFeed = useCallback(async () => {
    try {
      let url = `/api/intelligence-feed?limit=${MAX_EVENTS}`;
      if (filterType) url += `&type=${filterType}`;
      const res = await fetch(url);
      const data = await res.json();
      if (data.success && data.events) {
        const incoming = new Set<string>(data.events.map((e: IntelligenceEvent) => e.id));
        const fresh = new Set<string>();
        data.events.forEach((e: IntelligenceEvent) => {
          if (!previousIdsRef.current.has(e.id)) fresh.add(e.id);
        });
        previousIdsRef.current = incoming;
        setNewIds(fresh);
        setEvents(data.events);
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
    const interval = setInterval(() => {
      if (!paused) fetchFeed();
    }, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [fetchFeed, paused]);

  useEffect(() => {
    if (newIds.size > 0) {
      const timer = setTimeout(() => setNewIds(new Set()), 500);
      return () => clearTimeout(timer);
    }
  }, [newIds]);

  const typeFilters: string[] = ['', 'SIGNAL', 'PERMIT', 'PATTERN', 'DEVELOPER_EXPANSION', 'CONTRACTOR_ACTIVITY', 'PARCEL_ALERT', 'SUPPLY_CHAIN', 'GRAPH_INFERENCE', 'SIGNAL_QUALITY', 'LAND_TRANSACTION', 'PLAT_FILING', 'CONSTRUCTION_FINANCING'];

  return (
    <div style={{ maxWidth: '900px', margin: '0 auto' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div>
          <h2
            style={{
              fontFamily: "'Orbitron', sans-serif",
              fontSize: '1.3rem',
              fontWeight: 900,
              background: 'linear-gradient(135deg, #34d399 0%, #22d3ee 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              margin: 0,
            }}
          >
            LIVE INTELLIGENCE FEED
          </h2>
          <p style={{ color: '#64748b', fontSize: '0.8rem', margin: '0.25rem 0 0' }}>
            Real-time development signals across all monitored markets
          </p>
        </div>
        <button
          onClick={() => setPaused(!paused)}
          style={{
            background: paused ? 'rgba(239,68,68,0.1)' : 'rgba(52,211,153,0.1)',
            border: `1px solid ${paused ? 'rgba(239,68,68,0.3)' : 'rgba(52,211,153,0.3)'}`,
            color: paused ? '#f87171' : '#34d399',
            padding: '0.4rem 0.85rem',
            borderRadius: '6px',
            cursor: 'pointer',
            fontSize: '0.75rem',
            fontWeight: 600,
            fontFamily: "'Orbitron', sans-serif",
          }}
        >
          {paused ? 'PAUSED' : 'LIVE'}
        </button>
      </div>

      {/* Type filter bar */}
      <div style={{ display: 'flex', gap: '0.35rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
        {typeFilters.map((t) => {
          const colors = FEED_EVENT_COLORS[t as EventType] || { accent: '#94a3b8', bg: 'transparent', border: 'rgba(255,255,255,0.08)' };
          const active = filterType === t;
          return (
            <button
              key={t || 'all'}
              onClick={() => setFilterType(t)}
              style={{
                background: active ? colors.bg : 'transparent',
                border: `1px solid ${active ? colors.border : 'rgba(255,255,255,0.06)'}`,
                color: active ? colors.accent : '#64748b',
                padding: '0.3rem 0.65rem',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '0.65rem',
                fontWeight: 600,
                fontFamily: "'Orbitron', sans-serif",
                textTransform: 'uppercase',
              }}
            >
              {t ? FEED_EVENT_LABELS[t as EventType] || t : 'ALL'}
            </button>
          );
        })}
      </div>

      {/* Feed container */}
      <div ref={feedRef} style={{ maxHeight: '65vh', overflowY: 'auto', padding: '2px', scrollBehavior: 'smooth' }}>
        {loading && events.length === 0 && (
          <div style={{ textAlign: 'center', padding: '3rem', color: '#34d399', fontFamily: "'Orbitron', sans-serif", animation: 'pulse 1.5s ease-in-out infinite' }}>
            INITIALIZING FEED...
          </div>
        )}
        {!loading && events.length === 0 && (
          <div style={{ textAlign: 'center', padding: '3rem' }}>
            <div style={{ fontSize: '1.2rem', color: '#64748b', fontFamily: "'Orbitron', sans-serif", marginBottom: '0.5rem' }}>NO EVENTS YET</div>
            <div style={{ fontSize: '0.85rem', color: '#475569' }}>Intelligence events will appear here as they are detected by the system.</div>
          </div>
        )}
        {events.map((event) => (
          <FeedEventCard key={event.id} event={event} isNew={newIds.has(event.id)} />
        ))}
      </div>

      {events.length > 0 && (
        <div style={{ textAlign: 'center', padding: '0.5rem', fontSize: '0.7rem', color: '#475569', marginTop: '0.5rem' }}>
          Showing {events.length} events &middot; Polling every 10s{paused ? ' (paused)' : ''}
        </div>
      )}
    </div>
  );
}
