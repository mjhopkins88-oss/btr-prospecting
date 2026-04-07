/**
 * SignalIntelligence - Signal Quality Ranking Engine Dashboard
 *
 * Displays signal source rankings, accuracy metrics, best performing
 * cities, and signal type performance from the Signal Quality Engine.
 *
 * Polls /api/signal-intelligence for data.
 * The rendering implementation lives inline in static/index.html.
 * This file is the canonical TypeScript reference for the component.
 */

import React, { useState, useEffect, useCallback } from 'react';

// ---- Types ----

interface SignalSource {
  source_name: string;
  source_type: string;
  city?: string;
  state?: string;
  signals_generated: number;
  signals_confirmed: number;
  accuracy_score: number;
  accuracy_pct: number;
}

interface TypeRanking {
  signal_type: string;
  signals_generated: number;
  signals_confirmed: number;
  accuracy_score: number;
  accuracy_pct: number;
}

interface CityRanking {
  city: string;
  state: string;
  source_count: number;
  avg_accuracy: number;
  avg_accuracy_pct: number;
  total_signals: number;
  total_confirmed: number;
}

interface PriorityEntry {
  source_name: string;
  priority_score: number;
  signals_last_30_days: number;
  accuracy_score: number;
  accuracy_pct: number;
  schedule_interval: string;
}

interface IntelligenceStats {
  total_sources: number;
  avg_accuracy: number;
  avg_accuracy_pct: number;
  total_signals_tracked: number;
  total_confirmed: number;
}

interface IntelligenceData {
  top_sources: SignalSource[];
  type_rankings: TypeRanking[];
  city_rankings: CityRanking[];
  priority_index: PriorityEntry[];
  stats: IntelligenceStats;
}

// ---- Constants ----

const POLL_INTERVAL_MS = 60_000; // refresh every 60s

function accuracyColor(pct: number): string {
  if (pct >= 70) return '#34d399';
  if (pct >= 50) return '#facc15';
  if (pct >= 30) return '#f97316';
  return '#ef4444';
}

function priorityTierColor(score: number): string {
  if (score > 0.7) return '#34d399';
  if (score >= 0.4) return '#facc15';
  return '#64748b';
}

// ---- Main Component ----

export default function SignalIntelligence() {
  const [data, setData] = useState<IntelligenceData | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'sources' | 'types' | 'cities' | 'priority'>('sources');

  const fetchData = useCallback(async () => {
    try {
      const res = await fetch('/api/signal-intelligence?limit=20');
      const json = await res.json();
      if (json.success) {
        setData(json);
      }
    } catch (e) {
      console.error('[SignalIntelligence] Error:', e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [fetchData]);

  if (loading && !data) {
    return (
      <div style={{ textAlign: 'center', padding: '3rem', color: '#34d399', fontFamily: "'Orbitron', sans-serif" }}>
        LOADING SIGNAL INTELLIGENCE...
      </div>
    );
  }

  if (!data) {
    return (
      <div style={{ textAlign: 'center', padding: '3rem', color: '#64748b' }}>
        No signal intelligence data available yet.
      </div>
    );
  }

  const { top_sources, type_rankings, city_rankings, priority_index, stats } = data;

  const tabs = [
    { key: 'sources' as const, label: 'TOP SOURCES' },
    { key: 'types' as const, label: 'SIGNAL TYPES' },
    { key: 'cities' as const, label: 'CITIES' },
    { key: 'priority' as const, label: 'PRIORITY INDEX' },
  ];

  return (
    <div style={{ maxWidth: '1000px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: '1.5rem' }}>
        <h2
          style={{
            fontFamily: "'Orbitron', sans-serif",
            fontSize: '1.3rem',
            fontWeight: 900,
            background: 'linear-gradient(135deg, #a78bfa 0%, #22d3ee 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            margin: 0,
          }}
        >
          SIGNAL INTELLIGENCE
        </h2>
        <p style={{ color: '#64748b', fontSize: '0.8rem', margin: '0.25rem 0 0' }}>
          Signal quality rankings and source accuracy analytics
        </p>
      </div>

      {/* Stats Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '12px', marginBottom: '1.5rem' }}>
        {[
          { label: 'TRACKED SOURCES', value: stats.total_sources },
          { label: 'AVG ACCURACY', value: `${stats.avg_accuracy_pct}%`, color: accuracyColor(stats.avg_accuracy_pct) },
          { label: 'SIGNALS TRACKED', value: stats.total_signals_tracked },
          { label: 'CONFIRMED', value: stats.total_confirmed, color: '#34d399' },
        ].map((card) => (
          <div
            key={card.label}
            style={{
              background: 'rgba(15,22,36,0.95)',
              border: '1px solid rgba(255,255,255,0.08)',
              borderRadius: '8px',
              padding: '14px 16px',
              textAlign: 'center',
            }}
          >
            <div style={{ fontSize: '0.6rem', color: '#64748b', fontFamily: "'Orbitron', sans-serif", marginBottom: '6px', letterSpacing: '0.05em' }}>
              {card.label}
            </div>
            <div style={{ fontSize: '1.4rem', fontWeight: 700, color: card.color || '#f1f5f9', fontFamily: "'Orbitron', sans-serif" }}>
              {card.value}
            </div>
          </div>
        ))}
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: '0.35rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            style={{
              background: activeTab === tab.key ? 'rgba(167,139,250,0.08)' : 'transparent',
              border: `1px solid ${activeTab === tab.key ? 'rgba(167,139,250,0.3)' : 'rgba(255,255,255,0.06)'}`,
              color: activeTab === tab.key ? '#a78bfa' : '#64748b',
              padding: '0.35rem 0.75rem',
              borderRadius: '4px',
              cursor: 'pointer',
              fontSize: '0.65rem',
              fontWeight: 600,
              fontFamily: "'Orbitron', sans-serif",
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div style={{ maxHeight: '55vh', overflowY: 'auto' }}>
        {activeTab === 'sources' && (
          <div>
            {top_sources.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '2rem', color: '#475569' }}>
                No signal sources tracked yet. Data will appear as signals are processed.
              </div>
            ) : (
              top_sources.map((src, i) => (
                <div
                  key={src.source_name}
                  style={{
                    background: 'rgba(15,22,36,0.95)',
                    border: '1px solid rgba(255,255,255,0.08)',
                    borderLeft: `3px solid ${accuracyColor(src.accuracy_pct)}`,
                    borderRadius: '8px',
                    padding: '12px 16px',
                    marginBottom: '8px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{ fontSize: '0.7rem', color: '#475569', fontWeight: 700 }}>#{i + 1}</span>
                      <span style={{ fontSize: '0.95rem', fontWeight: 600, color: '#f1f5f9' }}>{src.source_name}</span>
                      <span style={{
                        fontSize: '0.55rem', fontFamily: "'Orbitron', sans-serif",
                        background: 'rgba(167,139,250,0.08)', border: '1px solid rgba(167,139,250,0.2)',
                        borderRadius: '4px', padding: '2px 6px', color: '#a78bfa',
                      }}>
                        {src.source_type}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '4px' }}>
                      {src.signals_confirmed}/{src.signals_generated} signals confirmed
                      {src.city && ` · ${src.city}${src.state ? `, ${src.state}` : ''}`}
                    </div>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '1.2rem', fontWeight: 700, color: accuracyColor(src.accuracy_pct), fontFamily: "'Orbitron', sans-serif" }}>
                      {src.accuracy_pct}%
                    </div>
                    <div style={{ fontSize: '0.6rem', color: '#475569' }}>ACCURACY</div>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === 'types' && (
          <div>
            {type_rankings.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '2rem', color: '#475569' }}>
                No signal type data available yet.
              </div>
            ) : (
              type_rankings.map((t) => (
                <div
                  key={t.signal_type}
                  style={{
                    background: 'rgba(15,22,36,0.95)',
                    border: '1px solid rgba(255,255,255,0.08)',
                    borderRadius: '8px',
                    padding: '12px 16px',
                    marginBottom: '8px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 600, color: '#f1f5f9' }}>{t.signal_type}</div>
                    <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '2px' }}>
                      {t.signals_confirmed}/{t.signals_generated} confirmed
                    </div>
                  </div>
                  <div style={{
                    width: '60px', height: '60px', borderRadius: '50%',
                    border: `3px solid ${accuracyColor(t.accuracy_pct)}`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    flexDirection: 'column',
                  }}>
                    <div style={{ fontSize: '0.9rem', fontWeight: 700, color: accuracyColor(t.accuracy_pct), fontFamily: "'Orbitron', sans-serif" }}>
                      {t.accuracy_pct}%
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === 'cities' && (
          <div>
            {city_rankings.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '2rem', color: '#475569' }}>
                No city data available yet.
              </div>
            ) : (
              city_rankings.map((c) => (
                <div
                  key={`${c.city}-${c.state}`}
                  style={{
                    background: 'rgba(15,22,36,0.95)',
                    border: '1px solid rgba(255,255,255,0.08)',
                    borderRadius: '8px',
                    padding: '12px 16px',
                    marginBottom: '8px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 600, color: '#f1f5f9' }}>
                      {c.city}, {c.state}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '2px' }}>
                      {c.source_count} sources · {c.total_confirmed}/{c.total_signals} confirmed
                    </div>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '1.2rem', fontWeight: 700, color: accuracyColor(c.avg_accuracy_pct), fontFamily: "'Orbitron', sans-serif" }}>
                      {c.avg_accuracy_pct}%
                    </div>
                    <div style={{ fontSize: '0.6rem', color: '#475569' }}>AVG ACCURACY</div>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === 'priority' && (
          <div>
            {priority_index.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '2rem', color: '#475569' }}>
                No priority data available yet.
              </div>
            ) : (
              priority_index.map((p) => (
                <div
                  key={p.source_name}
                  style={{
                    background: 'rgba(15,22,36,0.95)',
                    border: '1px solid rgba(255,255,255,0.08)',
                    borderLeft: `3px solid ${priorityTierColor(p.priority_score)}`,
                    borderRadius: '8px',
                    padding: '12px 16px',
                    marginBottom: '8px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 600, color: '#f1f5f9' }}>{p.source_name}</div>
                    <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '2px' }}>
                      {p.signals_last_30_days} signals (30d) · Accuracy: {p.accuracy_pct}%
                    </div>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '0.9rem', fontWeight: 700, color: priorityTierColor(p.priority_score), fontFamily: "'Orbitron', sans-serif" }}>
                      {p.schedule_interval}
                    </div>
                    <div style={{ fontSize: '0.6rem', color: '#475569' }}>
                      PRIORITY: {(p.priority_score * 100).toFixed(0)}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}
