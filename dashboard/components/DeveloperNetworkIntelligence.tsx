/**
 * DeveloperNetworkIntelligence - Developer Network Graph Dashboard
 *
 * Displays the developer relationship graph: connections between developers,
 * contractors, engineers, architects, lenders, and suppliers.
 *
 * Shows:
 *   - Top network clusters (strongest relationships)
 *   - Network statistics by relationship type
 *   - Entity-specific network connections (searchable)
 *   - Relationship strength indicators
 *
 * Polls /api/developer-network for data.
 */

import React, { useState, useEffect, useCallback } from 'react';

// ---- Types ----

interface NetworkEdge {
  entity_a: string;
  entity_b: string;
  relationship_type: string;
  co_occurrence_count: number;
  relationship_strength: number;
  last_seen?: string;
}

interface NetworkStats {
  total_edges: number;
  strong_edges: number;
  by_type: { relationship_type: string; count: number; avg_strength: number }[];
}

// ---- Constants ----

const POLL_INTERVAL_MS = 60_000;

const RELATIONSHIP_COLORS: Record<string, string> = {
  DEVELOPER_CONTRACTOR: '#f97316',
  DEVELOPER_ENGINEER: '#3b82f6',
  DEVELOPER_ARCHITECT: '#a855f7',
  DEVELOPER_LENDER: '#eab308',
  CONTRACTOR_SUPPLIER: '#22c55e',
  DEVELOPER_SUPPLIER: '#06b6d4',
  CONTRACTOR_ENGINEER: '#ec4899',
  LENDER_DEVELOPER: '#eab308',
};

const RELATIONSHIP_LABELS: Record<string, string> = {
  DEVELOPER_CONTRACTOR: 'Developer-Contractor',
  DEVELOPER_ENGINEER: 'Developer-Engineer',
  DEVELOPER_ARCHITECT: 'Developer-Architect',
  DEVELOPER_LENDER: 'Developer-Lender',
  CONTRACTOR_SUPPLIER: 'Contractor-Supplier',
  DEVELOPER_SUPPLIER: 'Developer-Supplier',
  CONTRACTOR_ENGINEER: 'Contractor-Engineer',
  LENDER_DEVELOPER: 'Lender-Developer',
};

// ---- Helpers ----

function strengthLabel(strength: number): string {
  if (strength >= 80) return 'STRONG';
  if (strength >= 50) return 'MODERATE';
  if (strength >= 25) return 'EMERGING';
  return 'WEAK';
}

function strengthColor(strength: number): string {
  if (strength >= 80) return '#22c55e';
  if (strength >= 50) return '#eab308';
  if (strength >= 25) return '#f97316';
  return '#64748b';
}

// ---- Component ----

export default function DeveloperNetworkIntelligence() {
  const [clusters, setClusters] = useState<NetworkEdge[]>([]);
  const [stats, setStats] = useState<NetworkStats | null>(null);
  const [searchEntity, setSearchEntity] = useState('');
  const [entityConnections, setEntityConnections] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchData = useCallback(async () => {
    try {
      const [clustersRes, statsRes] = await Promise.all([
        fetch('/api/developer-network/clusters?limit=30'),
        fetch('/api/developer-network/stats'),
      ]);

      if (clustersRes.ok) {
        const data = await clustersRes.json();
        setClusters(data.clusters || []);
      }
      if (statsRes.ok) {
        const data = await statsRes.json();
        setStats(data);
      }
      setError('');
    } catch (e) {
      setError('Failed to load network data');
    } finally {
      setLoading(false);
    }
  }, []);

  const searchEntityNetwork = useCallback(async () => {
    if (!searchEntity.trim()) return;
    try {
      const res = await fetch(`/api/developer-network/${encodeURIComponent(searchEntity)}`);
      if (res.ok) {
        const data = await res.json();
        setEntityConnections(data.connections || []);
      }
    } catch {
      setEntityConnections([]);
    }
  }, [searchEntity]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [fetchData]);

  return (
    <div style={{ maxWidth: '900px', margin: '0 auto' }}>
      <div style={{ marginBottom: '1.25rem' }}>
        <h2
          style={{
            fontFamily: "'Orbitron', sans-serif",
            fontSize: '1.3rem',
            fontWeight: 900,
            background: 'linear-gradient(135deg, #06b6d4 0%, #a855f7 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            letterSpacing: '0.05em',
            marginBottom: '0.25rem',
          }}
        >
          DEVELOPER NETWORK INTELLIGENCE
        </h2>
        <p style={{ color: '#64748b', fontSize: '0.8rem', margin: 0 }}>
          Relationship graph: developers, contractors, engineers, architects, lenders, suppliers
        </p>
      </div>

      {/* Stats bar */}
      {stats && (
        <div style={{
          display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px',
          marginBottom: '1rem',
        }}>
          <div style={{
            background: 'rgba(15,22,36,0.95)',
            border: '1px solid rgba(6,182,212,0.3)',
            borderRadius: '8px', padding: '12px', textAlign: 'center',
          }}>
            <div style={{ color: '#06b6d4', fontSize: '1.5rem', fontWeight: 900,
              fontFamily: "'Orbitron', sans-serif" }}>{stats.total_edges}</div>
            <div style={{ color: '#64748b', fontSize: '0.7rem', textTransform: 'uppercase',
              letterSpacing: '0.1em' }}>Network Edges</div>
          </div>
          <div style={{
            background: 'rgba(15,22,36,0.95)',
            border: '1px solid rgba(34,197,94,0.3)',
            borderRadius: '8px', padding: '12px', textAlign: 'center',
          }}>
            <div style={{ color: '#22c55e', fontSize: '1.5rem', fontWeight: 900,
              fontFamily: "'Orbitron', sans-serif" }}>{stats.strong_edges}</div>
            <div style={{ color: '#64748b', fontSize: '0.7rem', textTransform: 'uppercase',
              letterSpacing: '0.1em' }}>Strong Links</div>
          </div>
          <div style={{
            background: 'rgba(15,22,36,0.95)',
            border: '1px solid rgba(168,85,247,0.3)',
            borderRadius: '8px', padding: '12px', textAlign: 'center',
          }}>
            <div style={{ color: '#a855f7', fontSize: '1.5rem', fontWeight: 900,
              fontFamily: "'Orbitron', sans-serif" }}>{stats.by_type?.length || 0}</div>
            <div style={{ color: '#64748b', fontSize: '0.7rem', textTransform: 'uppercase',
              letterSpacing: '0.1em' }}>Relationship Types</div>
          </div>
        </div>
      )}

      {/* Entity search */}
      <div style={{
        display: 'flex', gap: '8px', marginBottom: '1rem',
      }}>
        <input
          type="text"
          value={searchEntity}
          onChange={(e) => setSearchEntity(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && searchEntityNetwork()}
          placeholder="Search entity network..."
          style={{
            flex: 1, background: 'rgba(15,22,36,0.95)',
            border: '1px solid rgba(100,116,139,0.3)',
            borderRadius: '6px', padding: '8px 12px',
            color: '#e2e8f0', fontSize: '0.85rem',
            fontFamily: "'JetBrains Mono', monospace",
          }}
        />
        <button
          onClick={searchEntityNetwork}
          style={{
            background: 'rgba(6,182,212,0.2)',
            border: '1px solid rgba(6,182,212,0.4)',
            borderRadius: '6px', padding: '8px 16px',
            color: '#06b6d4', cursor: 'pointer', fontSize: '0.8rem',
            fontWeight: 700,
          }}
        >
          SEARCH
        </button>
      </div>

      {/* Entity connections */}
      {entityConnections.length > 0 && (
        <div style={{ marginBottom: '1rem' }}>
          <h3 style={{ color: '#06b6d4', fontSize: '0.85rem', fontWeight: 700,
            marginBottom: '8px', fontFamily: "'Orbitron', sans-serif" }}>
            CONNECTIONS FOR: {searchEntity}
          </h3>
          {entityConnections.map((conn: any, i: number) => (
            <div key={i} style={{
              background: 'rgba(15,22,36,0.95)',
              border: `1px solid ${RELATIONSHIP_COLORS[conn.relationship_type] || '#64748b'}40`,
              borderLeft: `3px solid ${RELATIONSHIP_COLORS[conn.relationship_type] || '#64748b'}`,
              borderRadius: '6px', padding: '10px 14px', marginBottom: '6px',
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            }}>
              <div>
                <div style={{ color: '#e2e8f0', fontSize: '0.85rem', fontWeight: 600 }}>
                  {conn.partner}
                </div>
                <div style={{ color: '#64748b', fontSize: '0.7rem' }}>
                  {RELATIONSHIP_LABELS[conn.relationship_type] || conn.relationship_type}
                  {' · '}{conn.co_occurrence_count} co-occurrences
                </div>
              </div>
              <div style={{
                background: `${strengthColor(conn.relationship_strength)}20`,
                border: `1px solid ${strengthColor(conn.relationship_strength)}40`,
                borderRadius: '4px', padding: '2px 8px',
                fontSize: '0.65rem', fontWeight: 700,
                color: strengthColor(conn.relationship_strength),
                fontFamily: "'Orbitron', sans-serif",
              }}>
                {strengthLabel(conn.relationship_strength)} ({conn.relationship_strength})
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Top clusters */}
      <h3 style={{ color: '#a855f7', fontSize: '0.85rem', fontWeight: 700,
        marginBottom: '8px', fontFamily: "'Orbitron', sans-serif" }}>
        TOP NETWORK CLUSTERS
      </h3>

      {loading && <div style={{ color: '#64748b', padding: '20px' }}>Loading network data...</div>}
      {error && <div style={{ color: '#ef4444', padding: '10px' }}>{error}</div>}

      {clusters.map((edge, i) => (
        <div key={i} style={{
          background: 'rgba(15,22,36,0.95)',
          border: `1px solid ${RELATIONSHIP_COLORS[edge.relationship_type] || '#64748b'}40`,
          borderLeft: `3px solid ${RELATIONSHIP_COLORS[edge.relationship_type] || '#64748b'}`,
          borderRadius: '8px', padding: '12px 16px', marginBottom: '8px',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                <span style={{ color: '#e2e8f0', fontSize: '0.85rem', fontWeight: 600 }}>
                  {edge.entity_a}
                </span>
                <span style={{ color: '#64748b', fontSize: '0.75rem' }}>&#8596;</span>
                <span style={{ color: '#e2e8f0', fontSize: '0.85rem', fontWeight: 600 }}>
                  {edge.entity_b}
                </span>
              </div>
              <div style={{ display: 'flex', gap: '12px' }}>
                <span style={{
                  background: `${RELATIONSHIP_COLORS[edge.relationship_type] || '#64748b'}20`,
                  border: `1px solid ${RELATIONSHIP_COLORS[edge.relationship_type] || '#64748b'}40`,
                  borderRadius: '4px', padding: '1px 6px', fontSize: '0.6rem',
                  fontWeight: 700, color: RELATIONSHIP_COLORS[edge.relationship_type] || '#64748b',
                  fontFamily: "'Orbitron', sans-serif",
                }}>
                  {RELATIONSHIP_LABELS[edge.relationship_type] || edge.relationship_type}
                </span>
                <span style={{ color: '#64748b', fontSize: '0.7rem' }}>
                  {edge.co_occurrence_count} co-occurrences
                </span>
              </div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{
                color: strengthColor(edge.relationship_strength),
                fontSize: '1.1rem', fontWeight: 900,
                fontFamily: "'Orbitron', sans-serif",
              }}>
                {edge.relationship_strength}
              </div>
              <div style={{
                color: strengthColor(edge.relationship_strength),
                fontSize: '0.6rem', fontWeight: 700,
                fontFamily: "'Orbitron', sans-serif",
              }}>
                {strengthLabel(edge.relationship_strength)}
              </div>
            </div>
          </div>
        </div>
      ))}

      {/* Relationship type breakdown */}
      {stats?.by_type && stats.by_type.length > 0 && (
        <div style={{ marginTop: '1.5rem' }}>
          <h3 style={{ color: '#06b6d4', fontSize: '0.85rem', fontWeight: 700,
            marginBottom: '8px', fontFamily: "'Orbitron', sans-serif" }}>
            RELATIONSHIP TYPES
          </h3>
          <div style={{
            display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px',
          }}>
            {stats.by_type.map((t, i) => (
              <div key={i} style={{
                background: 'rgba(15,22,36,0.95)',
                border: `1px solid ${RELATIONSHIP_COLORS[t.relationship_type] || '#64748b'}30`,
                borderRadius: '6px', padding: '10px',
              }}>
                <div style={{
                  color: RELATIONSHIP_COLORS[t.relationship_type] || '#64748b',
                  fontSize: '0.7rem', fontWeight: 700,
                  fontFamily: "'Orbitron', sans-serif",
                  marginBottom: '4px',
                }}>
                  {RELATIONSHIP_LABELS[t.relationship_type] || t.relationship_type}
                </div>
                <div style={{ color: '#e2e8f0', fontSize: '1rem', fontWeight: 700 }}>
                  {t.count} edges
                </div>
                <div style={{ color: '#64748b', fontSize: '0.7rem' }}>
                  Avg strength: {Math.round(t.avg_strength || 0)}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
