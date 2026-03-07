/**
 * DevelopmentRadarMap - BTR Command development radar visualization
 *
 * Displays a radar-style map of development signals and construction
 * supply chain activity across monitored markets.
 *
 * Marker types:
 *   blue   — Standard development signals (permits, zoning, land purchase)
 *   orange — Construction Supply Chain Signals (engineering, site prep, utility)
 *   green  — High probability parcels (>70%)
 *   red    — Pattern matches detected
 *
 * Polls /api/radar-map every 30 seconds.
 */

import React, { useState, useEffect, useCallback } from 'react';

// ---- Types ----

interface RadarMarker {
  id: string;
  parcel_id?: string;
  signal_type: string;
  entity_name?: string;
  address?: string;
  city?: string;
  state?: string;
  latitude?: number;
  longitude?: number;
  development_probability: number;
  marker_color: string;
  created_at: string;
}

type SignalCategory = '' | 'supply_chain' | 'planning' | 'permit' | 'land_transaction' | 'plat_filing' | 'financing' | 'BUILDING_PERMIT' | 'ZONING_APPLICATION' | 'LAND_PURCHASE';

// ---- Constants ----

const POLL_INTERVAL_MS = 30_000;

const SIGNAL_TYPE_LABELS: Record<string, string> = {
  CIVIL_ENGINEERING_PLAN: 'Civil Engineering Plan',
  SITE_PREP_ACTIVITY: 'Site Preparation Activity',
  UTILITY_CONNECTION_REQUEST: 'Utility Connection Request',
  EARTHWORK_CONTRACTOR: 'Earthwork Contractor',
  CONCRETE_SUPPLY_SIGNAL: 'Concrete Supply Signal',
  INFRASTRUCTURE_BID: 'Infrastructure Bid',
  BUILDING_PERMIT: 'Building Permit',
  ZONING_APPLICATION: 'Zoning Application',
  LAND_PURCHASE: 'Land Purchase',
  ENGINEERING_ENGAGEMENT: 'Engineering Engagement',
  SITE_PLAN_SUBMISSION: 'Site Plan Submission',
  ZONING_AGENDA_ITEM: 'Zoning Agenda Item',
  REZONING_REQUEST: 'Rezoning Request',
  SUBDIVISION_APPLICATION: 'Subdivision Application',
  DEVELOPMENT_REVIEW_CASE: 'Development Review Case',
  MULTIFAMILY_PERMIT: 'Multifamily Permit',
  SUBDIVISION_PERMIT: 'Subdivision Permit',
  SITE_DEVELOPMENT_PERMIT: 'Site Development Permit',
  RESIDENTIAL_COMPLEX_PERMIT: 'Residential Complex Permit',
  LAND_PURCHASE: 'Land Purchase',
  DEED_TRANSFER: 'Deed Transfer',
  OWNER_CHANGE: 'Ownership Change',
  SUBDIVISION_PLAT: 'Subdivision Plat',
  PRELIMINARY_PLAT: 'Preliminary Plat',
  FINAL_PLAT: 'Final Plat',
  LOT_SPLIT: 'Lot Split',
  CONSTRUCTION_FINANCING: 'Construction Financing',
  COMMERCIAL_MORTGAGE: 'Commercial Mortgage',
  SECURED_LOAN: 'Secured Loan',
  DEVELOPER_EXPANSION: 'Developer Expansion',
};

const SUPPLY_CHAIN_TYPES = new Set([
  'CIVIL_ENGINEERING_PLAN', 'SITE_PREP_ACTIVITY',
  'UTILITY_CONNECTION_REQUEST', 'EARTHWORK_CONTRACTOR',
  'CONCRETE_SUPPLY_SIGNAL', 'INFRASTRUCTURE_BID',
]);

const PLANNING_SIGNAL_TYPES = new Set([
  'ZONING_AGENDA_ITEM', 'SITE_PLAN_SUBMISSION',
  'SUBDIVISION_APPLICATION', 'REZONING_REQUEST',
  'DEVELOPMENT_REVIEW_CASE',
]);

const PERMIT_SIGNAL_TYPES = new Set([
  'BUILDING_PERMIT', 'MULTIFAMILY_PERMIT',
  'SUBDIVISION_PERMIT', 'SITE_DEVELOPMENT_PERMIT',
  'RESIDENTIAL_COMPLEX_PERMIT',
]);

const LAND_TRANSACTION_TYPES = new Set([
  'LAND_PURCHASE', 'DEED_TRANSFER', 'OWNER_CHANGE',
]);

const PLAT_FILING_TYPES = new Set([
  'SUBDIVISION_PLAT', 'PRELIMINARY_PLAT',
  'FINAL_PLAT', 'LOT_SPLIT',
]);

const FINANCING_SIGNAL_TYPES = new Set([
  'CONSTRUCTION_FINANCING', 'COMMERCIAL_MORTGAGE',
  'SECURED_LOAN',
]);

// ---- Helpers ----

function timeAgo(dateStr: string): string {
  if (!dateStr) return '';
  const now = new Date();
  const then = new Date(dateStr);
  const secs = Math.floor((now.getTime() - then.getTime()) / 1000);
  if (secs < 60) return 'just now';
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

function getMarkerStyle(marker: RadarMarker) {
  const isSupplyChain = SUPPLY_CHAIN_TYPES.has(marker.signal_type);
  const isHighProb = marker.development_probability >= 70;

  const isPlanningSignal = PLANNING_SIGNAL_TYPES.has(marker.signal_type);
  const isPermitSignal = PERMIT_SIGNAL_TYPES.has(marker.signal_type);

  const isLandTransaction = LAND_TRANSACTION_TYPES.has(marker.signal_type);
  const isPlatFiling = PLAT_FILING_TYPES.has(marker.signal_type);
  const isFinancing = FINANCING_SIGNAL_TYPES.has(marker.signal_type);

  if (isSupplyChain) return { color: '#f97316', bg: 'rgba(249,115,22,0.15)', border: 'rgba(249,115,22,0.4)', label: 'SUPPLY CHAIN' };
  if (isPermitSignal) return { color: '#22c55e', bg: 'rgba(34,197,94,0.15)', border: 'rgba(34,197,94,0.4)', label: 'PERMIT SIGNAL' };
  if (isPlanningSignal) return { color: '#3b82f6', bg: 'rgba(59,130,246,0.15)', border: 'rgba(59,130,246,0.4)', label: 'PLANNING SIGNAL' };
  if (isLandTransaction) return { color: '#ef4444', bg: 'rgba(239,68,68,0.15)', border: 'rgba(239,68,68,0.4)', label: 'LAND TRANSACTION' };
  if (isPlatFiling) return { color: '#a855f7', bg: 'rgba(168,85,247,0.15)', border: 'rgba(168,85,247,0.4)', label: 'PLAT FILING' };
  if (isFinancing) return { color: '#eab308', bg: 'rgba(234,179,8,0.15)', border: 'rgba(234,179,8,0.4)', label: 'FINANCING' };
  if (isHighProb) return { color: '#34d399', bg: 'rgba(52,211,153,0.15)', border: 'rgba(52,211,153,0.4)', label: 'HIGH PROB' };
  return { color: '#3b82f6', bg: 'rgba(59,130,246,0.15)', border: 'rgba(59,130,246,0.4)', label: 'SIGNAL' };
}

// ---- Components ----

interface MarkerCardProps {
  marker: RadarMarker;
}

function MarkerCard({ marker }: MarkerCardProps) {
  const style = getMarkerStyle(marker);
  const isSupplyChain = SUPPLY_CHAIN_TYPES.has(marker.signal_type);

  return (
    <div
      style={{
        background: 'rgba(15,22,36,0.95)',
        border: `1px solid ${style.border}`,
        borderLeft: `3px solid ${style.color}`,
        borderRadius: '8px',
        padding: '12px 16px',
        marginBottom: '8px',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span
            style={{
              background: style.bg,
              border: `1px solid ${style.border}`,
              borderRadius: '4px',
              padding: '2px 8px',
              fontSize: '0.6rem',
              fontWeight: 700,
              color: style.color,
              fontFamily: "'Orbitron', sans-serif",
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
            }}
          >
            {isSupplyChain ? 'CONSTRUCTION SIGNAL' : style.label}
          </span>
          <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#f1f5f9' }}>
            {SIGNAL_TYPE_LABELS[marker.signal_type] || marker.signal_type}
          </span>
        </div>
        <span style={{ fontSize: '0.7rem', color: '#475569', whiteSpace: 'nowrap' }}>
          {timeAgo(marker.created_at)}
        </span>
      </div>

      <div style={{ fontSize: '0.82rem', color: '#94a3b8', marginTop: '4px' }}>
        {marker.city && <span>{marker.city}{marker.state ? `, ${marker.state}` : ''}</span>}
        {marker.entity_name && <span style={{ marginLeft: '12px', color: style.color }}>{marker.entity_name}</span>}
      </div>

      {marker.address && (
        <div style={{ fontSize: '0.72rem', color: '#64748b', marginTop: '4px' }}>{marker.address}</div>
      )}

      <div style={{ display: 'flex', gap: '16px', marginTop: '6px', fontSize: '0.7rem' }}>
        <span style={{ color: marker.development_probability >= 70 ? '#34d399' : '#64748b' }}>
          Probability: {marker.development_probability}%
        </span>
      </div>
    </div>
  );
}

// ---- Main Component ----

export default function DevelopmentRadarMap() {
  const [markers, setMarkers] = useState<RadarMarker[]>([]);
  const [loading, setLoading] = useState(true);
  const [category, setCategory] = useState<SignalCategory>('');
  const [cityFilter, setCityFilter] = useState('');

  const fetchMarkers = useCallback(async () => {
    try {
      let url = `/api/radar-map?limit=200`;
      if (category) url += `&signal_category=${category}`;
      const res = await fetch(url);
      const data = await res.json();
      if (data.markers) {
        setMarkers(data.markers);
      }
    } catch (e) {
      console.error('[RadarMap] Error:', e);
    } finally {
      setLoading(false);
    }
  }, [category]);

  useEffect(() => {
    fetchMarkers();
    const interval = setInterval(fetchMarkers, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [fetchMarkers]);

  const filteredMarkers = cityFilter
    ? markers.filter(m => m.city?.toLowerCase().includes(cityFilter.toLowerCase()))
    : markers;

  const supplyChainCount = markers.filter(m => SUPPLY_CHAIN_TYPES.has(m.signal_type)).length;
  const highProbCount = markers.filter(m => m.development_probability >= 70).length;

  const categories: { value: SignalCategory; label: string }[] = [
    { value: '', label: 'ALL SIGNALS' },
    { value: 'supply_chain', label: 'SUPPLY CHAIN' },
    { value: 'permit', label: 'PERMITS' },
    { value: 'planning', label: 'PLANNING' },
    { value: 'land_transaction', label: 'LAND' },
    { value: 'plat_filing', label: 'PLATS' },
    { value: 'financing', label: 'FINANCING' },
  ];

  return (
    <div style={{ maxWidth: '900px', margin: '0 auto' }}>
      <div style={{ marginBottom: '1.25rem' }}>
        <h2
          style={{
            fontFamily: "'Orbitron', sans-serif",
            fontSize: '1.3rem',
            fontWeight: 900,
            background: 'linear-gradient(135deg, #f97316 0%, #22d3ee 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            margin: 0,
          }}
        >
          DEVELOPMENT RADAR MAP
        </h2>
        <p style={{ color: '#64748b', fontSize: '0.8rem', margin: '0.25rem 0 0' }}>
          Geo-located development signals &amp; construction supply chain activity
        </p>
      </div>

      {/* Stats bar */}
      <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
        <div style={{ background: 'rgba(249,115,22,0.08)', border: '1px solid rgba(249,115,22,0.2)', borderRadius: '6px', padding: '8px 16px' }}>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, color: '#f97316', fontFamily: "'Orbitron', sans-serif" }}>{supplyChainCount}</div>
          <div style={{ fontSize: '0.65rem', color: '#94a3b8', textTransform: 'uppercase' }}>Supply Chain</div>
        </div>
        <div style={{ background: 'rgba(52,211,153,0.08)', border: '1px solid rgba(52,211,153,0.2)', borderRadius: '6px', padding: '8px 16px' }}>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, color: '#34d399', fontFamily: "'Orbitron', sans-serif" }}>{highProbCount}</div>
          <div style={{ fontSize: '0.65rem', color: '#94a3b8', textTransform: 'uppercase' }}>High Probability</div>
        </div>
        <div style={{ background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.2)', borderRadius: '6px', padding: '8px 16px' }}>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, color: '#3b82f6', fontFamily: "'Orbitron', sans-serif" }}>{markers.length}</div>
          <div style={{ fontSize: '0.65rem', color: '#94a3b8', textTransform: 'uppercase' }}>Total Signals</div>
        </div>
      </div>

      {/* Category filter */}
      <div style={{ display: 'flex', gap: '0.35rem', marginBottom: '0.75rem', flexWrap: 'wrap' }}>
        {categories.map((cat) => {
          const active = category === cat.value;
          const color = cat.value === 'supply_chain' ? '#f97316' : '#94a3b8';
          return (
            <button
              key={cat.value || 'all'}
              onClick={() => setCategory(cat.value)}
              style={{
                background: active ? `rgba(${cat.value === 'supply_chain' ? '249,115,22' : '148,163,184'},0.1)` : 'transparent',
                border: `1px solid ${active ? color : 'rgba(255,255,255,0.06)'}`,
                color: active ? color : '#64748b',
                padding: '0.3rem 0.65rem',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '0.65rem',
                fontWeight: 600,
                fontFamily: "'Orbitron', sans-serif",
              }}
            >
              {cat.label}
            </button>
          );
        })}
      </div>

      {/* City search */}
      <input
        type="text"
        placeholder="Filter by city..."
        value={cityFilter}
        onChange={(e) => setCityFilter(e.target.value)}
        style={{
          width: '100%',
          background: 'rgba(15,22,36,0.8)',
          border: '1px solid rgba(255,255,255,0.08)',
          borderRadius: '6px',
          padding: '8px 12px',
          color: '#f1f5f9',
          fontSize: '0.85rem',
          marginBottom: '1rem',
          outline: 'none',
        }}
      />

      {/* Signal list */}
      <div style={{ maxHeight: '55vh', overflowY: 'auto', padding: '2px' }}>
        {loading && markers.length === 0 && (
          <div style={{ textAlign: 'center', padding: '3rem', color: '#f97316', fontFamily: "'Orbitron', sans-serif", animation: 'pulse 1.5s ease-in-out infinite' }}>
            SCANNING RADAR...
          </div>
        )}
        {!loading && filteredMarkers.length === 0 && (
          <div style={{ textAlign: 'center', padding: '3rem' }}>
            <div style={{ fontSize: '1.2rem', color: '#64748b', fontFamily: "'Orbitron', sans-serif", marginBottom: '0.5rem' }}>NO SIGNALS</div>
            <div style={{ fontSize: '0.85rem', color: '#475569' }}>No signals match the current filter.</div>
          </div>
        )}
        {filteredMarkers.map((marker) => (
          <MarkerCard key={marker.id} marker={marker} />
        ))}
      </div>

      {filteredMarkers.length > 0 && (
        <div style={{ textAlign: 'center', padding: '0.5rem', fontSize: '0.7rem', color: '#475569', marginTop: '0.5rem' }}>
          Showing {filteredMarkers.length} signals &middot; Refreshing every 30s
        </div>
      )}
    </div>
  );
}
