/**
 * DeveloperContacts - Dashboard panel for developer contact discovery
 *
 * Shows discovered contacts for development leads including contact name,
 * title, email, LinkedIn profile, and outreach draft preview.
 * Includes a "Send Outreach" button for each contact with a draft.
 *
 * Polls /api/developer-contacts every 30 seconds for updates.
 */

import React, { useState, useEffect, useCallback } from 'react';

// ---- Types ----

interface OutreachDraft {
  id: string;
  subject: string;
  email_body: string;
}

interface DeveloperContact {
  id: string;
  developer: string;
  contact_name: string;
  title: string;
  email: string;
  linkedin: string;
  company_domain: string;
  confidence_score: number;
  created_at: string;
}

interface LeadContact {
  id: string;
  contact_name: string;
  title: string;
  email: string;
  linkedin: string;
  company_domain: string;
  confidence_score: number;
  outreach_draft: OutreachDraft | null;
}

// ---- Constants ----

const POLL_INTERVAL_MS = 30_000;

// ---- Helpers ----

function confidenceColor(score: number): string {
  if (score >= 80) return '#00ff88';
  if (score >= 60) return '#00ccff';
  if (score >= 40) return '#ffaa00';
  return '#888888';
}

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

// ---- Component ----

const DeveloperContacts: React.FC = () => {
  const [contacts, setContacts] = useState<DeveloperContact[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [leadContacts, setLeadContacts] = useState<LeadContact[]>([]);
  const [sendingDraft, setSendingDraft] = useState<string | null>(null);
  const [sentDrafts, setSentDrafts] = useState<Set<string>>(new Set());

  const fetchContacts = useCallback(async () => {
    try {
      const res = await fetch('/api/developer-contacts?limit=50');
      if (res.ok) {
        const data = await res.json();
        setContacts(data.contacts || []);
      }
    } catch (err) {
      console.error('[DeveloperContacts] Fetch error:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchContacts();
    const interval = setInterval(fetchContacts, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [fetchContacts]);

  const handleSendOutreach = async (draftId: string) => {
    setSendingDraft(draftId);
    try {
      const res = await fetch(`/api/developer-contacts/send-outreach/${draftId}`, {
        method: 'POST',
      });
      if (res.ok) {
        setSentDrafts(prev => new Set(prev).add(draftId));
      }
    } catch (err) {
      console.error('[DeveloperContacts] Send error:', err);
    } finally {
      setSendingDraft(null);
    }
  };

  if (loading) {
    return (
      <div style={{ padding: '1rem', color: '#888' }}>
        Loading developer contacts...
      </div>
    );
  }

  if (contacts.length === 0) {
    return (
      <div style={{ padding: '1rem', color: '#888' }}>
        No developer contacts discovered yet.
      </div>
    );
  }

  return (
    <div style={{ padding: '1rem' }}>
      <h2 style={{ marginBottom: '1rem', color: '#00ff88', fontSize: '1.2rem' }}>
        Developer Contacts
      </h2>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.9rem' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid #333', color: '#aaa', textAlign: 'left' }}>
            <th style={{ padding: '0.5rem' }}>Developer</th>
            <th style={{ padding: '0.5rem' }}>Contact</th>
            <th style={{ padding: '0.5rem' }}>Title</th>
            <th style={{ padding: '0.5rem' }}>Email</th>
            <th style={{ padding: '0.5rem' }}>LinkedIn</th>
            <th style={{ padding: '0.5rem' }}>Confidence</th>
            <th style={{ padding: '0.5rem' }}>Discovered</th>
          </tr>
        </thead>
        <tbody>
          {contacts.map((contact) => (
            <tr key={contact.id} style={{ borderBottom: '1px solid #222' }}>
              <td style={{ padding: '0.5rem', color: '#fff' }}>{contact.developer}</td>
              <td style={{ padding: '0.5rem', color: '#ccc' }}>{contact.contact_name}</td>
              <td style={{ padding: '0.5rem', color: '#aaa' }}>{contact.title}</td>
              <td style={{ padding: '0.5rem' }}>
                {contact.email ? (
                  <a
                    href={`mailto:${contact.email}`}
                    style={{ color: '#00ccff', textDecoration: 'none' }}
                  >
                    {contact.email}
                  </a>
                ) : (
                  <span style={{ color: '#666' }}>--</span>
                )}
              </td>
              <td style={{ padding: '0.5rem' }}>
                {contact.linkedin ? (
                  <a
                    href={contact.linkedin}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ color: '#00ccff', textDecoration: 'none' }}
                  >
                    Profile
                  </a>
                ) : (
                  <span style={{ color: '#666' }}>--</span>
                )}
              </td>
              <td style={{
                padding: '0.5rem',
                color: confidenceColor(contact.confidence_score),
                fontWeight: 'bold'
              }}>
                {contact.confidence_score}
              </td>
              <td style={{ padding: '0.5rem', color: '#666' }}>
                {timeAgo(contact.created_at)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default DeveloperContacts;
