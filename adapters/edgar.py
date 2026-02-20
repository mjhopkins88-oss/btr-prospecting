"""
EDGAR Adapter — monitors SEC filings for BTR operators.

Uses the official SEC EDGAR EFTS (full-text search) API.
No scraping — purely API-based.

Endpoints used:
  - efts.sec.gov/LATEST/search-index?q=...&dateRange=...&forms=...
  - www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=...&type=...&dateb=&owner=include&count=10&output=atom
"""
import json
import re
from datetime import datetime, timedelta

import requests

from adapters.base import BaseAdapter
from discovery_config import MONITORED_OPERATORS, EDGAR_FILING_TYPES

# SEC requires a User-Agent with contact info
SEC_USER_AGENT = 'BTRProspecting/1.0 (btr-discovery-bot; max@btrinsurance.com)'
EFTS_SEARCH_URL = 'https://efts.sec.gov/LATEST/search-index'
EDGAR_FILING_URL = 'https://www.sec.gov/cgi-bin/browse-edgar'
EDGAR_FULL_TEXT_URL = 'https://efts.sec.gov/LATEST/search-index'

# Keywords that indicate BTR-relevant filing content
BTR_KEYWORDS = [
    'build to rent', 'build-to-rent', 'single family rental',
    'single-family rental', 'BTR', 'SFR',
    'acquisition', 'disposition', 'credit facility',
    'joint venture', 'recapitalization', 'securitization',
]

# Map filing content to signal types
SIGNAL_KEYWORDS = {
    'acquisition': ['acquisition', 'acquired', 'purchase', 'merger'],
    'sale': ['disposition', 'disposed', 'sold', 'sale of'],
    'financing': ['credit facility', 'securitization', 'debt', 'loan', 'offering', 'notes'],
    'recap': ['recapitalization', 'joint venture', 'JV', 'partnership'],
}


class EDGARAdapter(BaseAdapter):
    name = 'edgar'
    source_type = 'filing'

    def fetch(self, cities, config):
        items = []

        for operator_name, info in MONITORED_OPERATORS.items():
            cik = info.get('cik', '')
            if not cik:
                continue  # skip private companies

            if not self.limiter.can_call():
                print(f"[EDGAR] Call cap reached, stopping")
                break

            filings = self._fetch_recent_filings(cik, operator_name)
            items.extend(filings)

        return items

    def _fetch_recent_filings(self, cik, company_name):
        """Fetch recent filings for a company from EDGAR full-text search."""
        if not self.limiter.wait():
            return []

        # Use EDGAR full-text search API
        date_from = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        date_to = datetime.now().strftime('%Y-%m-%d')

        # Strip leading zeros for EFTS
        cik_clean = cik.lstrip('0')

        try:
            # EDGAR EFTS full-text search for this company's recent filings
            url = 'https://efts.sec.gov/LATEST/search-index'
            params = {
                'q': f'"{company_name}"',
                'dateRange': 'custom',
                'startdt': date_from,
                'enddt': date_to,
                'forms': ','.join(EDGAR_FILING_TYPES),
            }

            resp = requests.get(
                url,
                params=params,
                headers={'User-Agent': SEC_USER_AGENT},
                timeout=15
            )

            if resp.status_code == 429:
                self.limiter.report_error(429, resp.headers.get('Retry-After'))
                return []

            if resp.status_code != 200:
                # Fallback: use the company filings RSS feed
                return self._fetch_via_rss(cik, company_name)

            data = resp.json()
            hits = data.get('hits', {}).get('hits', [])

            items = []
            for hit in hits[:5]:  # limit per company
                source = hit.get('_source', {})
                filing_type = source.get('forms', source.get('form_type', ''))
                if isinstance(filing_type, list):
                    filing_type = filing_type[0] if filing_type else ''

                title = source.get('display_names', source.get('entity_name', company_name))
                if isinstance(title, list):
                    title = title[0] if title else company_name

                file_date = source.get('file_date', source.get('period_of_report', ''))
                file_num = source.get('file_num', '')

                # Build SEC filing URL
                accession = source.get('_id', source.get('accession_no', ''))
                filing_url = f'https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}&type={filing_type}&dateb=&owner=include&count=5'
                if accession:
                    acc_clean = accession.replace('-', '')
                    filing_url = f'https://www.sec.gov/Archives/edgar/data/{cik_clean}/{acc_clean}'

                description = source.get('display_description', '')
                if not description:
                    description = f'{company_name} filed {filing_type}'

                signal_type = self._detect_signal_type(description, filing_type)
                confidence = 'high' if filing_type in ('8-K', '10-Q', '10-K') else 'medium'

                items.append({
                    'title': f'{company_name} — {filing_type} Filing',
                    'url': filing_url,
                    'snippet': description[:300] if description else f'{filing_type} filed {file_date}',
                    'published_at': file_date,
                    'source_name': 'SEC EDGAR',
                    'source_type': 'filing',
                    'confidence': confidence,
                    'city': '',
                    'state': '',
                    'entity_name': company_name,
                    'signal_type': signal_type,
                })

            return items

        except requests.exceptions.Timeout:
            print(f"[EDGAR] Timeout fetching filings for {company_name}")
            return []
        except Exception as e:
            print(f"[EDGAR] Error fetching filings for {company_name}: {e}")
            # Try RSS fallback
            return self._fetch_via_rss(cik, company_name)

    def _fetch_via_rss(self, cik, company_name):
        """Fallback: fetch recent filings via EDGAR company RSS/Atom feed."""
        if not self.limiter.wait():
            return []

        try:
            cik_clean = cik.lstrip('0')
            url = f'https://data.sec.gov/submissions/CIK{cik}.json'

            resp = requests.get(
                url,
                headers={'User-Agent': SEC_USER_AGENT},
                timeout=15
            )

            if resp.status_code == 429:
                self.limiter.report_error(429, resp.headers.get('Retry-After'))
                return []

            if resp.status_code != 200:
                self.limiter.report_error(resp.status_code)
                return []

            data = resp.json()
            recent = data.get('filings', {}).get('recent', {})

            forms = recent.get('form', [])
            dates = recent.get('filingDate', [])
            accessions = recent.get('accessionNumber', [])
            primary_docs = recent.get('primaryDocument', [])
            descriptions = recent.get('primaryDocDescription', [])

            cutoff = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
            items = []

            for i in range(min(len(forms), 20)):
                form = forms[i] if i < len(forms) else ''
                # Check if this is a filing type we care about
                if not any(form.startswith(ft) for ft in EDGAR_FILING_TYPES):
                    continue

                file_date = dates[i] if i < len(dates) else ''
                if file_date < cutoff:
                    continue

                accession = accessions[i] if i < len(accessions) else ''
                acc_clean = accession.replace('-', '')
                primary_doc = primary_docs[i] if i < len(primary_docs) else ''
                desc = descriptions[i] if i < len(descriptions) else ''

                filing_url = f'https://www.sec.gov/Archives/edgar/data/{cik_clean}/{acc_clean}/{primary_doc}'

                signal_type = self._detect_signal_type(desc, form)
                confidence = 'high' if form in ('8-K', '10-Q', '10-K') else 'medium'

                items.append({
                    'title': f'{company_name} — {form} Filing',
                    'url': filing_url,
                    'snippet': desc or f'{form} filed {file_date}',
                    'published_at': file_date,
                    'source_name': 'SEC EDGAR',
                    'source_type': 'filing',
                    'confidence': confidence,
                    'city': '',
                    'state': '',
                    'entity_name': company_name,
                    'signal_type': signal_type,
                })

                if len(items) >= 5:
                    break

            return items

        except requests.exceptions.Timeout:
            print(f"[EDGAR] Timeout on RSS fallback for {company_name}")
            return []
        except Exception as e:
            print(f"[EDGAR] RSS fallback error for {company_name}: {e}")
            return []

    def _detect_signal_type(self, description, filing_type):
        """Detect signal type from filing description and type."""
        desc_lower = (description or '').lower()

        for signal, keywords in SIGNAL_KEYWORDS.items():
            for kw in keywords:
                if kw.lower() in desc_lower:
                    return signal

        # Default mapping by filing type
        if filing_type == '8-K':
            return 'other'  # 8-K is a catch-all current report
        elif filing_type in ('10-Q', '10-K'):
            return 'other'
        elif filing_type.startswith('424') or filing_type == 'S-3':
            return 'financing'
        elif filing_type == 'D':
            return 'financing'

        return 'other'
