"""
Data models for the Lead Intelligence entity graph.
Plain dicts with factory helpers — no ORM dependency.
"""
from shared.database import new_id, now_ts


# ---------------------------------------------------------------------------
# Entity factories
# ---------------------------------------------------------------------------

def make_project(name, city, state, **extra):
    return {
        'id': new_id(),
        'name': name,
        'city': city,
        'state': state,
        'project_type': extra.get('project_type', 'BTR'),
        'status': extra.get('status', 'rumored'),
        'unit_count': extra.get('unit_count'),
        'estimated_value': extra.get('estimated_value'),
        'source_url': extra.get('source_url'),
        'raw_json': extra.get('raw_json'),
        'created_at': now_ts(),
        'updated_at': now_ts(),
    }


def make_company(name, **extra):
    return {
        'id': new_id(),
        'name': name,
        'domain': extra.get('domain'),
        'company_type': extra.get('company_type', 'developer'),
        'hq_city': extra.get('hq_city'),
        'hq_state': extra.get('hq_state'),
        'employee_count': extra.get('employee_count'),
        'raw_json': extra.get('raw_json'),
        'created_at': now_ts(),
        'updated_at': now_ts(),
    }


def make_contact(company_id, full_name, **extra):
    return {
        'id': new_id(),
        'company_id': company_id,
        'full_name': full_name,
        'title': extra.get('title'),
        'email': extra.get('email'),
        'phone': extra.get('phone'),
        'linkedin_url': extra.get('linkedin_url'),
        'role_tag': extra.get('role_tag', 'unknown'),
        'created_at': now_ts(),
        'updated_at': now_ts(),
    }


def make_signal(source_type, headline, **extra):
    return {
        'id': new_id(),
        'source_type': source_type,
        'headline': headline,
        'body': extra.get('body'),
        'url': extra.get('url'),
        'published_at': extra.get('published_at'),
        'city': extra.get('city'),
        'state': extra.get('state'),
        'raw_json': extra.get('raw_json'),
        'project_id': extra.get('project_id'),
        'company_id': extra.get('company_id'),
        'signal_type': extra.get('signal_type', 'news'),
        'strength': extra.get('strength', 0.5),
        'normalized': extra.get('normalized', False),
        'created_at': now_ts(),
    }


def make_lead(project_id, company_id, **extra):
    return {
        'id': new_id(),
        'project_id': project_id,
        'company_id': company_id,
        'contact_id': extra.get('contact_id'),
        'score': extra.get('score', 0.0),
        'score_components': extra.get('score_components'),
        'grade': extra.get('grade', 'C'),
        'status': extra.get('status', 'new'),
        'assigned_to': extra.get('assigned_to'),
        'region': extra.get('region'),
        'next_action': extra.get('next_action'),
        'created_at': now_ts(),
        'updated_at': now_ts(),
    }


def make_outcome(lead_id, outcome_type, **extra):
    return {
        'id': new_id(),
        'lead_id': lead_id,
        'outcome_type': outcome_type,
        'notes': extra.get('notes'),
        'revenue': extra.get('revenue'),
        'created_at': now_ts(),
    }
