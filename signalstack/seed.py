"""
Seed data for SignalStack — social-selling knowledge layer + demo records.

`seed_principles_if_empty()` is invoked from schema.init_schema() so any
fresh deploy boots with a usable knowledge base. `seed_demo()` is opt-in
and idempotent enough for local exploration.
"""
from db import get_db
from . import repo


PRINCIPLES = [
    {
        "category": "trust_building",
        "principle_name": "Earn the right to message",
        "description": (
            "On LinkedIn, trust comes before pitch. Open with something the "
            "recipient already knows is true about themselves or their work."
        ),
        "practical_use_case": "First-touch outreach to a cold but warm-ish prospect.",
        "allowed_contexts": "Verifiable public role, post, or company event.",
        "disallowed_contexts": "Anything inferred about personal life.",
        "example_pattern": "Saw your team is hiring two underwriters in Texas — that usually means a portfolio shift.",
        "anti_pattern": "Hope this finds you well! I help companies like yours…",
    },
    {
        "category": "curiosity",
        "principle_name": "Open a loop, don't close one",
        "description": "Curiosity beats persuasion. Ask the question they haven't been asked.",
        "practical_use_case": "When you have an insight but no obvious ask.",
        "allowed_contexts": "When you genuinely don't know the answer.",
        "disallowed_contexts": "Manufactured curiosity that's actually a pitch.",
        "example_pattern": "Curious how you're thinking about reinsurance capacity now that the Q3 renewals are settling.",
        "anti_pattern": "Curious if you'd be open to a 15-min call this week?",
    },
    {
        "category": "relevance",
        "principle_name": "Tie to a specific signal",
        "description": "Every opener should reference a specific, observable thing.",
        "practical_use_case": "Always.",
        "allowed_contexts": "Any stored signal marked safe_to_reference.",
        "disallowed_contexts": "Generic congratulations or vague compliments.",
        "example_pattern": "Noticed the new Charlotte office — second southeast location this year.",
        "anti_pattern": "Congrats on your recent success!",
    },
    {
        "category": "specificity",
        "principle_name": "Concrete > clever",
        "description": "Numbers, places, names, and timeframes outperform adjectives.",
        "practical_use_case": "Whenever you have a stored fact you can name.",
        "allowed_contexts": "Stored facts only.",
        "disallowed_contexts": "Invented metrics.",
        "example_pattern": "Your post on the SOC 2 Type II rollout last week.",
        "anti_pattern": "Your amazing leadership.",
    },
    {
        "category": "social_proof",
        "principle_name": "Name a peer pattern, not a logo wall",
        "description": "Reference a pattern across similar operators, not customer logos.",
        "practical_use_case": "When offering perspective.",
        "allowed_contexts": "Patterns the sender has actually observed.",
        "disallowed_contexts": "Made-up case studies.",
        "example_pattern": "A few teams at similar AUM are wrestling with the same trade-off.",
        "anti_pattern": "We work with Acme, Globex, and Initech.",
    },
    {
        "category": "timing",
        "principle_name": "Reach when context is fresh",
        "description": "Reference recent, dated events; avoid stale 'congrats' months later.",
        "practical_use_case": "Within 2-3 weeks of the signal.",
        "allowed_contexts": "Recent posts, recent role changes, recent news.",
        "disallowed_contexts": "Anniversaries, birthdays, generic milestones.",
        "example_pattern": "Saw the announcement this morning.",
        "anti_pattern": "Congrats on your work anniversary!",
    },
    {
        "category": "objection_softening",
        "principle_name": "Make 'no' easy",
        "description": "Lower stakes. A reply costs nothing; a meeting costs everything.",
        "practical_use_case": "First touch.",
        "allowed_contexts": "Always for cold outreach.",
        "disallowed_contexts": "When already in active conversation.",
        "example_pattern": "No agenda — happy to be wrong here.",
        "anti_pattern": "Looking for 30 minutes on your calendar this week.",
    },
    {
        "category": "conversational_tone",
        "principle_name": "Write like a peer, not a vendor",
        "description": "Cadence of a colleague — short sentences, no marketing voice.",
        "practical_use_case": "All messages.",
        "allowed_contexts": "Always.",
        "disallowed_contexts": "Boilerplate corporate phrasing.",
        "example_pattern": "Quick thought — feel free to ignore.",
        "anti_pattern": "I wanted to take a moment to reach out and introduce myself.",
    },
    {
        "category": "authority_without_chest_beating",
        "principle_name": "Show, don't claim",
        "description": "Demonstrate insight through observation, not credentials.",
        "practical_use_case": "When credibility matters.",
        "allowed_contexts": "Observations grounded in real patterns.",
        "disallowed_contexts": "Self-introductions and resumes.",
        "example_pattern": "Usually when underwriting tightens like this, the renewal mix shifts within a quarter.",
        "anti_pattern": "As a 20-year industry veteran…",
    },
    {
        "category": "anti_template",
        "principle_name": "If it could be sent to anyone, send it to no one",
        "description": "Every sentence should fail the swap test: replace the name and it should no longer make sense.",
        "practical_use_case": "Always.",
        "allowed_contexts": "Always.",
        "disallowed_contexts": "Always.",
        "example_pattern": "Specific to this prospect's stored facts.",
        "anti_pattern": "I help companies like yours optimize growth.",
    },
]


def seed_principles_if_empty() -> int:
    """Insert the canonical principles list once, only if table is empty."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM ss_social_principles")
        n = cur.fetchone()[0]
    finally:
        conn.close()
    if n:
        return 0
    for p in PRINCIPLES:
        repo.create_principle(p)
    print(f"[SignalStack] Seeded {len(PRINCIPLES)} social-selling principles")
    return len(PRINCIPLES)


def seed_demo() -> dict:
    """Optional: create one company + prospect + signals + profile context."""
    company = repo.create_company({
        "name": "Northwind Mutual",
        "website": "northwind.example",
        "industry": "Specialty Insurance",
        "location": "Hartford, CT",
        "notes": "Mid-market specialty carrier expanding into the southeast.",
    })
    prospect = repo.create_prospect({
        "full_name": "Dana Reyes",
        "linkedin_url": "https://www.linkedin.com/in/dana-reyes-demo",
        "company_id": company["id"],
        "company_name": company["name"],
        "title": "VP, Underwriting",
        "industry": "Specialty Insurance",
        "location": "Hartford, CT",
        "status": "researching",
    })
    repo.create_signal({
        "prospect_id": prospect["id"], "type": "company_expansion",
        "source": "public_web",
        "text": "Northwind opened a Charlotte office in Q3.",
        "safe_to_reference": True,
    })
    repo.create_signal({
        "prospect_id": prospect["id"], "type": "post_topic",
        "source": "linkedin_paste",
        "text": "Posted about reinsurance capacity tightening for casualty lines.",
        "safe_to_reference": True,
    })
    repo.upsert_profile_context(prospect["id"], {
        "linkedin_url": prospect["linkedin_url"],
        "headline": "VP Underwriting @ Northwind Mutual | Specialty Casualty",
        "current_role": "VP, Underwriting",
        "current_company": "Northwind Mutual",
        "featured_topics": "casualty underwriting, reinsurance, portfolio strategy",
        "notable_language_patterns": "concise, data-forward, dry humor",
    })
    return {"company": company, "prospect": prospect}
