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


BTR_PLAYBOOK = {
    "name": "btr_cre",
    "description": (
        "Build-to-Rent and broader commercial real estate intelligence. "
        "Encodes how BTR developers, capital allocators, land brokers, and "
        "GCs actually behave so generated outreach reads like a peer who "
        "knows the market — not a templated SDR."
    ),
    "market_focus": "build_to_rent, single_family_rental, horizontal_multifamily, cre_land",
}

BTR_ENTRIES = [
    # ---------------- market_signals ----------------
    {
        "category": "market_signals",
        "title": "Land entitlement velocity spike",
        "description": (
            "When a developer files multiple PUD or rezoning applications in "
            "the same submarket within a quarter, they are pre-positioning a "
            "pipeline 12–18 months ahead of vertical construction. This is "
            "earlier and more reliable than building permits."
        ),
        "when_to_use": "Public records show ≥2 entitlement filings in one MSA inside 90 days.",
        "message_angles": ["timely_observation", "market_pattern", "curiosity"],
        "example_phrases": [
            "Saw the second PUD filing in {submarket} this quarter — looks like you're stacking a 2027 pipeline.",
            "Two entitlement filings in 90 days usually means a horizontal program, not a one-off.",
        ],
        "anti_patterns": [
            "Congrats on the new project!",
            "I see you're growing in {city}.",
        ],
        "confidence": 0.9,
    },
    {
        "category": "market_signals",
        "title": "BTR-specific listing language shift",
        "description": (
            "Land listings flipping from 'multifamily zoned' to 'BTR-ready' "
            "or 'horizontal density' indicate the broker community is "
            "actively repricing for cottage / townhome yield assumptions."
        ),
        "when_to_use": "New land comps in target MSA mention BTR yield, density bonuses, or rent comps.",
        "message_angles": ["market_pattern", "point_of_view"],
        "example_phrases": [
            "Brokers in {market} are starting to list with BTR-yield language — pricing is moving before deals print.",
        ],
        "anti_patterns": ["The BTR market is hot right now."],
        "confidence": 0.85,
    },
    {
        "category": "market_signals",
        "title": "Supply constraint via lot deliveries",
        "description": (
            "Finished-lot deliveries lag entitlements by 9–14 months. A "
            "drop in finished lots while entitlements stay flat predicts "
            "near-term pricing power for anyone holding paper lots."
        ),
        "when_to_use": "Quarterly lot delivery counts decline two quarters in a row in the target MSA.",
        "message_angles": ["light_insight", "point_of_view"],
        "example_phrases": [
            "Finished-lot deliveries in {msa} dropped two quarters running — paper-lot holders are quietly winning.",
        ],
        "anti_patterns": ["Supply is tight everywhere."],
        "confidence": 0.8,
    },
    {
        "category": "market_signals",
        "title": "Insurance reset on new construction",
        "description": (
            "BTR pro formas are increasingly being broken by insurance "
            "re-rates rather than rate caps. A carrier exit in a state is "
            "often the first domino — it shows up in pro forma assumptions "
            "before it shows up in trade press."
        ),
        "when_to_use": "Carrier exit, large rate filing, or reinsurance pullback in the operator's footprint.",
        "message_angles": ["relevant_challenge", "curiosity"],
        "example_phrases": [
            "Curious how the {carrier} pullback in {state} is hitting your stabilized assumptions.",
        ],
        "anti_patterns": ["Insurance is a challenge."],
        "confidence": 0.9,
    },

    # ---------------- developer_behavior ----------------
    {
        "category": "developer_behavior",
        "title": "Pipeline-before-balance-sheet pattern",
        "description": (
            "Mid-size BTR developers typically tie up land 12–24 months "
            "before they have committed equity. They are quietly raising "
            "while publicly announcing groundbreakings — the announcement "
            "is the fundraise, not the finish line."
        ),
        "when_to_use": "Developer announces a new community or breaks ground on a community of >150 units.",
        "message_angles": ["curiosity", "market_pattern"],
        "example_phrases": [
            "The {project} groundbreaking usually means the next round of capital is being lined up — not that it's already closed.",
        ],
        "anti_patterns": ["Congrats on breaking ground!"],
        "confidence": 0.85,
    },
    {
        "category": "developer_behavior",
        "title": "Hiring as an org-chart tell",
        "description": (
            "When a BTR sponsor hires a Director of Construction or VP of "
            "Land before a Director of Asset Management, they are still in "
            "growth-by-development mode. The reverse order signals a pivot "
            "to operate-and-hold or a pending portfolio sale."
        ),
        "when_to_use": "Visible role openings or recent hires at the operator.",
        "message_angles": ["curiosity", "point_of_view"],
        "example_phrases": [
            "Two land hires before an AM hire usually means the next 24 months are still about pipeline, not stabilization.",
        ],
        "anti_patterns": ["I see you're hiring."],
        "confidence": 0.8,
    },
    {
        "category": "developer_behavior",
        "title": "GC swap mid-program",
        "description": (
            "When a developer changes general contractor mid-program, it's "
            "almost never about price — it's about schedule slippage that "
            "is breaking the lease-up window. That schedule risk shows up "
            "in capital partner conversations within ~6 weeks."
        ),
        "when_to_use": "Permit records or LinkedIn posts show a GC change on an active community.",
        "message_angles": ["curiosity", "relevant_challenge"],
        "example_phrases": [
            "GC swaps mid-program almost always trace back to lease-up timing, not unit cost — curious which side of that you're managing for.",
        ],
        "anti_patterns": ["Saw your new GC partnership!"],
        "confidence": 0.75,
    },

    # ---------------- capital_markets_behavior ----------------
    {
        "category": "capital_markets_behavior",
        "title": "Equity dry powder rotation into BTR",
        "description": (
            "Allocators with multifamily mandates have been quietly "
            "expanding language to include BTR / SFR. The tell is fund "
            "documents and annual letters, not press releases. Once two "
            "named LPs in a region update their mandate language, regional "
            "operators see term sheets within ~90 days."
        ),
        "when_to_use": "Capital partner of a target operator publishes a strategy update or annual letter.",
        "message_angles": ["light_insight", "market_pattern"],
        "example_phrases": [
            "{LP}'s annual letter quietly added BTR to its mandate — usually a ~90-day lead indicator on term sheets in the region.",
        ],
        "anti_patterns": ["Capital is flowing into BTR."],
        "confidence": 0.85,
    },
    {
        "category": "capital_markets_behavior",
        "title": "Debt structure migration to bridge-to-agency",
        "description": (
            "When BTR sponsors shift from construction-perm to bridge-to-"
            "agency takeouts, they are betting on a 24-month rate window "
            "and need lease-up to land precisely. Underwriting becomes "
            "intolerant of a 60-day delay."
        ),
        "when_to_use": "Operator publicly references bridge debt, agency takeout, or DSCR-driven structures.",
        "message_angles": ["point_of_view", "relevant_challenge"],
        "example_phrases": [
            "Bridge-to-agency only works if lease-up lands inside the rate window — the math gets brutal at 60 days late.",
        ],
        "anti_patterns": ["Debt markets are tough."],
        "confidence": 0.8,
    },
    {
        "category": "capital_markets_behavior",
        "title": "Programmatic JV fatigue",
        "description": (
            "By year two of a programmatic JV, sponsors are usually "
            "negotiating a second equity source as a hedge against a "
            "single LP's pacing changes. This rarely shows up publicly "
            "until it has already happened."
        ),
        "when_to_use": "Sponsor is 18+ months into a publicly announced programmatic JV.",
        "message_angles": ["curiosity", "market_pattern"],
        "example_phrases": [
            "Most programmatic JVs we watch start sourcing a second equity line around month 18 — pacing protection more than anything.",
        ],
        "anti_patterns": ["How is the JV going?"],
        "confidence": 0.75,
    },

    # ---------------- timing_triggers ----------------
    {
        "category": "timing_triggers",
        "title": "Post-groundbreaking 30-day window",
        "description": (
            "The 30 days after a groundbreaking is the only period where a "
            "developer is publicly committed but privately re-running cost "
            "models. Outreach landing in this window gets read."
        ),
        "when_to_use": "Within 30 days of an announced groundbreaking.",
        "message_angles": ["timely_observation", "curiosity"],
        "example_phrases": [
            "Saw the {project} groundbreaking three weeks back — usually the window where the cost model gets a quiet rerun.",
        ],
        "anti_patterns": ["Following up on your project."],
        "confidence": 0.85,
    },
    {
        "category": "timing_triggers",
        "title": "Quarter-end pipeline reviews",
        "description": (
            "BTR shops do internal pipeline reviews in the last two weeks "
            "of each quarter. New questions surface internally during this "
            "window — which is when an outside perspective lands hardest."
        ),
        "when_to_use": "Final two weeks of any calendar quarter.",
        "message_angles": ["curiosity", "low_pressure_starter"],
        "example_phrases": [
            "Quarter-end usually surfaces the questions nobody had time for in week one — happy to be a sounding board if it's useful.",
        ],
        "anti_patterns": ["End of quarter — let's connect!"],
        "confidence": 0.7,
    },
    {
        "category": "timing_triggers",
        "title": "Capital partner annual letter",
        "description": (
            "When the operator's named capital partner publishes its "
            "annual letter, the operator spends the following month "
            "re-translating that strategy into pipeline decisions."
        ),
        "when_to_use": "Within 30 days of a capital partner's published annual letter or strategy update.",
        "message_angles": ["light_insight", "curiosity"],
        "example_phrases": [
            "{LP}'s letter dropped last week — curious which line in it is driving the most internal debate on your side.",
        ],
        "anti_patterns": ["Did you see the news?"],
        "confidence": 0.8,
    },

    # ---------------- outreach_angles ----------------
    {
        "category": "outreach_angles",
        "title": "Pattern recognition over flattery",
        "description": (
            "BTR operators are pitched 3–6 times a week. The only opener "
            "that breaks through is one that names a pattern they have "
            "noticed but haven't articulated yet."
        ),
        "when_to_use": "Anytime you can name a real, observable pattern across similar operators.",
        "message_angles": ["market_pattern", "point_of_view"],
        "example_phrases": [
            "The shops that opened a second southeast market in 2024 are all running the same lease-up playbook — curious if you're seeing the same.",
        ],
        "anti_patterns": [
            "Love what you're building.",
            "Your LinkedIn caught my eye.",
        ],
        "confidence": 0.9,
    },
    {
        "category": "outreach_angles",
        "title": "Curiosity grounded in a dated event",
        "description": (
            "Curiosity works only when it is anchored in something dated "
            "and observable. Floating curiosity reads as a pitch in "
            "disguise."
        ),
        "when_to_use": "When you have a specific, recent, dated event you can point at.",
        "message_angles": ["curiosity"],
        "example_phrases": [
            "Saw the {project} permit go through last Tuesday — curious whether the cottage mix changed from the original entitlement.",
        ],
        "anti_patterns": ["Curious to learn more about your business."],
        "confidence": 0.85,
    },
    {
        "category": "outreach_angles",
        "title": "Timing-based co-conspirator framing",
        "description": (
            "Position yourself as someone watching the same window the "
            "operator is, not as someone selling into it. Shared "
            "observation > pitched solution."
        ),
        "when_to_use": "When market timing is the actual story.",
        "message_angles": ["timely_observation", "market_pattern"],
        "example_phrases": [
            "We're watching the same 90-day window on {market} — figured it was worth comparing notes.",
        ],
        "anti_patterns": ["I'd love to introduce our solution."],
        "confidence": 0.8,
    },

    # ---------------- messaging_principles ----------------
    {
        "category": "messaging_principles",
        "title": "Name the submarket, not the metro",
        "description": (
            "BTR operators think in submarkets (Wesley Chapel, Buckeye, "
            "Greer) — not metros (Tampa, Phoenix, Greenville). Naming the "
            "metro reads as outsider; naming the submarket reads as peer."
        ),
        "when_to_use": "Always when you have submarket-level data.",
        "message_angles": ["market_pattern", "timely_observation"],
        "example_phrases": [
            "What's happening in Buckeye looks different than the rest of the West Valley — curious how you're sizing it.",
        ],
        "anti_patterns": ["The Phoenix market is interesting."],
        "confidence": 0.9,
    },
    {
        "category": "messaging_principles",
        "title": "Reference the deal, not the company",
        "description": (
            "Specific deals (community names, parcel sizes, unit counts) "
            "outperform company-level references. The deal is what the "
            "operator's brain is currently loaded with."
        ),
        "when_to_use": "Always when you have a specific community, parcel, or deal name.",
        "message_angles": ["timely_observation", "curiosity"],
        "example_phrases": [
            "On the 212-unit cottage program in Greer — curious if you stuck with detached or pivoted to the duplex mix.",
        ],
        "anti_patterns": ["I see your firm is doing great work."],
        "confidence": 0.9,
    },
    {
        "category": "messaging_principles",
        "title": "Use yield language sparingly and correctly",
        "description": (
            "Yield-on-cost, untrended yield, and stabilized cap are useful "
            "anchors but only when used precisely. Misusing them is "
            "instantly disqualifying."
        ),
        "when_to_use": "When you can be precise about which metric you mean.",
        "message_angles": ["point_of_view"],
        "example_phrases": [
            "The untrended YOC math on horizontal product is moving faster than the stabilized cap — that gap is where the next argument lives.",
        ],
        "anti_patterns": ["Higher returns!", "Better cap rates."],
        "confidence": 0.85,
    },

    # ---------------- anti_patterns ----------------
    {
        "category": "anti_patterns",
        "title": "Generic congratulations",
        "description": "Treat every 'congrats on…' as a disqualifier.",
        "when_to_use": "Never.",
        "message_angles": [],
        "example_phrases": [],
        "anti_patterns": [
            "Congrats on the recent groundbreaking!",
            "Congrats on the new role!",
            "Congrats on the funding!",
        ],
        "confidence": 0.95,
    },
    {
        "category": "anti_patterns",
        "title": "SDR voice tells",
        "description": (
            "Phrases that instantly mark the sender as an outsourced SDR "
            "and not a peer in the market."
        ),
        "when_to_use": "Never.",
        "message_angles": [],
        "example_phrases": [],
        "anti_patterns": [
            "I hope this finds you well",
            "I wanted to reach out",
            "Quick question for you",
            "circling back",
            "touching base",
            "synergies",
            "Just following up",
        ],
        "confidence": 0.95,
    },
    {
        "category": "anti_patterns",
        "title": "Fake personalization from weak facts",
        "description": (
            "Anchoring an opener on the prospect's title, company, or city "
            "alone. These are public, generic, and signal zero research."
        ),
        "when_to_use": "Never.",
        "message_angles": [],
        "example_phrases": [],
        "anti_patterns": [
            "Noticed you're VP at {company} in {city}…",
            "As a leader in BTR…",
        ],
        "confidence": 0.9,
    },

    # ---------------- conversation_openers ----------------
    {
        "category": "conversation_openers",
        "title": "Submarket pattern opener",
        "description": "Lead with a submarket-specific pattern observation.",
        "when_to_use": "When you have submarket evidence (entitlements, comps, hiring).",
        "message_angles": ["market_pattern", "timely_observation"],
        "example_phrases": [
            "Two PUDs in {submarket} this quarter is not a coincidence — looks like you're stacking a 2027 pipeline.",
            "Lot deliveries in {submarket} dropped two quarters running — the paper-lot holders are quietly in the catbird seat.",
        ],
        "anti_patterns": [],
        "confidence": 0.9,
    },
    {
        "category": "conversation_openers",
        "title": "Capital window opener",
        "description": "Open by naming the capital window the operator is in.",
        "when_to_use": "When LP letters, debt structure, or programmatic JV details are visible.",
        "message_angles": ["light_insight", "curiosity"],
        "example_phrases": [
            "Bridge-to-agency takeouts only forgive a 30-day lease-up slip — curious how you're hedging that on {project}.",
            "{LP}'s letter quietly opened the BTR mandate — usually a 90-day lead indicator on regional term sheets.",
        ],
        "anti_patterns": [],
        "confidence": 0.85,
    },
    {
        "category": "conversation_openers",
        "title": "Specific-deal opener",
        "description": "Reference a specific community, parcel, or filing by name.",
        "when_to_use": "Whenever a deal-level fact is in the stored signals.",
        "message_angles": ["timely_observation", "curiosity"],
        "example_phrases": [
            "On the {project} filing — did the cottage mix end up where the original entitlement had it?",
            "Saw the {project} GC change last month. That usually traces back to lease-up timing more than cost.",
        ],
        "anti_patterns": [],
        "confidence": 0.9,
    },
]


def seed_btr_playbook_if_empty() -> int:
    """Seed the BTR/CRE industry playbook once. Idempotent."""
    existing = repo.get_playbook_by_name(BTR_PLAYBOOK["name"])
    if existing:
        return 0
    pb = repo.create_playbook(BTR_PLAYBOOK)
    for entry in BTR_ENTRIES:
        repo.create_playbook_entry({**entry, "playbook_id": pb["id"]})
    print(f"[SignalStack] Seeded BTR playbook with {len(BTR_ENTRIES)} entries")
    return len(BTR_ENTRIES)


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
