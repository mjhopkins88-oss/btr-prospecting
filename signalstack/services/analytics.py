"""
SignalStack analytics — minimal but real (no fake numbers).
Computed on demand against the live tables.
"""
from db import get_db


def overview() -> dict:
    conn = get_db()
    try:
        cur = conn.cursor()

        cur.execute("SELECT status, COUNT(*) FROM ss_prospects GROUP BY status")
        prospects_by_status = {r[0]: r[1] for r in cur.fetchall()}

        cur.execute("SELECT COUNT(*) FROM ss_messages WHERE status = 'sent'")
        sent = cur.fetchone()[0] or 0

        cur.execute("""
            SELECT COUNT(DISTINCT m.id)
            FROM ss_messages m
            JOIN ss_message_outcomes o ON o.message_id = m.id
            WHERE m.status = 'sent' AND o.outcome IN ('replied', 'positive_reply', 'meeting_booked')
        """)
        replied = cur.fetchone()[0] or 0

        cur.execute("""
            SELECT COUNT(DISTINCT m.id)
            FROM ss_messages m
            JOIN ss_message_outcomes o ON o.message_id = m.id
            WHERE m.status = 'sent' AND o.outcome IN ('positive_reply', 'meeting_booked')
        """)
        positive = cur.fetchone()[0] or 0

        cur.execute("""
            SELECT COUNT(DISTINCT m.id)
            FROM ss_messages m
            JOIN ss_message_outcomes o ON o.message_id = m.id
            WHERE o.outcome = 'meeting_booked'
        """)
        meetings = cur.fetchone()[0] or 0

        # Top performing message types (by positive outcome rate).
        cur.execute("""
            SELECT m.message_type,
                   COUNT(DISTINCT m.id) AS sent_n,
                   SUM(CASE WHEN o.outcome IN ('positive_reply','meeting_booked') THEN 1 ELSE 0 END) AS positive_n
            FROM ss_messages m
            LEFT JOIN ss_message_outcomes o ON o.message_id = m.id
            WHERE m.status = 'sent' AND m.message_type IS NOT NULL
            GROUP BY m.message_type
        """)
        top_types = []
        for mt, sent_n, pos_n in cur.fetchall():
            sent_n = sent_n or 0
            pos_n = pos_n or 0
            top_types.append({
                "message_type": mt,
                "sent": sent_n,
                "positive": pos_n,
                "rate": round((pos_n / sent_n), 3) if sent_n else 0.0,
            })
        top_types.sort(key=lambda x: x["rate"], reverse=True)

        # Top signal types by association with positive outcomes.
        cur.execute("""
            SELECT s.type,
                   COUNT(DISTINCT ms.message_id) AS used_n,
                   SUM(CASE WHEN o.outcome IN ('positive_reply','meeting_booked') THEN 1 ELSE 0 END) AS positive_n
            FROM ss_signals s
            JOIN ss_message_signals ms ON ms.signal_id = s.id
            LEFT JOIN ss_message_outcomes o ON o.message_id = ms.message_id
            GROUP BY s.type
        """)
        top_signals = []
        for st, used_n, pos_n in cur.fetchall():
            used_n = used_n or 0
            pos_n = pos_n or 0
            top_signals.append({
                "signal_type": st,
                "used": used_n,
                "positive": pos_n,
                "rate": round((pos_n / used_n), 3) if used_n else 0.0,
            })
        top_signals.sort(key=lambda x: x["rate"], reverse=True)

        return {
            "prospects_by_status": prospects_by_status,
            "messages_sent": sent,
            "reply_rate": round(replied / sent, 3) if sent else 0.0,
            "positive_reply_rate": round(positive / sent, 3) if sent else 0.0,
            "meeting_rate": round(meetings / sent, 3) if sent else 0.0,
            "top_message_types": top_types,
            "top_signal_types": top_signals,
        }
    finally:
        conn.close()
