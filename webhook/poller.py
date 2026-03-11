"""
PIPELINE POLLER
================
Connects to Oracle DB
Polls for PENDING webhook events
Hands each event to Orchestrator
"""

import oracledb
import asyncio
import logging
import sys
import os

# Add parent folder to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.config import DB_USER, DB_PASSWORD, DB_DSN

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 5


def get_connection():
    return oracledb.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        dsn=DB_DSN,
        config_dir=os.getenv("DB_WALLET_DIR"),
        wallet_location=os.getenv("DB_WALLET_DIR"),
        wallet_password=os.getenv("DB_WALLET_PASSWORD")
    )


def test_connection():
    """Test DB connection works"""
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM github_webhook_events")
        count = cur.fetchone()[0]
        cur.close()
        conn.close()
        log.info(f"✅ DB Connected! Total events in table: {count}")
        return True
    except Exception as e:
        log.error(f"❌ DB Connection failed: {e}")
        return False


def fetch_pending(conn) -> list:
    cur = conn.cursor()
    cur.execute("""
        SELECT id, event_type, raw_payload
        FROM github_webhook_events
        WHERE status = 'PENDING'
        ORDER BY created_at ASC
        FETCH FIRST 5 ROWS ONLY
    """)
    cols = [c[0].lower() for c in cur.description]
    rows = [dict(zip(cols, row)) for row in cur.fetchall()]
    cur.close()
    return rows


def set_status(conn, event_id: int, status: str):
    cur = conn.cursor()
    cur.execute("""
        UPDATE github_webhook_events
        SET status = :status
        WHERE id = :id
    """, {"status": status, "id": event_id})
    conn.commit()
    cur.close()


async def process_event(event: dict):
    """Hand off to Orchestrator"""
    from orchestrator.orchestrator import OrchestratorAgent
    orchestrator = OrchestratorAgent()
    ctx = await orchestrator.run(event)
    return ctx


async def main_loop():
    log.info("🚀 AutoDoc Poller Started")

    # Test connection first
    if not test_connection():
        log.error("Cannot start — DB connection failed!")
        return

    log.info(f"Polling every {POLL_INTERVAL_SECONDS} seconds...")

    while True:
        try:
            conn = get_connection()
            events = fetch_pending(conn)

            if events:
                log.info(f"📥 Found {len(events)} new event(s)")
                for event in events:
                    set_status(conn, event["id"], "PROCESSING")
                    try:
                        ctx = await process_event(event)
                        final = "DONE" if ctx.status == "DONE" else "ERROR"
                        set_status(conn, event["id"], final)
                        log.info(f"{'✅' if final == 'DONE' else '❌'} Event {event['id']} → {final}")
                    except Exception as e:
                        set_status(conn, event["id"], "ERROR")
                        log.error(f"Event {event['id']} failed: {e}")

            conn.close()

        except Exception as e:
            log.error(f"DB error: {e}")

        await asyncio.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    # Just test connection for now
    test_connection()