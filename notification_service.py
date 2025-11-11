# notification_service.py
from pyfcm import FCMNotification
import sqlite3
from pathlib import Path

# SQLite database (same folder structure used in main.py)
DB_PATH = Path("secure/aurumra.db")

# ✅ IMPORTANT: Replace with your Firebase Server Key
FIREBASE_SERVER_KEY = "YOUR_SERVER_KEY_HERE"

# Initialize FCM client
push_service = FCMNotification(api_key=FIREBASE_SERVER_KEY)


def register_tokens(tokens):
    """
    Store FCM device tokens in SQLite database.
    Avoid duplicates using INSERT OR IGNORE.
    """
    if not tokens:
        return {"registered": 0}

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS device_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE
        )
    """)

    for token in tokens:
        try:
            cur.execute("INSERT OR IGNORE INTO device_tokens (token) VALUES (?)", (token,))
        except Exception:
            pass

    conn.commit()
    conn.close()

    return {"registered": len(tokens)}


def broadcast_transaction_notification(title, message, data=None):
    """
    Send a push notification to ALL registered devices.
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT token FROM device_tokens")
    rows = cur.fetchall()
    conn.close()

    tokens = [r[0] for r in rows]

    if not tokens:
        return {"status": "no_device_tokens", "sent": 0}

    result = push_service.notify_multiple_devices(
        registration_ids=tokens,
        message_title=title,
        message_body=message,
        data_message=data or {}
    )

    return {
        "status": "sent",
        "target_count": len(tokens),
        "fcm_response": result
    }
