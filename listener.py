# listener.py — Incoming TX watcher (Polygon Amoy) + Push
# - Polls Covalent for each wallet in DB
# - Stores native MATIC value to wallet.db -> transactions table
# - Sends push via Expo (token stored per-wallet in devices table)
# - Loop interval: 15s

import os
import time
import requests
import sqlite3
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

COVALENT_API_KEY = os.getenv("COVALENT_API_KEY")
BASE_URL = "https://api.covalenthq.com/v1"
CHAIN_ID = "80002"  # Polygon Amoy

DB_PATH = "wallet.db"

def db():
    return sqlite3.connect(DB_PATH)

def ensure_schema():
    conn = db()
    cur = conn.cursor()
    # wallets table may already be created by SQLAlchemy; ensure minimal columns for address lookups
    cur.execute("""
        CREATE TABLE IF NOT EXISTS wallets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT UNIQUE,
            encrypted_private_key TEXT,
            wallet_password_hash TEXT,
            created_at TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            wallet_address TEXT PRIMARY KEY,
            expo_token TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            hash TEXT PRIMARY KEY,
            address TEXT,
            direction TEXT,   -- 'IN' or 'OUT' (we store only IN here)
            amount REAL,      -- native units (MATIC)
            value_raw TEXT,   -- wei as string
            symbol TEXT,      -- 'MATIC'
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

def get_expo_token(wallet_address: str):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT expo_token FROM devices WHERE wallet_address = ?", (wallet_address.lower(),))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def send_incoming_tx_notification(wallet_address: str, amount: float, inr_value: float):
    expo_token = get_expo_token(wallet_address)
    if not expo_token:
        print(f"⚠️ No device registered for notifications: {wallet_address}")
        return

    message = {
        "to": expo_token,
        "sound": "default",
        "title": "💰 Incoming Transaction",
        "body": f"{amount:.6f} MATIC received (~₹{round(inr_value, 2)})",
        "priority": "high"
    }

    try:
        r = requests.post("https://api.expo.dev/v2/push/send", json=message, timeout=10)
        print("📨 Push API response:", r.text)
    except Exception as e:
        print("⚠️ Push send error:", e)

def get_matic_price_in_inr() -> float:
    try:
        r = requests.get("https://api.coinbase.com/v2/prices/MATIC-INR/spot", timeout=10).json()
        return float(r["data"]["amount"])
    except Exception:
        return 0.0

def check_incoming_transactions(address: str):
    url = f"{BASE_URL}/{CHAIN_ID}/address/{address}/transactions_v3/"
    params = {"key": COVALENT_API_KEY}
    try:
        r = requests.get(url, params=params, timeout=20).json()
    except Exception as e:
        print("⚠️ Covalent error:", e)
        return []

    if "data" not in r or "items" not in r["data"]:
        return []

    # Keep only transactions where 'to' is our address
    return [tx for tx in r["data"]["items"] if tx.get("to_address") and tx["to_address"].lower() == address.lower()]

def insert_transaction(tx_hash: str, address: str, amount_matic: float, value_raw: str, timestamp_iso: str):
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO transactions (hash, address, direction, amount, value_raw, symbol, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (tx_hash, address.lower(), "IN", float(amount_matic), value_raw, "MATIC", timestamp_iso))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # already inserted
    finally:
        conn.close()

def monitor_wallets():
    ensure_schema()
    while True:
        conn = db()
        cur = conn.cursor()
        cur.execute("SELECT address FROM wallets")
        rows = cur.fetchall()
        conn.close()

        addresses = [row[0] for row in rows if row and row[0]]
        if not addresses:
            print("ℹ️ No wallets in DB yet.")
            time.sleep(15)
            continue

        for address in addresses:
            print(f"🔍 Checking wallet: {address}")
            incoming = check_incoming_transactions(address)

            for tx in incoming:
                tx_hash = tx.get("tx_hash")
                value_raw = str(tx.get("value", "0"))
                amount = int(value_raw) / 10**18  # wei -> MATIC
                # Covalent returns RFC3339; normalize to ISO without Z
                ts_raw = tx.get("block_signed_at", "")
                timestamp = ts_raw.replace("Z", "") if ts_raw else datetime.utcnow().isoformat(timespec="seconds")

                # Insert if new
                insert_transaction(tx_hash, address, amount, value_raw, timestamp)

                # INR conversion + Push
                price = get_matic_price_in_inr()
                inr_value = amount * price
                send_incoming_tx_notification(address, amount, inr_value)

                print(f"✅ Incoming for {address}: {amount:.6f} MATIC (~₹{inr_value:.2f})  {tx_hash}")

        print("⏳ Waiting 15s...\n")
        time.sleep(15)

if __name__ == "__main__":
    monitor_wallets()
