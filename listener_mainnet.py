# listener_mainnet.py — Polygon Mainnet Listener + Push Notifications

import os
import time
import requests
import sqlite3
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

COVALENT_API_KEY = os.getenv("COVALENT_API_KEY")
BASE_URL = "https://api.covalenthq.com/v1"
CHAIN_ID = "137"  # ✅ Polygon Mainnet

DB_PATH = "wallet.db"

def db():
    return sqlite3.connect(DB_PATH)

def ensure_schema():
    conn = db()
    cur = conn.cursor()
    
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
            direction TEXT,
            amount REAL,
            value_raw TEXT,
            symbol TEXT,
            timestamp TEXT
        )
    """)

    conn.commit()
    conn.close()

def get_expo_token(wallet_address):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT expo_token FROM devices WHERE wallet_address = ?", (wallet_address.lower(),))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def send_notification(wallet_address, amount, inr_value):
    expo_token = get_expo_token(wallet_address)
    if not expo_token:
        print(f"⚠️ No device registered for {wallet_address}")
        return

    msg = {
        "to": expo_token,
        "sound": "default",
        "title": "💰 Incoming MATIC",
        "body": f"{amount:.6f} MATIC received (~₹{round(inr_value, 2)})"
    }

    try:
        r = requests.post("https://api.expo.dev/v2/push/send", json=msg)
        print("📨 Notification Sent:", r.text)
    except Exception as e:
        print("⚠️ Notification Error:", e)

def get_matic_price_in_inr():
    try:
        r = requests.get("https://api.coinbase.com/v2/prices/MATIC-INR/spot").json()
        return float(r["data"]["amount"])
    except:
        return 0.0

def check_incoming(address):
    url = f"{BASE_URL}/{CHAIN_ID}/address/{address}/transactions_v3/"
    params = {"key": COVALENT_API_KEY}

    try:
        r = requests.get(url, params=params).json()
    except:
        return []

    items = r.get("data", {}).get("items", [])
    return [tx for tx in items if tx.get("to_address", "").lower() == address.lower()]

def insert_tx(tx_hash, address, amount, raw, timestamp):
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO transactions (hash, address, direction, amount, value_raw, symbol, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (tx_hash, address.lower(), "IN", amount, raw, "MATIC", timestamp))
        conn.commit()
    except:
        pass
    conn.close()

def monitor():
    ensure_schema()
    while True:
        conn = db()
        cur = conn.cursor()
        cur.execute("SELECT address FROM wallets")
        rows = cur.fetchall()
        conn.close()

        for (address,) in rows:
            print(f"🔍 Checking (Mainnet): {address}")
            incoming = check_incoming(address)

            for tx in incoming:
                tx_hash = tx["tx_hash"]
                raw = tx["value"]
                amount = int(raw) / 10**18
                timestamp = tx["block_signed_at"].replace("Z", "")

                insert_tx(tx_hash, address, amount, raw, timestamp)

                price_in_inr = get_matic_price_in_inr()
                send_notification(address, amount, amount * price_in_inr)

                print(f"✅ {amount:.6f} MATIC received on Mainnet for {address}")

        print("⏳ Waiting 15s...\n")
        time.sleep(15)

if __name__ == "__main__":
    print("🚀 Listener Running — Polygon Mainnet (Live)")
    monitor()
