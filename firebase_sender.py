import firebase_admin
from firebase_admin import credentials, messaging
import os

# Load Firebase Admin key
cred = credentials.Certificate("firebase-key.json")
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)

def send_incoming_tx_notification(address, amount, inr_value):
    message = messaging.Message(
        notification=messaging.Notification(
            title="💰 Incoming Transaction",
            body=f"You received {amount:.4f} MATIC (~₹{inr_value:.2f})"
        ),
        topic=address.lower()  # Device must subscribe to this topic
    )

    try:
        response = messaging.send(message)
        print(f"✅ Push Notification Sent → {response}")
    except Exception as e:
        print(f"⚠️ Notification Error: {e}")
