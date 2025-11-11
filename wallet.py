# wallet.py — Aurumra Wallet backend (Merged, Clean)
# - 12-word BIP39 -> m/44'/60'/0'/0/0 (MetaMask compatible)
# - Private key encrypted with Fernet; Fernet key stored in DB
# - Wallet password hashed with Argon2 (verify on load)
# - SQLite via SQLAlchemy (DB unified to wallet.db)
# - Fee policy: 0.01% internal, 0.02% external
# - send_eth / send_erc20 / send_nft forward service fee to ADMIN_WALLET_COMMON (best-effort)
# - get_w3(chain_name) returns (w3, chain_dict)
# - NEW: Polygon (Amoy) added; NEW: get_transaction_history() returning native values (MATIC)

import os
import json
from decimal import Decimal
from datetime import datetime
from typing import Optional, Tuple, Any, Dict, List

from dotenv import load_dotenv
load_dotenv()

from web3 import Web3
from eth_account import Account
from mnemonic import Mnemonic

# crypto + hashing
from cryptography.fernet import Fernet
from argon2 import PasswordHasher, exceptions as argon2_exceptions

# SQLAlchemy
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.sql import func

# ---------------------------------
# CONFIG / CONSTANTS
# ---------------------------------
INFURA_KEY = os.getenv("INFURA_KEY", "ab14f1ef8d724337acee20524cd676b9")

# ✅ Unify DB with listener: use wallet.db
DATABASE_URL = os.getenv("WALLET_DATABASE_URL", "sqlite:///./wallet.db")

# Fallback logs (JSON files)
TX_JSON_FALLBACK = os.getenv("TX_JSON_FALLBACK", "tx_log.json")
FEE_JSON_FALLBACK = os.getenv("FEE_JSON_FALLBACK", "fee_log.json")

# Treasury / admin wallet (fee receiver)
ADMIN_WALLET_COMMON = os.getenv("ADMIN_WALLET_COMMON", "0x8c7744438a061f5fcc060739de04425e495e41eb")

# Final fee policy (global)
INTERNAL_RATE = Decimal("0.0001")  # 0.01%
EXTERNAL_RATE = Decimal("0.0002")  # 0.02%
GAS_MARGIN = Decimal("1.05")

# ---------------------------------
# Chains (include Polygon Amoy as default dev; Polygon mainnet optional)
# ---------------------------------
CHAINS: Dict[str, Dict[str, Any]] = {
    # Dev default for us: Polygon Amoy (chainId 80002)
    "Polygon Amoy": {
        "rpc": "https://rpc-amoy.polygon.technology/",
        "chainId": 80002,
        "symbol": "MATIC",
        "explorer": "https://www.oklink.com/amoy/tx/",
    },
    # Optional: Polygon mainnet
    "Polygon Mainnet": {
        "rpc": "https://polygon-rpc.com/",
        "chainId": 137,
        "symbol": "MATIC",
        "explorer": "https://polygonscan.com/tx/",
    },
    # Kept for ETH testing if needed
    "Ethereum Sepolia": {
        "rpc": f"https://sepolia.infura.io/v3/{INFURA_KEY}",
        "chainId": 11155111,
        "symbol": "ETH",
        "explorer": "https://sepolia.etherscan.io/tx/",
    },
}

# Minimal ERC20 ABI
ERC20_ABI = json.loads("""[
  {"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"type":"function"},
  {"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"type":"function"},
  {"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"type":"function"},
  {"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"}
]""")

# ---------------------------------
# DB setup (SQLAlchemy)
# ---------------------------------
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class EncryptionKeyRecord(Base):
    __tablename__ = "encryption_key"
    id = Column(Integer, primary_key=True, index=True)
    key_b64 = Column(String, nullable=False)  # Fernet key (base64)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class WalletRecord(Base):
    __tablename__ = "wallets"
    id = Column(Integer, primary_key=True, index=True)
    address = Column(String, index=True, unique=True)
    encrypted_private_key = Column(Text, nullable=False)  # base64 str
    wallet_password_hash = Column(String, nullable=False) # Argon2 hash
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class FeeRecord(Base):
    __tablename__ = "fee_records"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    chain = Column(String, index=True)
    tx_hash = Column(String, index=True)
    to_address = Column(String)
    amount = Column(Float)
    service_fee = Column(Float)
    admin_wallet = Column(String)

Base.metadata.create_all(bind=engine)

# ---------------------------------
# Utilities: atomic JSON append
# ---------------------------------
def atomic_json_append(path: str, entry: dict):
    import json, os
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump([], f)
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except Exception:
        data = []
    data.append(entry)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, default=str)
    os.replace(tmp, path)

def log_fee_db(chain: str, tx_hash: str, to_address: str, amount: float, service_fee: float, admin_wallet: str):
    try:
        db = SessionLocal()
        rec = FeeRecord(
            chain=chain, tx_hash=tx_hash, to_address=to_address,
            amount=float(amount), service_fee=float(service_fee), admin_wallet=admin_wallet
        )
        db.add(rec)
        db.commit()
        db.close()
    except Exception:
        atomic_json_append(FEE_JSON_FALLBACK, {
            "timestamp": datetime.utcnow().isoformat(),
            "chain": chain, "tx_hash": tx_hash, "to": to_address,
            "amount": amount, "service_fee": service_fee, "admin_wallet": admin_wallet
        })

def log_tx_record(tx_record: dict):
    try:
        atomic_json_append(TX_JSON_FALLBACK, tx_record)
    except Exception:
        pass

# ---------------------------------
# Password & Fernet key mgmt
# ---------------------------------
ph_wallet = PasswordHasher()

def get_or_create_fernet_key() -> str:
    db = SessionLocal()
    try:
        rec = db.query(EncryptionKeyRecord).order_by(EncryptionKeyRecord.id.asc()).first()
        if rec and rec.key_b64:
            return rec.key_b64
        key_b64 = Fernet.generate_key().decode()
        rec = EncryptionKeyRecord(key_b64=key_b64)
        db.add(rec)
        db.commit()
        return key_b64
    finally:
        db.close()

def _get_fernet() -> Fernet:
    key = get_or_create_fernet_key()
    return Fernet(key.encode())

def encrypt_private_key_hex(private_hex: str) -> str:
    f = _get_fernet()
    return f.encrypt(private_hex.encode()).decode()

def decrypt_private_key_hex(enc_b64: str) -> str:
    f = _get_fernet()
    return f.decrypt(enc_b64.encode()).decode()

# ---------------------------------
# Address validation helper
# ---------------------------------
def is_valid_eth_address(addr: str) -> bool:
    if not addr or not isinstance(addr, str):
        return False
    try:
        _ = Web3.to_checksum_address(addr)
        return True
    except Exception:
        return False

# ---------------------------------
# Wallet persistence (DB)
# ---------------------------------
def save_wallet_to_db(address: str, private_key_hex: str, wallet_password: str) -> dict:
    enc = encrypt_private_key_hex(private_key_hex)
    pwd_hash = ph_wallet.hash(wallet_password)
    db = SessionLocal()
    try:
        existing = db.query(WalletRecord).filter(WalletRecord.address == address).first()
        if existing:
            existing.encrypted_private_key = enc
            existing.wallet_password_hash = pwd_hash
        else:
            rec = WalletRecord(
                address=address,
                encrypted_private_key=enc,
                wallet_password_hash=pwd_hash
            )
            db.add(rec)
        db.commit()
        return {"address": address}
    finally:
        db.close()

def get_wallet_from_db_by_password(wallet_password: str) -> dict:
    db = SessionLocal()
    try:
        for w in db.query(WalletRecord).all():
            try:
                ph_wallet.verify(w.wallet_password_hash, wallet_password)
                priv = decrypt_private_key_hex(w.encrypted_private_key)
                return {"address": w.address, "private_key": priv}
            except argon2_exceptions.VerifyMismatchError:
                continue
            except Exception:
                continue
        raise Exception("Wallet not found or incorrect wallet password")
    finally:
        db.close()

# Optional legacy file fallback
WALLET_FILE = "aurumra_wallet.json"
def create_file_fallback(wallet_data: dict):
    try:
        with open(WALLET_FILE, "w") as f:
            import json; json.dump(wallet_data, f)
    except Exception:
        pass

# ---------------------------------
# BIP39 Seed -> Account (ETH)
# ---------------------------------
def _new_mnemonic_12() -> str:
    return Mnemonic("english").generate(strength=128)  # 12 words

def _acct_from_mnemonic(mnemonic: str, path: str = "m/44'/60'/0'/0/0"):
    Account.enable_unaudited_hdwallet_features()
    return Account.from_mnemonic(mnemonic, account_path=path)

# ---------------------------------
# Public API expected by main.py
# ---------------------------------
def create_wallet(wallet_password: str) -> Dict[str, str]:
    mnemonic = _new_mnemonic_12()
    acct = _acct_from_mnemonic(mnemonic)
    address = acct.address
    private_hex = acct.key.hex() if hasattr(acct, "key") else acct._private_key.hex()

    save_wallet_to_db(address, private_hex, wallet_password)
    create_file_fallback({"address": address})

    # Default to Polygon Amoy for dev
    return {"address": address, "seed_phrase": mnemonic, "network": "Polygon Amoy"}

def restore_wallet(seed_phrase: str, wallet_password: str) -> Dict[str, str]:
    key = (seed_phrase or "").strip()
    if (key.startswith("0x") and len(key) == 66) or (len(key) == 64):
        pk = key if key.startswith("0x") else "0x" + key
        acct = Account.from_key(pk)
    else:
        try:
            acct = _acct_from_mnemonic(key)
        except Exception:
            raise ValueError("Provide a valid 12-word mnemonic or raw private key hex.")

    address = acct.address
    private_hex = acct.key.hex() if hasattr(acct, "key") else acct._private_key.hex()
    save_wallet_to_db(address, private_hex, wallet_password)
    return {"address": address, "network": "Polygon Amoy"}

def load_wallet(wallet_password: str) -> Dict[str, str]:
    try:
        return get_wallet_from_db_by_password(wallet_password)
    except Exception:
        if os.path.exists(WALLET_FILE):
            try:
                import json
                with open(WALLET_FILE, "r") as f:
                    data = json.load(f)
                if "private_key" in data:
                    return {"address": data.get("address"), "private_key": data.get("private_key")}
                raise Exception("Wallet not found or wrong wallet password")
            except Exception:
                pass
        raise

# ---------------------------------
# Web3 setup
# ---------------------------------
def _inject_poa_if_needed(w3: Web3, rpc: Optional[str] = None):
    try:
        from web3.middleware import geth_poa_middleware
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    except Exception:
        pass

def get_w3(chain_name: str) -> Tuple[Web3, Dict[str, Any]]:
    if chain_name not in CHAINS:
        raise ValueError(f"Unsupported chain: {chain_name}")
    chain = CHAINS[chain_name]
    w3 = Web3(Web3.HTTPProvider(chain["rpc"]))
    if not w3.is_connected():
        raise RuntimeError(f"Web3 not connected to {chain_name}")
    if any(x in chain["rpc"].lower() for x in ["polygon", "bsc", "matic", "avax", "sepolia", "linea"]):
        _inject_poa_if_needed(w3, chain["rpc"])
    return w3, chain

# ---------------------------------
# Gas helpers
# ---------------------------------
def _send_raw_tx_and_return_hex(w3: Web3, signed_tx_obj: Any) -> str:
    raw = getattr(signed_tx_obj, "rawTransaction", None) or getattr(signed_tx_obj, "raw_transaction", None) or signed_tx_obj
    tx_hash = w3.eth.send_raw_transaction(raw)
    try:
        return tx_hash.hex()
    except Exception:
        return str(tx_hash)

def estimate_native_tx_gas(w3: Web3, from_addr: str, to_addr: str, value_wei: int) -> Tuple[int, int]:
    obj = {"from": from_addr, "to": to_addr, "value": int(value_wei)}
    try:
        estimated = w3.eth.estimate_gas(obj)
    except Exception:
        estimated = 21000
    try:
        gas_price = w3.eth.gas_price
    except Exception:
        gas_price = int(1e9)
    estimated = int(Decimal(estimated) * GAS_MARGIN)
    return int(estimated), int(gas_price)

def estimate_contract_tx_gas(w3: Web3, tx_built: dict) -> Tuple[int, int]:
    try:
        estimated = w3.eth.estimate_gas(tx_built)
    except Exception:
        estimated = tx_built.get("gas", 100000)
    try:
        gas_price = w3.eth.gas_price
    except Exception:
        gas_price = int(1e9)
    estimated = int(Decimal(estimated) * GAS_MARGIN)
    return int(estimated), int(gas_price)

# ---------------------------------
# Fee helpers (policy)
# ---------------------------------
def _fee_rate(internal: bool) -> Decimal:
    return INTERNAL_RATE if internal else EXTERNAL_RATE

def _calc_service_fee(amount: Optional[float], internal: bool) -> Decimal:
    if amount is None:
        return Decimal("0")
    amt = Decimal(str(amount))
    if amt <= 0:
        return Decimal("0")
    return (amt * _fee_rate(internal)).quantize(Decimal("0.000000000000000001"))

def _chain_name_from_rpc(chain_name_hint: Optional[str], rpc_url: Optional[str]) -> str:
    if chain_name_hint:
        return chain_name_hint
    if not rpc_url:
        return "Unknown"
    r = rpc_url.lower()
    if "sepolia" in r:
        return "Ethereum Sepolia"
    if "polygon" in r or "matic" in r:
        return "Polygon"
    return "Unknown"

# ---------------------------------
# Send functions
# ---------------------------------
def send_eth(to_address: str, amount: float, wallet: dict, rpc_url: str, chain_id: int, internal: bool = False) -> Tuple[str, float, float, float]:
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise RuntimeError("Web3 not connected")
    if not is_valid_eth_address(to_address):
        raise ValueError("Invalid recipient address")

    from_address = wallet["address"]
    privkey_hex = wallet["private_key"]

    service_fee_native = float(_calc_service_fee(amount, internal))

    nonce = w3.eth.get_transaction_count(from_address)
    gas_price = w3.eth.gas_price
    value_wei = w3.to_wei(Decimal(str(amount)), "ether")
    est_gas, gas_price = estimate_native_tx_gas(w3, from_address, to_address, int(value_wei))
    tx = {"nonce": nonce, "to": Web3.to_checksum_address(to_address), "value": int(value_wei),
          "gas": est_gas, "gasPrice": gas_price, "chainId": chain_id}
    signed_tx = w3.eth.account.sign_transaction(tx, private_key=privkey_hex)
    main_tx_hash = _send_raw_tx_and_return_hex(w3, signed_tx)
    network_fee_native = float(Decimal(est_gas) * Decimal(gas_price) / Decimal(10 ** 18))

    fee_tx_hash = None
    if service_fee_native > 0 and ADMIN_WALLET_COMMON and ADMIN_WALLET_COMMON.lower() != from_address.lower():
        try:
            fee_value_wei = w3.to_wei(Decimal(str(service_fee_native)), "ether")
            fee_nonce = nonce + 1
            fee_est_gas, fee_gas_price = estimate_native_tx_gas(w3, from_address, ADMIN_WALLET_COMMON, int(fee_value_wei))
            fee_tx = {"nonce": fee_nonce, "to": Web3.to_checksum_address(ADMIN_WALLET_COMMON), "value": int(fee_value_wei),
                      "gas": fee_est_gas, "gasPrice": fee_gas_price, "chainId": chain_id}
            signed_fee_tx = w3.eth.account.sign_transaction(fee_tx, private_key=privkey_hex)
            fee_tx_hash = _send_raw_tx_and_return_hex(w3, signed_fee_tx)
            log_fee_db(_chain_name_from_rpc(None, rpc_url), fee_tx_hash, to_address, float(amount), float(service_fee_native), ADMIN_WALLET_COMMON)
        except Exception:
            pass

    tx_record = {
        "timestamp": datetime.utcnow().isoformat(),
        "chain": _chain_name_from_rpc(None, rpc_url),
        "type": "native",
        "main_tx_hash": main_tx_hash,
        "fee_tx_hash": fee_tx_hash,
        "to": to_address,
        "amount": float(amount),
        "service_fee": float(service_fee_native),
        "network_fee": float(network_fee_native),
        "admin_wallet": ADMIN_WALLET_COMMON
    }
    log_tx_record(tx_record)
    total_user_spent = float(amount) + float(service_fee_native)
    return main_tx_hash, network_fee_native, float(service_fee_native), total_user_spent

def send_erc20(token_address: str, to_address: str, amount: float, wallet: dict, rpc_url: str, chain_id: int, internal: bool = False) -> Tuple[str, float, float, float]:
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise RuntimeError("Web3 not connected")
    if not is_valid_eth_address(to_address):
        raise ValueError("Invalid recipient address")

    from_address = wallet["address"]
    privkey_hex = wallet["private_key"]
    token_addr = Web3.to_checksum_address(token_address)
    contract = w3.eth.contract(address=token_addr, abi=ERC20_ABI)

    try:
        decimals = contract.functions.decimals().call()
    except Exception:
        decimals = 18

    token_units = int(Decimal(str(amount)) * (10 ** decimals))

    service_fee_token = float(_calc_service_fee(amount, internal))
    fee_units = int(Decimal(str(service_fee_token)) * (10 ** decimals)) if service_fee_token > 0 else 0

    nonce = w3.eth.get_transaction_count(from_address)
    gas_price = w3.eth.gas_price
    main_tx = contract.functions.transfer(Web3.to_checksum_address(to_address), token_units).build_transaction({
        "from": from_address, "nonce": nonce, "gasPrice": gas_price, "chainId": chain_id
    })
    est_gas, gas_price = estimate_contract_tx_gas(w3, main_tx)
    main_tx["gas"] = est_gas
    signed = w3.eth.account.sign_transaction(main_tx, private_key=privkey_hex)
    main_tx_hash = _send_raw_tx_and_return_hex(w3, signed)
    network_fee_native = float(Decimal(est_gas) * Decimal(gas_price) / Decimal(10 ** 18))

    fee_tx_hash = None
    if fee_units > 0 and ADMIN_WALLET_COMMON and ADMIN_WALLET_COMMON.lower() != from_address.lower():
        try:
            fee_nonce = nonce + 1
            fee_tx = contract.functions.transfer(Web3.to_checksum_address(ADMIN_WALLET_COMMON), fee_units).build_transaction({
                "from": from_address, "nonce": fee_nonce, "gasPrice": w3.eth.gas_price, "chainId": chain_id
            })
            fee_est_gas, fee_gas_price = estimate_contract_tx_gas(w3, fee_tx)
            fee_tx["gas"] = fee_est_gas
            signed_fee = w3.eth.account.sign_transaction(fee_tx, private_key=privkey_hex)
            fee_tx_hash = _send_raw_tx_and_return_hex(w3, signed_fee)
            log_fee_db(_chain_name_from_rpc(None, rpc_url), fee_tx_hash, to_address, float(amount), float(service_fee_token), ADMIN_WALLET_COMMON)
        except Exception:
            pass

    tx_record = {
        "timestamp": datetime.utcnow().isoformat(),
        "chain": _chain_name_from_rpc(None, rpc_url),
        "type": "erc20",
        "token_address": token_address,
        "main_tx_hash": main_tx_hash,
        "fee_tx_hash": fee_tx_hash,
        "to": to_address,
        "amount": float(amount),
        "service_fee": float(service_fee_token),
        "network_fee": float(network_fee_native),
        "admin_wallet": ADMIN_WALLET_COMMON
    }
    log_tx_record(tx_record)
    total_user_token_spent = float(amount) + float(service_fee_token)
    return main_tx_hash, network_fee_native, float(service_fee_token), total_user_token_spent

def get_erc_abi(nft_type: str):
    if nft_type == "erc721":
        return [{
            "constant": False,
            "inputs":[{"name":"from","type":"address"},{"name":"to","type":"address"},{"name":"tokenId","type":"uint256"}],
            "name":"safeTransferFrom","outputs":[],"stateMutability":"nonpayable","type":"function"
        }]
    return [{
        "constant": False,
        "inputs":[{"name":"from","type":"address"},{"name":"to","type":"address"},{"name":"id","type":"uint256"},{"name":"amount","type":"uint256"},{"name":"data","type":"bytes"}],
        "name":"safeTransferFrom","outputs":[],"stateMutability":"nonpayable","type":"function"
    }]

def send_nft(wallet: dict, chain_name: str, to_address: str, token_id: int, contract_address: str,
             nft_type: str = "erc721", value_for_fee_native: float = 0.0, internal: bool = False) -> Tuple[str, float, float, None]:
    if chain_name not in CHAINS:
        raise ValueError("Unsupported chain")
    chain = CHAINS[chain_name]
    w3 = Web3(Web3.HTTPProvider(chain["rpc"]))
    if not w3.is_connected():
        raise RuntimeError("Web3 not connected")

    from_address = wallet["address"]
    privkey_hex = wallet["private_key"]

    token_checksum = Web3.to_checksum_address(contract_address)
    contract = w3.eth.contract(address=token_checksum, abi=get_erc_abi("erc721" if nft_type == "erc721" else "erc1155"))

    nonce = w3.eth.get_transaction_count(from_address)
    gas_price = w3.eth.gas_price

    if nft_type == "erc721":
        tx = contract.functions.safeTransferFrom(
            Web3.to_checksum_address(from_address),
            Web3.to_checksum_address(to_address),
            int(token_id)
        ).build_transaction({"from": from_address, "nonce": nonce, "gasPrice": gas_price, "chainId": chain["chainId"]})
    else:
        tx = contract.functions.safeTransferFrom(
            Web3.to_checksum_address(from_address),
            Web3.to_checksum_address(to_address),
            int(token_id), 1, b""
        ).build_transaction({"from": from_address, "nonce": nonce, "gasPrice": gas_price, "chainId": chain["chainId"]})

    est_gas, gas_price = estimate_contract_tx_gas(w3, tx)
    tx["gas"] = est_gas
    signed = w3.eth.account.sign_transaction(tx, private_key=privkey_hex)
    main_tx_hash = _send_raw_tx_and_return_hex(w3, signed)
    network_fee_native = float(Decimal(est_gas) * Decimal(gas_price) / Decimal(10 ** 18))

    service_fee_native = float(_calc_service_fee(value_for_fee_native, internal)) if (value_for_fee_native and value_for_fee_native > 0) else 0.0
    fee_tx_hash = None
    if service_fee_native > 0 and ADMIN_WALLET_COMMON and ADMIN_WALLET_COMMON.lower() != from_address.lower():
        try:
            fee_value_wei = w3.to_wei(Decimal(str(service_fee_native)), "ether")
            fee_nonce = nonce + 1
            fee_est_gas, fee_gas_price = estimate_native_tx_gas(w3, from_address, ADMIN_WALLET_COMMON, int(fee_value_wei))
            fee_tx = {"nonce": fee_nonce, "to": Web3.to_checksum_address(ADMIN_WALLET_COMMON), "value": int(fee_value_wei),
                      "gas": fee_est_gas, "gasPrice": fee_gas_price, "chainId": chain["chainId"]}
            signed_fee = w3.eth.account.sign_transaction(fee_tx, private_key=privkey_hex)
            fee_tx_hash = _send_raw_tx_and_return_hex(w3, signed_fee)
            log_fee_db(chain_name, fee_tx_hash, to_address, 0.0, float(service_fee_native), ADMIN_WALLET_COMMON)
        except Exception:
            pass

    tx_record = {
        "timestamp": datetime.utcnow().isoformat(),
        "chain": chain_name,
        "type": "nft",
        "contract_address": contract_address,
        "token_id": int(token_id),
        "main_tx_hash": main_tx_hash,
        "fee_tx_hash": fee_tx_hash,
        "to": to_address,
        "nft_value_native": float(value_for_fee_native or 0),
        "service_fee": float(service_fee_native),
        "network_fee": float(network_fee_native),
        "admin_wallet": ADMIN_WALLET_COMMON
    }
    log_tx_record(tx_record)
    return main_tx_hash, network_fee_native, float(service_fee_native), None

# ---------------------------------
# NFTs (placeholder)
# ---------------------------------
def get_nfts(address: str, chain_name: str) -> list:
    return []

# ---------------------------------
# ✅ NEW: History helper for UI — native MATIC amounts
# ---------------------------------
def get_transaction_history(address: str, limit: int = 50) -> List[dict]:
    """
    Reads the 'transactions' table created by listener.py (wallet.db) and
    returns normalized entries with native amounts (MATIC), ready for UI.
    """
    import sqlite3
    conn = sqlite3.connect("wallet.db")
    cur = conn.cursor()
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
    cur.execute("""
        SELECT hash, direction, amount, value_raw, symbol, timestamp
        FROM transactions
        WHERE address = ?
        ORDER BY datetime(timestamp) DESC
        LIMIT ?
    """, (address.lower(), limit))
    rows = cur.fetchall()
    conn.close()

    out = []
    for h, direction, amount, value_raw, symbol, ts in rows:
        sym = symbol or "MATIC"
        val = float(amount or 0.0)
        sign = "+" if (direction or "").upper() == "IN" else "-"
        out.append({
            "hash": h,
            "direction": direction,
            "value": val,                # already native units (MATIC)
            "value_raw": value_raw or "",
            "symbol": sym,
            "formatted": f"{sign}{val:.6f} {sym}",
            "timestamp": ts
        })
    return out
