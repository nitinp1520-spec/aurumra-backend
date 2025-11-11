# main.py — Aurumra Wallet Backend (Polygon-ready, fees + incoming detection + native balance in history)

import os
import json
import time
import logging
import asyncio
import sqlite3
from pathlib import Path
from functools import wraps
from typing import Optional, List, Dict, Any, Tuple, Callable

import httpx
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from argon2 import PasswordHasher, exceptions as argon2_exceptions

app = FastAPI()

def get_db():
    return sqlite3.connect("wallet.db")

@app.post("/register_device")
def register_device(wallet_address: str, expo_token: str):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO devices (wallet_address, expo_token)
        VALUES (?, ?)
    """, (wallet_address.lower(), expo_token))
    db.commit()
    db.close()
    return {"message": "✅ Device registered"}

# =========================================================
# Load env first
# =========================================================
load_dotenv()

INFURA_KEY = os.getenv("INFURA_KEY", "").strip()
ADMIN_WALLET_COMMON = os.getenv("ADMIN_WALLET_COMMON", "").strip()
POLL_SECONDS = int(os.getenv("INCOMING_POLL_SECONDS", "12"))

# Optional: USDT on Polygon (defaults to canonical)
POLYGON_USDT_ADDRESS = os.getenv(
    "POLYGON_USDT_ADDRESS",
    "0xC2132D05D31c914a87C6611C10748AEb04B58e8F"
).strip()

# =========================================================
# Wallet APIs (from wallet.py)
# =========================================================
from wallet import (
    create_wallet,
    restore_wallet,
    load_wallet,
    send_eth,
    send_erc20,
    send_nft,
    get_nfts,
    CHAINS,
    ERC20_ABI,
    get_w3,
)

# Optional notifications bridge
try:
    from notification_service import register_tokens as _register_tokens
    from notification_service import broadcast_transaction_notification as _broadcast_tx
except Exception:
    _register_tokens = None
    _broadcast_tx = None

# =========================================================
# App + Logging
# =========================================================
app = FastAPI(
    title="Aurumra Wallet Backend",
    description="Secure local-encrypted multi-chain wallet backend",
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECURE_DIR = Path("secure")
SECURE_DIR.mkdir(exist_ok=True)
LOG_FILE = SECURE_DIR / "aurumra_backend.log"
logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("aurumra_backend")

# =========================================================
# Files/constants
# =========================================================
MASTER_FILE = SECURE_DIR / "master.json"
TX_LOG_FILE = SECURE_DIR / "transactions.json"
WALLET_FILE = SECURE_DIR / "aurumra_wallet.json"  # optional legacy file

COINGECKO_API = (
    "https://api.coingecko.com/api/v3/simple/price"
    "?ids=ethereum,polygon,binancecoin&vs_currencies=usd"
)

# =========================================================
# SQLite (internal registry of Aurumra addresses)
# =========================================================
DB_PATH = SECURE_DIR / "aurumra.db"

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS wallets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT UNIQUE NOT NULL,
                label TEXT,
                created_at INTEGER NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS seen_incoming (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain TEXT NOT NULL,
                tx_hash TEXT NOT NULL UNIQUE
            )
            """
        )
        conn.commit()

def upsert_wallet_address(address: str, label: Optional[str] = None):
    if not address:
        return
    ts = int(time.time())
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO wallets (address, label, created_at)
            VALUES (?, ?, ?)
            ON CONFLICT(address) DO UPDATE SET
                label=COALESCE(excluded.label, wallets.label)
            """,
            (address.lower(), label, ts),
        )
        conn.commit()

def address_exists(address: str) -> bool:
    if not address:
        return False
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM wallets WHERE address = ?", (address.lower(),))
        return cur.fetchone() is not None

def list_tracked_addresses() -> List[str]:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT address FROM wallets")
        return [r[0] for r in cur.fetchall()]

def mark_seen_incoming(chain: str, tx_hash: str) -> bool:
    """Returns True if newly inserted, False if already present."""
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT OR IGNORE INTO seen_incoming (chain, tx_hash) VALUES (?, ?)",
                (chain, tx_hash),
            )
            conn.commit()
            return cur.rowcount > 0
    except Exception:
        return False

init_db()

# =========================================================
# Master Password (Argon2)
# =========================================================
ph = PasswordHasher()

def set_master_password(password: str) -> str:
    hashed = ph.hash(password)
    MASTER_FILE.write_text(hashed, encoding="utf-8")
    try:
        os.chmod(MASTER_FILE, 0o600)
    except Exception:
        logger.warning("Could not set restrictive permissions on master file.")
    logger.info("Master password set/updated.")
    return hashed

def get_hashed_master_password() -> str:
    if not MASTER_FILE.exists():
        raise FileNotFoundError("Master password not set. Initialize using /initialize_master")
    return MASTER_FILE.read_text(encoding="utf-8").strip()

def verify_master_password(password: str) -> bool:
    try:
        hashed = get_hashed_master_password()
    except FileNotFoundError:
        return False
    try:
        return ph.verify(hashed, password)
    except argon2_exceptions.VerifyMismatchError:
        return False
    except Exception as e:
        logger.error(f"Error verifying master password: {e}")
        return False

def ensure_rehash_if_needed(password: str):
    try:
        hashed = get_hashed_master_password()
        if ph.check_needs_rehash(hashed):
            logger.info("Argon2 hash needs rehashing; updating stored hash.")
            set_master_password(password)
    except Exception as e:
        logger.warning(f"Rehash check failed: {e}")

# =========================================================
# Models
# =========================================================
class MasterWalletRequest(BaseModel):
    master_password: str
    wallet_password: str

class RestoreWalletRequest(MasterWalletRequest):
    seed_phrase: str

class CheckBalanceRequest(MasterWalletRequest):
    chain_name: str

class SendRequest(MasterWalletRequest):
    chain_name: str
    to_address: str
    amount: Optional[float] = None
    token_address: Optional[str] = None
    token_id: Optional[int] = None
    type: str = "native"   # native | erc20 | nft

class TokenInfoRequest(MasterWalletRequest):
    chain_name: str
    token_address: str

class NFTRequest(MasterWalletRequest):
    chain_name: str

class UpdateMasterRequest(BaseModel):
    old_password: str
    new_password: str

class InitMasterBody(BaseModel):
    password: str

class WalletRequest(MasterWalletRequest):
    chain_name: Optional[str] = None

# =========================================================
# Helpers
# =========================================================
def success_response(data: dict, message: str = "Success") -> dict:
    return {"status": "ok", "message": message, "data": data}

def log_transaction(entry: Dict[str, Any]) -> None:
    try:
        txs = []
        if TX_LOG_FILE.exists():
            try:
                txs = json.loads(TX_LOG_FILE.read_text(encoding="utf-8"))
            except Exception:
                txs = []
        txs.append(entry)
        TX_LOG_FILE.write_text(json.dumps(txs, indent=2), encoding="utf-8")
    except Exception as e:
        logger.error(f"Failed to log transaction: {e}")

async def get_coin_prices() -> Dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(COINGECKO_API)
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.warning(f"CoinGecko fetch failed: {e}")
        return {}

def validate_chain_name(chain_name: str):
    if chain_name not in CHAINS:
        raise HTTPException(status_code=400, detail=f"Unsupported chain name: {chain_name}")

def is_internal_transfer(to_address: str) -> bool:
    try:
        return address_exists(to_address)
    except Exception:
        return False

# service-fee preview (wallet.py actually enforces & forwards)
def calculate_service_fee(amount: Optional[float], internal: bool) -> float:
    if not amount or amount <= 0:
        return 0.0
    rate = 0.0001 if internal else 0.0002
    return round(amount * rate, 18)

# run either sync or async function
async def _maybe_call(func: Optional[Callable], *args, **kwargs):
    if not func:
        return None
    if asyncio.iscoroutinefunction(func):
        return await func(*args, **kwargs)
    # run sync in thread
    return await asyncio.to_thread(func, *args, **kwargs)

# =========================================================
# Routes
# =========================================================
@app.get("/")
def root():
    return {"message": "🪙 Aurumra Wallet backend running successfully!"}

@app.post("/initialize_master")
def initialize_master(body: InitMasterBody):
    if MASTER_FILE.exists():
        raise HTTPException(status_code=403, detail="Master password already initialized.")
    try:
        hashed = set_master_password(body.password)
        return success_response({"hash_preview": hashed[:20] + "..."}, "Master password initialized.")
    except Exception as e:
        logger.exception("Failed to initialize master password.")
        raise HTTPException(status_code=500, detail=str(e))

class LoadWalletBody(BaseModel):
    master_password: str

@app.post("/load_wallet")
def api_load_wallet(body: LoadWalletBody):
    try:
        if not verify_master_password(body.master_password):
            raise HTTPException(status_code=401, detail="Invalid master password")
        if not WALLET_FILE.exists():
            raise HTTPException(status_code=404, detail="Wallet file not found")
        wallet_data = json.loads(WALLET_FILE.read_text(encoding="utf-8"))
        if wallet_data.get("address"):
            upsert_wallet_address(wallet_data["address"], label="local_wallet")
        return success_response(
            {"address": wallet_data.get("address"), "network": wallet_data.get("network", "Ethereum Sepolia")},
            "Wallet loaded successfully",
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("load_wallet error")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/update_master_password")
def update_master_password(req: UpdateMasterRequest):
    try:
        if not verify_master_password(req.old_password):
            raise HTTPException(status_code=401, detail="Incorrect old password")
        new_hash = set_master_password(req.new_password)
        return success_response({"hash_preview": new_hash[:20] + "..."}, "Master password updated successfully.")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to update master password.")
        raise HTTPException(status_code=500, detail=str(e))

# ---------- Auth decorator ----------
def require_master_password(param_name: str = "request"):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            model = kwargs.get(param_name)
            if model is None:
                for a in args:
                    if hasattr(a, "master_password"):
                        model = a
                        break
            if model is None or not getattr(model, "master_password", None):
                raise HTTPException(status_code=401, detail="Master password required")
            if not verify_master_password(model.master_password):
                raise HTTPException(status_code=401, detail="Unauthorized")
            try:
                asyncio.create_task(asyncio.to_thread(ensure_rehash_if_needed, model.master_password))
            except Exception:
                pass
            return await func(*args, **kwargs)
        return wrapper
    return decorator

# ---------- Wallet core ----------
@app.post("/create_wallet")
@require_master_password("request")
async def api_create_wallet(request: MasterWalletRequest):
    try:
        wallet = await asyncio.to_thread(create_wallet, request.wallet_password)
        upsert_wallet_address(wallet.get("address"), label="local_wallet")
        return success_response(wallet, "Wallet created successfully")
    except Exception as e:
        logger.exception("create_wallet error")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/restore_wallet")
@require_master_password("request")
async def api_restore_wallet(request: RestoreWalletRequest):
    try:
        wallet = await asyncio.to_thread(restore_wallet, request.seed_phrase, request.wallet_password)
        upsert_wallet_address(wallet.get("address"), label="local_wallet")
        return success_response(wallet, "Wallet restored successfully")
    except Exception as e:
        logger.exception("restore_wallet error")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/receive")
@require_master_password("request")
async def receive_address(request: MasterWalletRequest):
    try:
        wallet = await asyncio.to_thread(load_wallet, request.wallet_password)
        upsert_wallet_address(wallet.get("address"), label="local_wallet")
        return success_response({"address": wallet["address"]}, "Receive address fetched")
    except Exception as e:
        logger.exception("receive error")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/check_balance")
@require_master_password("request")
async def api_check_balance(request: CheckBalanceRequest):
    validate_chain_name(request.chain_name)
    try:
        wallet = await asyncio.to_thread(load_wallet, request.wallet_password)
        w3, chain = await asyncio.to_thread(get_w3, request.chain_name)
        balance_wei = await asyncio.to_thread(lambda: w3.eth.get_balance(wallet["address"]))
        native = float(w3.from_wei(balance_wei, "ether") if hasattr(w3, "from_wei") else w3.fromWei(balance_wei, "ether"))
        return success_response({"address": wallet["address"], "balance": native, "symbol": chain.get("symbol")}, "Balance fetched")
    except Exception as e:
        logger.exception("check_balance error")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/send")
@require_master_password("request")
async def api_send(request: SendRequest):
    validate_chain_name(request.chain_name)
    try:
        wallet = await asyncio.to_thread(load_wallet, request.wallet_password)
        w3, chain = await asyncio.to_thread(get_w3, request.chain_name)

        internal = is_internal_transfer(request.to_address)
        service_fee_preview = calculate_service_fee(request.amount, internal)

        tx_hash = None
        network_fee = None
        total_amount = None

        if request.type == "erc20":
            if not request.token_address or request.amount is None:
                raise HTTPException(status_code=400, detail="token_address and amount are required for erc20")
            tx_hash, network_fee, _, total_amount = await asyncio.to_thread(
                send_erc20,
                request.token_address,
                request.to_address,
                request.amount,
                wallet,
                chain["rpc"],
                chain["chainId"],
                internal
            )
        elif request.type == "nft":
            if request.token_id is None or not request.token_address:
                raise HTTPException(status_code=400, detail="token_address and token_id are required for nft")
            tx_hash, network_fee, _, _ = await asyncio.to_thread(
                send_nft,
                wallet,
                request.chain_name,
                request.to_address,
                request.token_id,
                request.token_address,
                "erc721",
                request.amount or 0.0,
                internal
            )
        else:  # native
            if request.amount is None:
                raise HTTPException(status_code=400, detail="amount is required for native transfers")
            tx_hash, network_fee, _, total_amount = await asyncio.to_thread(
                send_eth,
                request.to_address,
                request.amount,
                wallet,
                chain["rpc"],
                chain["chainId"],
                internal
            )

        log_transaction({
            "tx_hash": tx_hash,
            "type": request.type,
            "to": request.to_address,
            "chain": request.chain_name,
            "amount": request.amount,
            "service_fee_preview": service_fee_preview,
            "internal": internal,
            "ts": int(time.time())
        })

        try:
            await _maybe_call(
                _broadcast_tx,
                title="Aurumra Transaction Submitted",
                message=f"{request.type.upper()} → {request.to_address[:10]}…",
                data={"chain": request.chain_name, "type": request.type, "tx_hash": tx_hash}
            )
        except Exception as e:
            logger.warning(f"Push notification failed for tx {tx_hash}: {e}")

        return success_response({
            "tx_hash": tx_hash,
            "network_fee": network_fee,
            "service_fee_preview": service_fee_preview,
            "total_amount": total_amount
        }, "Transaction submitted")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("send error")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/erc20_info")
@require_master_password("request")
async def erc20_info(request: TokenInfoRequest):
    validate_chain_name(request.chain_name)
    try:
        wallet = await asyncio.to_thread(load_wallet, request.wallet_password)
        w3, _ = await asyncio.to_thread(get_w3, request.chain_name)

        if not request.token_address or len(request.token_address) != 42:
            raise HTTPException(status_code=400, detail="Invalid token address")

        def read_contract():
            token_addr = w3.to_checksum_address(request.token_address)
            contract = w3.eth.contract(address=token_addr, abi=ERC20_ABI)
            balance = contract.functions.balanceOf(wallet["address"]).call()
            try:
                decimals = contract.functions.decimals().call()
            except Exception:
                decimals = 18
            try:
                symbol = contract.functions.symbol().call()
            except Exception:
                symbol = "TKN"
            return balance, decimals, symbol

        balance, decimals, symbol = await asyncio.to_thread(read_contract)
        value = float(balance) / (10 ** decimals)
        return success_response({
            "address": wallet["address"],
            "token_address": request.token_address,
            "balance": value,
            "decimals": decimals,
            "symbol": symbol
        }, "Token info fetched successfully")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("erc20_info error")
        raise HTTPException(status_code=500, detail=f"Error fetching token info: {str(e)}")

@app.post("/nfts")
@require_master_password("request")
async def nfts_endpoint(request: NFTRequest):
    validate_chain_name(request.chain_name)
    try:
        wallet = await asyncio.to_thread(load_wallet, request.wallet_password)
        nft_list = await asyncio.to_thread(get_nfts, wallet["address"], request.chain_name)
        prices_usd = {}
        try:
            prices_usd = await get_coin_prices()
        except Exception as e:
            logger.warning(f"CoinGecko fetch failed: {e}")

        enriched = []
        for nft in nft_list:
            price_native = 0.0
            last_sale = nft.get("last_sale") or {}
            total_price = last_sale.get("total_price", 0)
            try:
                price_native = int(total_price) / 1e18 if total_price else 0.0
            except Exception:
                price_native = 0.0

            chain_key = request.chain_name.lower()
            if chain_key in ("ethereum", "sepolia", "ethereum sepolia"):
                price_usd = price_native * prices_usd.get("ethereum", {}).get("usd", 0)
            elif chain_key == "polygon":
                price_usd = price_native * prices_usd.get("polygon", {}).get("usd", 0)
            elif chain_key in ("bsc", "binance"):
                price_usd = price_native * prices_usd.get("binancecoin", {}).get("usd", 0)
            else:
                price_usd = 0.0

            attributes = nft.get("traits", []) or []
            rarity = nft.get("rarity", "Common")
            if rarity == "Common" and attributes:
                rare_traits = [t for t in attributes if t.get("trait_type") and "rare" in (t.get("value") or "").lower()]
                if rare_traits:
                    rarity = "Rare"

            external_link = nft.get("external_link") or f"https://testnets.opensea.io/assets/{nft.get('token_address')}/{nft.get('tokenId')}"

            enriched.append({
                "token_id": nft.get("tokenId"),
                "name": nft.get("name") or f"NFT #{nft.get('tokenId')}",
                "image": nft.get("image") or "",
                "collection": nft.get("collection") or "Unknown Collection",
                "rarity": rarity,
                "priceNative": price_native,
                "priceUSD": price_usd,
                "attributes": attributes,
                "token_address": nft.get("token_address") or "",
                "external_link": external_link,
                "description": nft.get("description") or ""
            })

        return success_response({"nfts": enriched}, "NFTs fetched and enriched")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("nfts error")
        raise HTTPException(status_code=500, detail=f"Error fetching NFTs: {str(e)}")

# ---------- Local tx log + native balance ----------
@app.post("/tx_history")
@require_master_password("request")
async def tx_history(request: WalletRequest, page: int = Query(1, ge=1), per_page: int = Query(50, ge=1, le=200)):
    """
    Returns paginated local tx log AND, if wallet_password & chain_name provided,
    includes current native balance for that chain.
    """
    try:
        # transactions
        txs = []
        if TX_LOG_FILE.exists():
            try:
                txs = json.loads(TX_LOG_FILE.read_text(encoding="utf-8"))
            except Exception:
                txs = []
        if request.chain_name:
            txs = [t for t in txs if t.get("chain") == request.chain_name or t.get("chain_name") == request.chain_name]

        # paginate
        total = len(txs)
        start = (page - 1) * per_page
        end = start + per_page
        page_items = txs[start:end]

        # balance (optional)
        native_balance = None
        native_symbol = None
        address = None
        if request.chain_name:
            try:
                wallet = await asyncio.to_thread(load_wallet, request.wallet_password)
                address = wallet["address"]
                w3, chain = await asyncio.to_thread(get_w3, request.chain_name)
                bal_wei = await asyncio.to_thread(lambda: w3.eth.get_balance(address))
                native_balance = float(w3.from_wei(bal_wei, "ether") if hasattr(w3, "from_wei") else w3.fromWei(bal_wei, "ether"))
                native_symbol = chain.get("symbol")
            except Exception as e:
                logger.warning(f"tx_history balance read failed: {e}")

        return success_response({
            "transactions": page_items,
            "page": page,
            "per_page": per_page,
            "total": total,
            "address": address,
            "native_balance": native_balance,
            "native_symbol": native_symbol,
        }, "Transaction history fetched")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("tx_history error")
        raise HTTPException(status_code=500, detail=str(e))

# ---------- Notifications ----------
@app.post("/register_device")
async def register_device(request: Request):
    try:
        body = await request.json()
        tokens: List[str] = body.get("tokens", [])
        if not tokens:
            return success_response({"registered": 0}, "No tokens provided")
        result = await _maybe_call(_register_tokens, tokens)
        return success_response(result or {"registered": len(tokens)}, "Device tokens registered")
    except Exception as e:
        logger.exception("register_device error")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/notify_test")
async def notify_test():
    try:
        result = await _maybe_call(
            _broadcast_tx,
            title="Aurumra Test",
            message="This is a simulated notification test",
            data={"event": "test_push"}
        )
        return success_response(result or {}, "Test notification sent (best-effort)")
    except Exception as e:
        logger.exception("notify_test error")
        raise HTTPException(status_code=500, detail=str(e))

# For your RN client which called /test_push earlier (now exists)
@app.post("/test_push")
async def test_push():
    try:
        result = await _maybe_call(
            _broadcast_tx,
            title="Aurumra Test",
            message="It works!",
            data={"event": "manual_test"}
        )
        return success_response(result or {}, "Push trigger sent")
    except Exception as e:
        logger.exception("test_push error")
        raise HTTPException(status_code=500, detail=str(e))

# =========================================================
# Incoming Transfer Detector (native + USDT on Polygon)
# =========================================================

LAST_BLOCK_FILE = SECURE_DIR / "last_blocks.json"

def _read_last_blocks() -> Dict[str, int]:
    try:
        return json.loads(LAST_BLOCK_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}

def _write_last_blocks(d: Dict[str, int]):
    try:
        LAST_BLOCK_FILE.write_text(json.dumps(d, indent=2), encoding="utf-8")
    except Exception:
        pass

async def _scan_polygon_incoming_once():
    """
    - Scans Polygon mainnet latest block range since last seen
    - Detects incoming native transfers and USDT transfers to any tracked wallet
    - Logs as 'incoming' and pushes a notification
    """
    chain_name = "Polygon"
    if "Polygon" not in CHAINS and "Polygon Mainnet" not in CHAINS:
        # Some setups name it "Polygon"; others you may add as "Polygon Mainnet".
        # We'll try infer by key search:
        polygon_key = None
        for key in CHAINS.keys():
            if "polygon" in key.lower():
                chain_name = key
                break

    try:
        w3, chain = get_w3(chain_name)
    except Exception:
        # If Polygon not configured in wallet.CHAINS yet, skip silently
        return

    tracked = [addr.lower() for addr in list_tracked_addresses()]
    if not tracked:
        return

    last_blocks = _read_last_blocks()
    start_block = last_blocks.get(chain_name, None)
    latest = w3.eth.block_number

    # initialize window (first run: just set to latest-1 to avoid huge catch-up)
    if start_block is None:
        start_block = max(latest - 1, 0)

    # Limit the range per tick
    end_block = min(start_block + 4, latest)

    if end_block < start_block:
        # update pointer anyway
        last_blocks[chain_name] = latest
        _write_last_blocks(last_blocks)
        return

    usdt_addr = None
    try:
        usdt_addr = w3.to_checksum_address(POLYGON_USDT_ADDRESS) if POLYGON_USDT_ADDRESS else None
    except Exception:
        usdt_addr = None

    # Native transfers
    for blk_num in range(start_block, end_block + 1):
        try:
            block = w3.eth.get_block(blk_num, full_transactions=True)
        except Exception:
            continue

        # Native incoming: tx.to in tracked
        for tx in block.transactions:
            to_addr = (tx.to or "").lower() if getattr(tx, "to", None) else ""
            if to_addr and to_addr in tracked:
                tx_hash = tx.hash.hex() if hasattr(tx, "hash") else str(tx.hash)
                if mark_seen_incoming(chain_name, tx_hash):
                    amount_native = float(w3.from_wei(tx.value, "ether"))
                    entry = {
                        "direction": "incoming",
                        "type": "native",
                        "chain": chain_name,
                        "tx_hash": tx_hash,
                        "to": to_addr,
                        "amount": amount_native,
                        "ts": int(time.time())
                    }
                    log_transaction(entry)
                    await _maybe_call(
                        _broadcast_tx,
                        title="Incoming Native Funds",
                        message=f"+{amount_native:.6f} {chain.get('symbol', 'MATIC')} received",
                        data={"chain": chain_name, "tx_hash": tx_hash, "type": "incoming_native"}
                    )

        # ERC20 USDT incoming: filter logs in block for Transfer(to = tracked)
        if usdt_addr:
            try:
                # ERC20 Transfer(topic0) = keccak("Transfer(address,address,uint256)")
                topic0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                logs = w3.eth.get_logs({
                    "fromBlock": blk_num,
                    "toBlock": blk_num,
                    "address": usdt_addr,
                    "topics": [topic0]
                })
                for lg in logs:
                    # topic[2] is 'to' (indexed), last 20 bytes
                    if len(lg["topics"]) >= 3:
                        to_hex = "0x" + lg["topics"][2].hex()[-40:]
                        to_lower = to_hex.lower()
                        if to_lower in tracked:
                            tx_hash = lg["transactionHash"].hex()
                            if mark_seen_incoming(chain_name, tx_hash):
                                # value is in data
                                value_int = int(lg["data"], 16)
                                # USDT on Polygon uses 6 decimals
                                amount_usdt = value_int / (10 ** 6)
                                entry = {
                                    "direction": "incoming",
                                    "type": "erc20",
                                    "token": "USDT",
                                    "token_address": POLYGON_USDT_ADDRESS,
                                    "chain": chain_name,
                                    "tx_hash": tx_hash,
                                    "to": to_lower,
                                    "amount": amount_usdt,
                                    "ts": int(time.time())
                                }
                                log_transaction(entry)
                                await _maybe_call(
                                    _broadcast_tx,
                                    title="Incoming USDT",
                                    message=f"+{amount_usdt:.2f} USDT received",
                                    data={"chain": chain_name, "tx_hash": tx_hash, "type": "incoming_usdt"}
                                )
            except Exception as e:
                logger.debug(f"USDT log scan error @ block {blk_num}: {e}")

    # move window
    last_blocks[chain_name] = end_block + 1
    _write_last_blocks(last_blocks)

async def _incoming_loop():
    # lightweight polling loop
    while True:
        try:
            await _scan_polygon_incoming_once()
        except Exception as e:
            logger.debug(f"incoming loop error: {e}")
        await asyncio.sleep(POLL_SECONDS)

@app.on_event("startup")
async def startup_event():
    # Make sure the last_blocks file exists
    if not LAST_BLOCK_FILE.exists():
        _write_last_blocks({})
    # Start incoming detector
    asyncio.create_task(_incoming_loop())

# =========================================================
# Dev entrypoint
# =========================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
