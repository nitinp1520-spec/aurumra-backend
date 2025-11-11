// utils/SecureStoreUtils.js
// -----------------------------------------------------------------------------
// 🔐 Secure Storage Helpers for Aurumra Wallet
// AES-GCM encryption with Argon2id or PBKDF2 key derivation
// Compatible with Expo + React Native (managed or bare)
// -----------------------------------------------------------------------------
//
// Exports:
//   encryptData(plaintext, password)       → encrypted JSON string
//   decryptData(encryptedJSON, password)   → plaintext string
//   hashPassword(password)                 → { hash, salt, kdf }
//   verifyPassword(password, storedObj)    → boolean
//   rotateKey(oldPassword, newPassword, blob) → re-encrypted JSON
//
// -----------------------------------------------------------------------------
import { Buffer } from "buffer";

/* ===== Runtime capability detection ===== */
let hasWebCrypto = false;
let subtle = null;
if (typeof global?.crypto?.subtle !== "undefined") {
  hasWebCrypto = true;
  subtle = global.crypto.subtle;
}

let argon2 = null;
let SimpleCrypto = null;
try {
  argon2 = require("react-native-argon2");
} catch {
  argon2 = null;
}
try {
  SimpleCrypto =
    require("react-native-simple-crypto").default ||
    require("react-native-simple-crypto");
} catch {
  SimpleCrypto = null;
}

/* ===== Helper functions ===== */
const abToBase64 = (ab) => Buffer.from(ab).toString("base64");
const base64ToAb = (b64) => Uint8Array.from(Buffer.from(b64, "base64")).buffer;

async function randomBytes(length = 16) {
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    return crypto.getRandomValues(new Uint8Array(length));
  }
  if (SimpleCrypto?.utils?.randomBytes) {
    const hex = await SimpleCrypto.utils.randomBytes(length);
    return Uint8Array.from(Buffer.from(hex, "hex"));
  }
  // fallback (not secure, dev only)
  const arr = new Uint8Array(length);
  for (let i = 0; i < length; i++) arr[i] = Math.floor(Math.random() * 256);
  return arr;
}

/* ===== Argon2id Parameters ===== */
const DEFAULT_ARGON2_PARAMS = {
  time: 2, // iterations
  mem: 32768, // 32 MB
  parallelism: 2,
  hashLen: 32,
};

/* ===== Key Derivation ===== */
async function deriveKey(password, saltUint8, opts = {}) {
  const {
    time = DEFAULT_ARGON2_PARAMS.time,
    mem = DEFAULT_ARGON2_PARAMS.mem,
    parallelism = DEFAULT_ARGON2_PARAMS.parallelism,
    hashLen = DEFAULT_ARGON2_PARAMS.hashLen,
  } = opts;

  // 1️⃣ Try Argon2id first
  if (argon2?.hash) {
    try {
      const saltHex = Buffer.from(saltUint8).toString("hex");
      const resHex = await argon2.hash({
        pass: password,
        salt: saltHex,
        timeCost: time,
        memoryCost: mem,
        parallelism,
        hashLen,
        type: 2, // Argon2id
      });
      return Uint8Array.from(Buffer.from(resHex, "hex")).buffer;
    } catch (err) {
      console.warn("Argon2id failed, falling back to PBKDF2:", err.message);
    }
  }

  // 2️⃣ WebCrypto PBKDF2
  if (hasWebCrypto && subtle) {
    const enc = new TextEncoder();
    const keyMaterial = await subtle.importKey(
      "raw",
      enc.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );
    const derivedBits = await subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: saltUint8,
        iterations: 120000,
        hash: "SHA-256",
      },
      keyMaterial,
      hashLen * 8
    );
    return derivedBits;
  }

  // 3️⃣ SimpleCrypto PBKDF2 fallback
  if (SimpleCrypto?.PBKDF2) {
    const saltHex = Buffer.from(saltUint8).toString("hex");
    const derivedHex = await SimpleCrypto.PBKDF2.hash(
      password,
      saltHex,
      120000,
      hashLen * 8
    );
    return Uint8Array.from(Buffer.from(derivedHex, "hex")).buffer;
  }

  throw new Error(
    "No KDF available. Install react-native-argon2 or react-native-simple-crypto."
  );
}

/* ===== AES Encryption (AES-GCM preferred) ===== */
async function importAesKey(rawKey, algo = "AES-GCM") {
  if (hasWebCrypto && subtle) {
    return subtle.importKey("raw", rawKey, { name: algo }, false, [
      "encrypt",
      "decrypt",
    ]);
  }
  return rawKey; // fallback for SimpleCrypto
}

async function aesEncrypt(keyRaw, plaintext) {
  const ivArr = await randomBytes(12); // 96-bit nonce for GCM
  const iv = ivArr.buffer;
  const enc = new TextEncoder();
  const pt = enc.encode(plaintext);

  if (hasWebCrypto && subtle) {
    const cryptoKey = await importAesKey(keyRaw, "AES-GCM");
    const ct = await subtle.encrypt(
      { name: "AES-GCM", iv: new Uint8Array(iv) },
      cryptoKey,
      pt
    );
    return { ciphertext: abToBase64(ct), iv: abToBase64(iv), algo: "AES-GCM" };
  }

  if (SimpleCrypto?.AES) {
    const keyHex = Buffer.from(new Uint8Array(keyRaw)).toString("hex");
    const ivHex = Buffer.from(ivArr).toString("hex");
    const ptHex = Buffer.from(pt).toString("hex");
    const ctHex = await SimpleCrypto.AES.encrypt(ptHex, keyHex, ivHex);
    console.warn("⚠️ Fallback to AES-CBC (no AEAD).");
    return {
      ciphertext: abToBase64(Buffer.from(ctHex, "hex")),
      iv: abToBase64(iv),
      algo: "AES-CBC",
    };
  }

  throw new Error("No AES provider available.");
}

/* ===== AES Decrypt ===== */
async function aesDecrypt(keyRaw, ciphertextB64, ivB64, algo = "AES-GCM") {
  const ctAb = base64ToAb(ciphertextB64);
  const ivAb = base64ToAb(ivB64);

  if (hasWebCrypto && subtle) {
    const cryptoKey = await importAesKey(keyRaw, algo);
    const plainBuf = await subtle.decrypt(
      { name: algo, iv: new Uint8Array(ivAb) },
      cryptoKey,
      ctAb
    );
    return new TextDecoder().decode(plainBuf);
  }

  if (SimpleCrypto?.AES) {
    const keyHex = Buffer.from(new Uint8Array(keyRaw)).toString("hex");
    const ivHex = Buffer.from(new Uint8Array(ivAb)).toString("hex");
    const ctHex = Buffer.from(new Uint8Array(ctAb)).toString("hex");
    const ptHex = await SimpleCrypto.AES.decrypt(ctHex, keyHex, ivHex);
    return Buffer.from(ptHex, "hex").toString();
  }

  throw new Error("No AES provider available for decryption.");
}

/* ===== Public High-Level API ===== */
export async function encryptData(plainText, password) {
  if (!password) throw new Error("Password required for encryption.");
  const saltArr = await randomBytes(16);
  const saltB64 = abToBase64(saltArr.buffer);

  const keyRaw = await deriveKey(password, saltArr, DEFAULT_ARGON2_PARAMS);
  const { ciphertext, iv, algo } = await aesEncrypt(keyRaw, plainText);

  return JSON.stringify({
    version: 2,
    kdf: argon2 ? "argon2id" : "pbkdf2",
    salt: saltB64,
    iv,
    algo,
    ciphertext,
  });
}

export async function decryptData(encryptedJSONString, password) {
  if (!password) throw new Error("Password required for decryption.");
  let parsed;
  try {
    parsed = JSON.parse(encryptedJSONString);
  } catch {
    throw new Error("Invalid encrypted data format.");
  }

  const { salt, iv, algo, ciphertext } = parsed;
  if (!salt || !iv || !ciphertext)
    throw new Error("Encrypted data missing required fields.");

  const saltAb = base64ToAb(salt);
  const keyRaw = await deriveKey(password, new Uint8Array(saltAb), DEFAULT_ARGON2_PARAMS);
  return aesDecrypt(keyRaw, ciphertext, iv, algo || "AES-GCM");
}

export async function hashPassword(password) {
  const saltArr = await randomBytes(16);
  const saltB64 = abToBase64(saltArr.buffer);
  if (argon2?.hash) {
    const saltHex = Buffer.from(saltArr).toString("hex");
    const hex = await argon2.hash({
      pass: password,
      salt: saltHex,
      timeCost: DEFAULT_ARGON2_PARAMS.time,
      memoryCost: DEFAULT_ARGON2_PARAMS.mem,
      parallelism: DEFAULT_ARGON2_PARAMS.parallelism,
      hashLen: DEFAULT_ARGON2_PARAMS.hashLen,
      type: 2,
    });
    return {
      hash: abToBase64(Buffer.from(hex, "hex")),
      salt: saltB64,
      kdf: "argon2id",
    };
  }

  const keyRaw = await deriveKey(password, saltArr, DEFAULT_ARGON2_PARAMS);
  return { hash: abToBase64(keyRaw), salt: saltB64, kdf: "pbkdf2" };
}

export async function verifyPassword(password, stored) {
  const { hash, salt, kdf } = stored || {};
  if (!hash || !salt) return false;
  const saltArr = Uint8Array.from(Buffer.from(salt, "base64"));
  const keyRaw = await deriveKey(password, saltArr, DEFAULT_ARGON2_PARAMS);
  return abToBase64(keyRaw) === hash;
}

export async function rotateKey(oldPassword, newPassword, encryptedBlob) {
  const plain = await decryptData(encryptedBlob, oldPassword);
  return encryptData(plain, newPassword);
}

/* Export internal info for debugging */
export default {
  encryptData,
  decryptData,
  hashPassword,
  verifyPassword,
  rotateKey,
  deriveKey,
  _internals: {
    hasWebCrypto,
    usingArgon2: !!argon2,
    usingSimpleCrypto: !!SimpleCrypto,
    DEFAULT_ARGON2_PARAMS,
  },
};
