// /FilesCipherHandler.js

import { b64uEncode, b64uDecode } from "./Base64Url.js";
import { aesGcmEncrypt, aesGcmDecrypt } from "./AESGCM.js";

// ---------- base64 "normal" (no urlsafe) ----------
function b64EncodeStd(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error("b64EncodeStd: bytes debe ser Uint8Array");
  }
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function b64DecodeStd(str) {
  if (typeof str !== "string") {
    throw new Error("b64DecodeStd: input debe ser string");
  }
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ---------- key normalization (igual que python) ----------
function normalizeAesKey(aesKeyStr) {
  const enc = new TextEncoder();
  let bytes = enc.encode(aesKeyStr);

  if (bytes.length > 32) bytes = bytes.slice(0, 32);

  if (bytes.length < 32) {
    const padded = new Uint8Array(32);
    padded.set(bytes);
    padded.fill(0x30, bytes.length); // '0'
    bytes = padded;
  }

  return bytes; // Uint8Array(32)
}

// ============================================================
// API publica (compat con back)
// ============================================================

export async function encryptFiles(files, aes_key) {
  if (!files || files.length === 0) return [];
  if (typeof aes_key !== "string" || !aes_key) {
    throw new Error("encryptFiles: aes_key invalida");
  }

  const keyBytes = normalizeAesKey(aes_key);
  const out = [];

  for (const f of files) {
    const data_b64 = f?.data_b64;
    if (data_b64 == null) continue; // igual que tu back (skip)

    const raw = b64DecodeStd(String(data_b64));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await aesGcmEncrypt(keyBytes, iv, raw);

    out.push({
      id: f?.id ?? null,
      file_name: f?.file_name ?? null,
      mime: f?.mime ?? null,
      iv: b64uEncode(iv),
      ciphertext: b64uEncode(ct),
    });
  }

  return out;
}

export async function decryptFiles(encFiles, aes_key) {
  if (!encFiles || encFiles.length === 0) return [];
  if (typeof aes_key !== "string" || !aes_key) {
    throw new Error("decryptFiles: aes_key invalida");
  }

  const keyBytes = normalizeAesKey(aes_key);
  const out = [];

  for (const f of encFiles) {
    const iv_s = f?.iv;
    const ct_s = f?.ciphertext;
    if (!iv_s || !ct_s) continue; // igual que tu back (skip)

    const iv = b64uDecode(String(iv_s));
    const ct = b64uDecode(String(ct_s));
    const plain = await aesGcmDecrypt(keyBytes, iv, ct);

    out.push({
      id: f?.id ?? null,
      file_name: f?.file_name ?? null,
      mime: f?.mime ?? null,
      data_b64: b64EncodeStd(plain),
    });
  }

  return out;
}
