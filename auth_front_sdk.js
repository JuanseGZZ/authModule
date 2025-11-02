
let BASE_URL = "";
let ACCESS_TOKEN = null;
let JWKS_CACHE = null;
let JWKS_CACHE_AT = 0;
const JWKS_TTL_MS = 10 * 60 * 1000;

export function cargarDominio(baseUrl) {
  if (!baseUrl) throw new Error("baseUrl requerido");
  BASE_URL = baseUrl.replace(/\/+$/, "");
}

export function getAccessToken() { return ACCESS_TOKEN; }
export function setAccessToken(tok) { ACCESS_TOKEN = tok || null; }

async function fetchJWKS() {
  const now = Date.now();
  if (JWKS_CACHE && (now - JWKS_CACHE_AT) < JWKS_TTL_MS) return JWKS_CACHE;
  const res = await fetch(`${BASE_URL}/.well-known/jwks.json`, { method: "GET", credentials: "include" });
  if (!res.ok) throw new Error("No se pudo obtener JWKS");
  const data = await res.json();
  JWKS_CACHE = data; JWKS_CACHE_AT = now;
  return data;
}

function base64url(buf) {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function strToUtf8Bytes(str) { return new TextEncoder().encode(str); }

async function importRsaPublicKeyJwk(jwk) {
  return await crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
}

async function generateAesGcmKey() {
  return await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

async function exportAesRaw(key) { return await crypto.subtle.exportKey("raw", key); }

async function aesGcmEncrypt(key, plaintext, iv) {
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return new Uint8Array(ct);
}

async function rsaOaepEncrypt(publicKey, data) {
  const buf = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, data);
  return new Uint8Array(buf);
}

export async function encriptarDatos(obj) {
  if (!BASE_URL) throw new Error("Llamá primero a cargarDominio()");
  const jwks = await fetchJWKS();
  const key = (jwks.keys || []).find(k => k.use === "enc_front" && (k.alg === "RSA-OAEP-256" || k.alg === "RSA-OAEP"));
  if (!key) throw new Error("No hay clave enc_front en JWKS");
  const publicKey = await importRsaPublicKeyJwk({ kty: key.kty, n: key.n, e: key.e, alg: "RSA-OAEP-256", ext: true, key_ops: ["encrypt"] });
  const cek = await generateAesGcmKey();
  const cekRaw = await exportAesRaw(cek);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = strToUtf8Bytes(JSON.stringify(obj));
  const cipher = await aesGcmEncrypt(cek, plaintext, iv);
  const wrapped = await rsaOaepEncrypt(publicKey, cekRaw);
  return { __front_enc__: { kid: key.kid, alg: "RSA-OAEP-256", enc: "A256GCM", cek: base64url(wrapped), iv: base64url(iv), ct: base64url(cipher) } };
}

async function request(path, opts = {}) {
  const headers = { "Content-Type": "application/json" };
  if (ACCESS_TOKEN) headers["Authorization"] = `Bearer ${ACCESS_TOKEN}`;
  const res = await fetch(`${BASE_URL}${path}`, { method: opts.method || "GET", headers, credentials: "include", body: opts.body ? JSON.stringify(opts.body) : undefined });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) { const err = new Error(data?.error?.message || `HTTP ${res.status}`); err.code = data?.error?.code; err.status = res.status; throw err; }
  return data;
}

export async function registrarse({ email, password, cifrar = false }) {
  const body = cifrar ? await encriptarDatos({ email, password }) : { email, password };
  return await request("/auth/register", { method: "POST", body });
}

export async function loguearse({ email, password, cifrar = false }) {
  const body = cifrar ? await encriptarDatos({ email, password }) : { email, password };
  const resp = await request("/auth/login", { method: "POST", body });
  if (resp?.access_token) setAccessToken(resp.access_token);
  return resp;
}

export async function refrescar() {
  const resp = await request("/auth/token/refresh", { method: "POST", body: {} });
  if (resp?.access_token) setAccessToken(resp.access_token);
  return resp;
}
