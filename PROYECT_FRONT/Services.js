// aca vamos a tener todas las funciones heredables

// login, register, unlogin, sendStateless, sendStateful.

// Services.js
import { Packet } from "./ModelPacket.js";
import { b64uEncode } from "./crypto/Base64Url.js";
import { aesGcmEncrypt } from "./crypto/AESGCM.js";

import { loginFetch, registerFetch, refreshFetch, unloginFetch } from "./Api.js";

/*
  AuthService
  - login/register: handshake RSA -> backend responde paquete AES -> decrypt con aeskey
  - refresh/unlogin:
      stateful: Packet.encryptAES() (incluye aes AES-en-AES)
      stateless: aes.ciphertext = RSA({aeskey}), y payload AES sin campo aes
*/
import { AUTH_BASE_URL } from "./Env.js";

const LS_KEY_PEM = "auth:rsa_pub_pem";
const LS_KEY_KID = "auth:rsa_pub_kid";

export async function getServerPublicKeyPemCached() {
  const cachedPem = localStorage.getItem(LS_KEY_PEM);
  const cachedKid = localStorage.getItem(LS_KEY_KID);

  // Si ya esta cacheada, igual podes usarla directo.
  // Si queres validar, podes pegarle al endpoint y comparar kid.
  if (cachedPem && cachedKid) return { pem: cachedPem, kid: cachedKid };

  const res = await fetch(AUTH_BASE_URL + "/v1/auth/public-key");
  if (!res.ok) throw new Error("No se pudo obtener public key del server");

  const data = await res.json();
  const pem = data.public_key_pem;
  const kid = data.kid;

  if (typeof pem !== "string" || pem.length < 100) {
    throw new Error("public_key_pem invalida");
  }

  localStorage.setItem(LS_KEY_PEM, pem);
  if (typeof kid === "string" && kid) localStorage.setItem(LS_KEY_KID, kid);

  return { pem, kid };
}

export class AuthService {
  constructor() {
    this.rsaPublicKeyPem = null;
    this._rsaKeyCache = null;
  }

  // =========================
  // PUBLIC API
  // =========================

  async register({ email, username, password, aeskey }) {
    const handshake = await this._buildHandshake({ email, username, password, aeskey });
    const encResp = await registerFetch({ handshake_b64u: handshake });
    const dec = await Packet.decryptAES(encResp, aeskey);
    return dec;
  }

  async login({ emailOrUsername, password, aeskey }) {
    // el back acepta "username" y/o "email" (segun tu implementacion).
    // mandamos ambos: si tiene "@", lo tratamos como email.
    const isEmail = typeof emailOrUsername === "string" && emailOrUsername.includes("@");
    const payload = {
      email: isEmail ? emailOrUsername : "",
      username: isEmail ? "" : emailOrUsername,
      password,
      aeskey
    };

    const handshake = await this._rsaEncryptJsonB64u(payload);
    const encResp = await loginFetch({ handshake_b64u: handshake });
    const dec = await Packet.decryptAES(encResp, aeskey);
    return dec;
  }

  async refreshStateful({ user_id, aes_old, refresh_token}) {
    // stateful: el back espera AES vieja, y compara dec.aes con aes_old
    const pkt = new Packet({
      refresh_token,
      aes_key: aes_old,
      user_id
    });

    const enc = await pkt.encryptAES();
    const respEnc = await refreshFetch(enc);
    const respDec = await Packet.decryptAES(respEnc, aes_old);
    return respDec;
  }

  async refreshStateless({ aeskey, refresh_token }) {
    const enc = await this._encryptPayloadOnly({
      aeskey,
      refresh_token,
    });

    const aesRsa = await this._rsaEncryptJsonB64u({ aeskey });

    const body = {
      user_id: "0",
      iv: enc.iv,
      ciphertext: enc.ciphertext,
      aes: { ciphertext: aesRsa }
    };

    const respEnc = await refreshFetch(body);
    const respDec = await Packet.decryptAES(respEnc, aeskey);
    return respDec;
  }

  async unloginStateful({ user_id, aes_old, refresh_token}) {
    const pkt = new Packet({
      refresh_token,
      aes_key: aes_old,
      user_id
    });

    const enc = await pkt.encryptAES();
    const rsp = await unloginFetch(enc);
    return rsp;
  }

  async unloginStateless({ aeskey, refresh_token}) {
    const enc = await this._encryptPayloadOnly({
      aeskey,
      refresh_token,
    });

    const aesRsa = await this._rsaEncryptJsonB64u({ aeskey });

    const body = {
      user_id: "0",
      iv: enc.iv,
      ciphertext: enc.ciphertext,
      aes: { ciphertext: aesRsa }
    };

    const rsp = await unloginFetch(body);
    return rsp;
  }

  // =========================
  // INTERNALS
  // =========================

  async _buildHandshake({ email, username, password, aeskey }) {
    if (typeof password !== "string" || !password) throw new Error("password requerido");
    if (typeof aeskey !== "string" || !aeskey) throw new Error("aeskey requerido");
    if (typeof email !== "string") email = "";
    if (typeof username !== "string") username = "";

    return this._rsaEncryptJsonB64u({ email, username, password, aeskey });
  }

  async _encryptPayloadOnly({ aeskey, refresh_token, access_token, data }) {
    // Replica del back: AESGCM(key= aeskey[:32].ljust(32,'0')), iv 12 bytes, ciphertext b64u
    const keyBytes = Packet.normalizeAesKey(aeskey);

    const payload = {
      refresh_token: refresh_token || "",
      access_token: access_token || "",
      data: data || {}
    };

    const plaintext = new TextEncoder().encode(JSON.stringify(payload));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await aesGcmEncrypt(keyBytes, iv, plaintext);

    return {
      iv: b64uEncode(iv),
      ciphertext: b64uEncode(ciphertext)
    };
  }

  async _rsaEncryptJsonB64u(obj) {
    const json = JSON.stringify(obj);
    const pt = new TextEncoder().encode(json);

    const rsaKey = await this._getRsaPublicKey();
    const ct = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, rsaKey, pt);

    return b64uEncode(new Uint8Array(ct));
  }
  
  async _ensurePublicKeyLoaded() {
    if (this.rsaPublicKeyPem) return;
    const { pem } = await getServerPublicKeyPemCached();
    this.rsaPublicKeyPem = pem;
  }

  async _getRsaPublicKey() {
    await this._ensurePublicKeyLoaded();
    if (this._rsaKeyCache) return this._rsaKeyCache;

    const spkiDer = pemPublicKeyToDer(this.rsaPublicKeyPem);
    const key = await crypto.subtle.importKey(
      "spki",
      spkiDer,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["encrypt"]
    );

    this._rsaKeyCache = key;
    return key;
  }
}

// =========================
// PEM helpers
// =========================
function pemPublicKeyToDer(pem) {
  const lines = pem.trim().split(/\r?\n/);
  const b64 = lines
    .filter((l) => !l.includes("BEGIN PUBLIC KEY") && !l.includes("END PUBLIC KEY"))
    .join("");
  const binStr = atob(b64);
  const bytes = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
  return bytes.buffer;
}
