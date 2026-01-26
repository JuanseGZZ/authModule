// clase para llevar en memoria local las sessiones

// Session.js

const LS_KEY = "auth:session:v1";

export class Session {
  constructor({
    user_id = "",
    access_token = "",
    refresh_token = "",
    aes = "",
    expires_at_ms = 0,
    stateful = true,
    kid = ""
  } = {}) {
    this.user_id = String(user_id || "");
    this.access_token = String(access_token || "");
    this.refresh_token = String(refresh_token || "");
    this.aes = String(aes || "");
    this.expires_at_ms = Number(expires_at_ms || 0);
    this.stateful = Boolean(stateful);
    this.kid = String(kid || ""); // opcional: kid de RSA pub cacheada
  }

  isValid() {
    return (
      typeof this.user_id === "string" &&
      this.user_id.length > 0 &&
      typeof this.access_token === "string" &&
      this.access_token.length > 0 &&
      typeof this.refresh_token === "string" &&
      this.refresh_token.length > 0 &&
      typeof this.aes === "string" &&
      this.aes.length > 0
    );
  }

  isExpired(nowMs = Date.now()) {
    if (!this.expires_at_ms || this.expires_at_ms <= 0) return false;
    return nowMs >= this.expires_at_ms;
  }

  msToExpiry(nowMs = Date.now()) {
    if (!this.expires_at_ms || this.expires_at_ms <= 0) return Infinity;
    return this.expires_at_ms - nowMs;
  }

  isExpiringSoon(bufferMs = 120000, nowMs = Date.now()) {
    return this.msToExpiry(nowMs) <= bufferMs;
  }

  toJSON() {
    return {
      user_id: this.user_id,
      access_token: this.access_token,
      refresh_token: this.refresh_token,
      aes: this.aes,
      expires_at_ms: this.expires_at_ms,
      stateful: this.stateful,
      kid: this.kid
    };
  }

  static fromJSON(obj) {
    if (!obj || typeof obj !== "object") return null;
    return new Session(obj);
  }

  static load() {
    try {
      const raw = localStorage.getItem(LS_KEY);
      if (!raw) return null;
      const obj = JSON.parse(raw);
      const s = Session.fromJSON(obj);
      if (!s) return null;
      // si esta corrupta o incompleta, la descartamos
      if (!s.isValid()) return null;
      return s;
    } catch {
      return null;
    }
  }

  save() {
    try {
      localStorage.setItem(LS_KEY, JSON.stringify(this.toJSON()));
      return true;
    } catch {
      return false;
    }
  }

  static clear() {
    try {
      localStorage.removeItem(LS_KEY);
      return true;
    } catch {
      return false;
    }
  }
}

// ESTA ES LA LINEA QUE TE FALTABA (estado en scope de modulo)
let session = Session.load();

export function getSessionOrNull() {
  return session && session.isValid() ? session : null;
}

export function setSessionFromDecoded(dec) {
  // dec viene de Packet.decryptAES en register/login/refresh
  session = new Session({
    user_id: dec.user_id,
    access_token: dec.access_token,
    refresh_token: dec.refresh_token,
    aes: dec.aes,
    expires_at_ms: 0,   // lo calculamos en el paso 2 (JWT exp)
    stateful: true
  });
  session.save();
}

export function clearSession() {
  session = null;
  Session.clear();
}
