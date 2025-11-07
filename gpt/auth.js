/*
 * auth.js - Frontend crypto + API helper compatible with the provided FastAPI backend.
 *
 * - Curve: X25519 (via embedded TweetNaCl scalarMult)
 * - KDF: HKDF-SHA256 (salt="ecies-salt", info="aes-key-transport")
 * - Payload cipher: AES-GCM (WebCrypto)
 * - Modes:
 *     - "stateless": per-request AES, ECIES envelope in "X-EC-Envelope" header
 *     - "stateful": session AES stored client-side (memory) + session_id in body
 *
 * Every function has a brief comment above it explaining its purpose.
 * No external deps required. Works in modern browsers with WebCrypto.
 * Exposes global `window.AuthClient`.
 */

/* ==============================
 * Minimal TweetNaCl (subset) for X25519 scalarMult
 * Source: https://github.com/dchest/tweetnacl-js (Public Domain)
 * Stripped to only what we need: randomBytes, scalarMult, box.keyPair (for key gen).
 * ============================== */
(function(root) {
  'use strict';
  var nacl = {}, _crypto = root.crypto || root.msCrypto;
  if (!_crypto || !_crypto.getRandomValues) {
    throw new Error('WebCrypto getRandomValues not available.');
  }
  function randomBytes(n) {
    var b = new Uint8Array(n);
    _crypto.getRandomValues(b);
    return b;
  }
  // Curve25519 implementation pieces (scalarMult).
  // This is a compact subset adapted from tweetnacl-js (public domain).
  // For brevity and size, the implementation is condensed.
  // BEGIN tweetnacl scalarMult subset
  var gf = function(init) {
    var r = new Float64Array(16);
    if (init) for (var i = 0; i < init.length; i++) r[i] = init[i];
    return r;
  };
  var _0 = new Uint8Array(16); var _9 = new Uint8Array(32); _9[0] = 9;
  function car25519(o){var c;for(var i=0;i<16;i++){o[i]+=65536; c=Math.floor(o[i]/65536); o[(i+1)*(i<15?1:0)] += c-1+37*(c-1); o[i]-=c*65536;}}
  function sel25519(p,q,b){var t,i,c=~(b-1); for(i=0;i<16;i++){t=c&(p[i]^q[i]); p[i]^=t; q[i]^=t;}}
  function pack25519(o,n){
    var i,j,m=t=0;
    var t = gf();
    var m = gf();
    var c = gf();
    var d = gf();
    var e = gf();
    for(i=0;i<16;i++) d[i]=n[i];
    car25519(d); car25519(d); car25519(d);
    for(j=0;j<2;j++) {
      e[0]=d[0]-0xffed; for(i=1;i<15;i++) e[i]=d[i]-0xffff; e[15]=d[15]-0x7fff; m[0]=1;
      for(i=0;i<16;i++) {c[i]=0; m[i]=m[i] & ((e[i]>>16)&1)^1;}
      sel25519(d,e,1-m[0]);
    }
    for(i=0;i<16;i++){o[2*i]=d[i]&0xff; o[2*i+1]=(d[i]>>8)&0xff;}
  }
  function unpack25519(o,n){
    for(var i=0;i<16;i++) o[i]=n[2*i]+(n[2*i+1]<<8);
    o[15]&=0x7fff;
  }
  function A(o,a,b){for(var i=0;i<16;i++) o[i]=a[i]+b[i];}
  function Z(o,a,b){for(var i=0;i<16;i++) o[i]=a[i]-b[i];}
  function M(o,a,b){
    var v, i, j, t = new Float64Array(31);
    for(i=0;i<31;i++) t[i]=0;
    for(i=0;i<16;i++) for(j=0;j<16;j++) t[i+j]+=a[i]*b[j];
    for(i=0;i<15;i++){v=t[i]+38*t[i+16]; o[i]=v&0xffff; t[i+1]+=Math.floor(v/65536);}
    o[15]=t[15];
  }
  function S(o,a){M(o,a,a);}
  function inv25519(o,i){
    var c = gf();
    for(var a=0;a<16;a++) c[a]=i[a];
    for(var a=253;a>=0;a--){ S(c,c); if(a!==2&&a!==4) M(c,c,i); }
    for(var a=0;a<16;a++) o[a]=c[a];
  }
  function scalarmult(q,n,p){
    var z = new Uint8Array(32); var x = new Float64Array(16);
    var r = gf([1]); var s = gf(); var t = gf(); var u = gf();
    for (var i=0;i<31;i++) z[i]=n[i];
    z[31]=(n[31]&127)|64; z[0]&=248;
    unpack25519(x,p);
    for (var i=0;i<16;i++){ s[i]=0; t[i]=0; }
    s[0]=1;
    for (var i=254;i>=0;i--){
      var b=(z[i>>>3]>>>(i&7))&1;
      sel25519(r,s,b); sel25519(t,u,b);
      A(u,t,s); Z(t,t,s); A(s,r, x); Z(r,r, x);
      S(t,t); S(r,r); M(r,r,s); M(t,t,u);
      A(s,t,r); Z(t,t,r); S(s,s); S(t,t);
      M(u,t,_121665); A(u,u,t);
      M(t,t,u); M(r,r,s);
    }
    var qx = new Uint8Array(32); var rr = gf(); var ss = gf();
    inv25519(rr,t); M(rr, r, rr); pack25519(qx, rr);
    for (var i=0;i<32;i++) q[i]=qx[i];
  }
  var _121665 = gf([0xdb41,1]);
  nacl.randomBytes = randomBytes;
  nacl.scalarMult = {
    base: function(n){
      var q = new Uint8Array(32);
      scalarmult(q, n, _9);
      return q;
    },
    scalarMult: function(n,p){
      var q = new Uint8Array(32);
      scalarmult(q, n, p);
      return q;
    },
    keyPair: function(){
      var sk = randomBytes(32);
      sk[0] &= 248; sk[31] &= 127; sk[31] |= 64;
      var pk = nacl.scalarMult.base(sk);
      return {publicKey: pk, secretKey: sk};
    }
  };
  root._nacl = nacl; // expose internal for this module
})(typeof window !== 'undefined' ? window : global);

/* ==============================
 * Utility: Base64 helpers (URL-safe and standard)
 * ============================== */
const B64 = {
  /** Convert ArrayBuffer to base64 (standard). */
  toB64: (buf) => {
    let bin = '';
    const bytes = new Uint8Array(buf);
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  },
  /** Convert base64 string to Uint8Array. */
  fromB64: (b64) => {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  },
  /** Convert Uint8Array to base64-url without padding. */
  toB64Url: (u8) => {
    return btoa(String.fromCharCode.apply(null, u8)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'');
  },
  /** Convert base64-url (no padding) to Uint8Array. */
  fromB64Url: (s) => {
    s = s.replace(/-/g,'+').replace(/_/g,'/');
    while (s.length % 4) s += '=';
    return B64.fromB64(s);
  }
};

/* ==============================
 * Utility: HKDF-SHA256 (RFC5869) using WebCrypto HMAC
 * ============================== */
/** Derive a key using HKDF-SHA-256. Returns Uint8Array of length `length`. */
async function hkdfSha256(ikmU8, saltU8, infoU8, length = 32) {
  const subtle = crypto.subtle;
  const ikmKey = await subtle.importKey('raw', ikmU8, {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
  const prkBuf = await subtle.sign('HMAC', await subtle.importKey('raw', saltU8, {name:'HMAC', hash:'SHA-256'}, false, ['sign']), ikmU8);
  const prkKey = await subtle.importKey('raw', new Uint8Array(prkBuf), {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
  let t = new Uint8Array(0);
  const okm = new Uint8Array(length);
  let written = 0;
  let counter = 1;
  while (written < length) {
    const input = new Uint8Array(t.length + infoU8.length + 1);
    input.set(t, 0);
    input.set(infoU8, t.length);
    input[input.length - 1] = counter;
    const mac = await subtle.sign('HMAC', prkKey, input);
    t = new Uint8Array(mac);
    const take = Math.min(t.length, length - written);
    okm.set(t.slice(0, take), written);
    written += take;
    counter += 1;
  }
  return okm;
}

/* ==============================
 * Utility: AES-GCM encrypt/decrypt with JSON envelopes
 * ============================== */
/** Encrypt a JSON-serializable object with AES-GCM. Returns {nonce,ciphertext,tag} base64. */
async function aesGcmEncrypt(aesKeyU8, payloadObj) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const algo = {name:'AES-GCM', iv: nonce};
  const key = await crypto.subtle.importKey('raw', aesKeyU8, 'AES-GCM', false, ['encrypt']);
  const plaintext = new TextEncoder().encode(JSON.stringify(payloadObj));
  const ct = new Uint8Array(await crypto.subtle.encrypt(algo, key, plaintext));
  const tag = ct.slice(ct.length - 16);
  const ciphertext = ct.slice(0, ct.length - 16);
  return {
    nonce: B64.toB64(nonce),
    ciphertext: B64.toB64(ciphertext),
    tag: B64.toB64(tag),
  };
}

/** Decrypt an AES-GCM JSON envelope {nonce,ciphertext,tag} to an object. */
async function aesGcmDecrypt(aesKeyU8, envelope) {
  const nonce = B64.fromB64(envelope.nonce);
  const ciphertext = B64.fromB64(envelope.ciphertext);
  const tag = B64.fromB64(envelope.tag);
  const full = new Uint8Array(ciphertext.length + tag.length);
  full.set(ciphertext, 0); full.set(tag, ciphertext.length);
  const key = await crypto.subtle.importKey('raw', aesKeyU8, 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv: nonce}, key, full);
  return JSON.parse(new TextDecoder().decode(pt));
}

/* ==============================
 * ECIES-like: build envelope for sending AES to server
 * ============================== */
/** Build an ECIES-like envelope encrypting `aesKeyU8` with server X25519 public key. */
async function buildEcEnvelope(serverPublicRawB64, aesKeyU8) {
  const serverPubU8 = B64.fromB64(serverPublicRawB64);
  const eph = _nacl.scalarMult.keyPair();
  const shared = _nacl.scalarMult.scalarMult(eph.secretKey, serverPubU8);
  const transportKey = await hkdfSha256(shared, new TextEncoder().encode('ecies-salt'), new TextEncoder().encode('aes-key-transport'), 32);
  const envelope = await aesGcmEncrypt(transportKey, { aes_base64: B64.toB64(aesKeyU8) });
  return {
    ephemeral_public_key: B64.toB64(eph.publicKey),
    nonce: envelope.nonce,
    ciphertext: envelope.ciphertext,
    tag: envelope.tag,
    _ephemeral_sk: eph.secretKey, // not sent; useful for debugging if needed
  };
}

/* ==============================
 * Main client: configuration and flows
 * ============================== */
(function(root){
  'use strict';

  /** Internal state for the client. */
  const state = {
    serverBaseUrl: null,
    apiCryptoMode: 'stateful', // 'stateful' | 'stateless'
    serverEcPublicB64: null,
    sessionId: null,
    sessionAesKeyU8: null,
    accessToken: null,
    refreshToken: null,
  };

  /** Fetch server public keys from /.well-known/server-keys and cache them. */
  async function fetchServerKeys() {
    const resp = await fetch(`${state.serverBaseUrl}/.well-known/server-keys`);
    if (!resp.ok) throw new Error(`Failed to fetch server keys: ${resp.status}`);
    const data = await resp.json();
    state.serverEcPublicB64 = data.ec_public_key_base64;
    return data;
  }

  /** Configure the client with server base URL and crypto mode (defaults to stateful). */
  async function config(serverBaseUrl, apiCryptoMode = 'stateful') {
    state.serverBaseUrl = serverBaseUrl.replace(/\/+$/,'');
    state.apiCryptoMode = apiCryptoMode;
    await fetchServerKeys();
    return { ok: true, mode: state.apiCryptoMode };
  }

  /** Generate a new random AES-256 key (Uint8Array length 32). */
  function generateAes256Key() {
    const k = new Uint8Array(32);
    crypto.getRandomValues(k);
    return k;
  }

  /** Perform handshake: send ECIES-wrapped AES; receive session_id + tokens encrypted with that AES. */
  async function handshake() {
    const aesKey = generateAes256Key();
    const env = await buildEcEnvelope(state.serverEcPublicB64, aesKey);
    const body = { ec_encrypted: {
      ephemeral_public_key: env.ephemeral_public_key,
      nonce: env.nonce,
      ciphertext: env.ciphertext,
      tag: env.tag
    }};
    const resp = await fetch(`${state.serverBaseUrl}/api/handshake`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(body)
    });
    if (!resp.ok) throw new Error(`Handshake failed: ${resp.status}`);
    const enc = await resp.json();
    const plain = await aesGcmDecrypt(aesKey, enc);
    state.sessionId = plain.session_id;
    state.accessToken = plain.access_token;
    state.refreshToken = plain.refresh_token;
    state.sessionAesKeyU8 = aesKey;
    return { ...plain };
  }

  /** Encrypt a payload for stateful mode using stored session AES and append session_id. */
  async function cifradoStateFull(payloadObj) {
    if (!state.sessionId || !state.sessionAesKeyU8) throw new Error('No active session; run handshake/login first.');
    const envelope = await aesGcmEncrypt(state.sessionAesKeyU8, payloadObj);
    return { ...envelope, session_id: state.sessionId };
  }

  /** Decrypt a server response in stateful mode using stored session AES. */
  async function descifradoStateFull(responseEnvelope) {
    if (!state.sessionAesKeyU8) throw new Error('Missing session AES key.');
    return await aesGcmDecrypt(state.sessionAesKeyU8, responseEnvelope);
  }

  /** Encrypt a payload for stateless mode; includes X-EC-Envelope header with ECIES AES transport. */
  async function cifradoStateLess(payloadObj) {
    const aesKey = generateAes256Key();
    const ecEnv = await buildEcEnvelope(state.serverEcPublicB64, aesKey);
    const envelope = await aesGcmEncrypt(aesKey, payloadObj);
    const headerJson = JSON.stringify({
      ephemeral_public_key: ecEnv.ephemeral_public_key,
      nonce: ecEnv.nonce,
      ciphertext: ecEnv.ciphertext,
      tag: ecEnv.tag
    });
    const headerValue = btoa(headerJson);
    return { envelope, headerValue, aesKey };
  }

  /** Decrypt a server response in stateless mode with the per-request AES key used. */
  async function descifradoStateLess(responseEnvelope, aesKey) {
    return await aesGcmDecrypt(aesKey, responseEnvelope);
  }

  /** Generic API call that chooses stateful/stateless encryption automatically. */
  async function apiCall(path, payloadObj) {
    const url = `${state.serverBaseUrl}${path.startsWith('/')? '': '/'}${path}`;
    if (state.apiCryptoMode === 'stateless') {
      const { envelope, headerValue, aesKey } = await cifradoStateLess(payloadObj);
      const resp = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-EC-Envelope': headerValue,
          ...(state.accessToken ? {'Authorization': `Bearer ${state.accessToken}`} : {})
        },
        body: JSON.stringify(envelope)
      });
      if (!resp.ok) throw new Error(`apiCall stateless failed: ${resp.status}`);
      const enc = await resp.json();
      return await descifradoStateLess(enc, aesKey);
    } else {
      const encBody = await cifradoStateFull(payloadObj);
      const resp = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(state.accessToken ? {'Authorization': `Bearer ${state.accessToken}`} : {})
        },
        body: JSON.stringify(encBody)
      });
      if (!resp.ok) throw new Error(`apiCall stateful failed: ${resp.status}`);
      const enc = await resp.json();
      return await descifradoStateFull(enc);
    }
  }

  /** Register wrapper: encrypts payload and stores returned tokens (via stateful response). */
  async function registerCall(email, username, password) {
    const plain = await apiCall('/register', { email, username, password });
    if (plain.access_token) state.accessToken = plain.access_token;
    if (plain.refresh_token) state.refreshToken = plain.refresh_token;
    return plain;
  }

  /** Login wrapper: encrypts payload and stores returned tokens (via stateful response). */
  async function loginCall(usernameOrEmail, password) {
    const plain = await apiCall('/login', { username_or_email: usernameOrEmail, password });
    if (plain.access_token) state.accessToken = plain.access_token;
    if (plain.refresh_token) state.refreshToken = plain.refresh_token;
    return plain;
  }

  /** Refresh wrapper: uses refresh token to get a new access token. */
  async function refreshCall() {
    if (!state.refreshToken) throw new Error('No refresh token available.');
    const plain = await apiCall('/refresh', { refresh_token: state.refreshToken });
    if (plain.access_token) state.accessToken = plain.access_token;
    return plain;
  }

  /** Logout wrapper: revokes refresh + server session; clears local state. */
  async function logoutCall() {
    await apiCall('/logout', { refresh_token: state.refreshToken || null });
    state.sessionId = null; state.sessionAesKeyU8 = null;
    state.accessToken = null; state.refreshToken = null;
    return { ok: true };
  }

  /** Example: echo wrapper for quick testing. */
  async function echoCall(obj) {
    return await apiCall('/echo', obj);
  }

  /** Export a minimal public API. */
  root.AuthClient = {
    /** Set base URL and crypto mode ("stateful" | "stateless"); fetch server keys. */
    config,
    /** Perform server handshake to obtain session_id and tokens, storing session AES. */
    handshake,
    /** Encrypted API helpers selecting mode automatically. */
    apiCall,
    registerCall,
    loginCall,
    refreshCall,
    logoutCall,
    echoCall,
    /** Access to some state (read-only copies). */
    getState: () => ({
      serverBaseUrl: state.serverBaseUrl,
      apiCryptoMode: state.apiCryptoMode,
      sessionId: state.sessionId,
      accessToken: state.accessToken,
      refreshToken: state.refreshToken
    })
  };

})(typeof window !== 'undefined' ? window : global);
