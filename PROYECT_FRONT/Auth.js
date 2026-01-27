// este va a llevar todo el core de la app

function generateAES() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode(...arr));
}

// Auth.js
import { AuthService } from "./Services.js";
import { Session, getSessionOrNull, setSessionFromDecoded, clearSession } from "./ModelSession.js"
import "./Env.js"
import { StatefulEnabled } from "./Env.js";
import { startAutoRefresh, stopAutoRefresh } from "./autoRefresh.js";

const auth = new AuthService();

export async function login(email, username, password) {
  // unlogeamos lo que haya si hay
  const s = getSessionOrNull();
  if (s) {
    logout();
  }

  const session = await auth.login({
    email,
    username,
    password,
    aeskey: generateAES()
  });
  setSessionFromDecoded(session);
  if (StatefulEnabled) {
    // iniciar el contador de autorefresh si es stateful
    startAutoRefresh();
  }
}

export async function register(email, username, password) {
  // unlogeamos lo que haya si hay
  const s = getSessionOrNull();
  if (s) {
    logout();
  }

  const session = await auth.register({
    email,
    username,
    password,
    aeskey: generateAES()
  });
  setSessionFromDecoded(session);
  if (StatefulEnabled) {
    // iniciar el contador de autorefresh si es stateful
    startAutoRefresh();
  }
}

export async function logout() {
  const s = getSessionOrNull();
  if (!s) return false;

  stopAutoRefresh();

  try {
    if (StatefulEnabled) {
      return await auth.unloginStateful({
        user_id: s.user_id,
        aes_old: s.aes,
        refresh_token: s.refresh_token
      });
    }

    return await auth.unloginStateless({
      aeskey: s.aes,
      refresh_token: s.refresh_token
    });
  } finally {
    clearSession();
  }
}

import { Packet } from "./ModelPacket.js";

export async function sendStateful(url, data = {}, files = []) {
  const activeSession = getSessionOrNull();

  if (!activeSession) {
    throw new Error("sendStateful: no hay sesion activa. Hace login/register primero.");
  }

  const statefulPacket = new Packet({
    refresh_token: activeSession.refresh_token,
    access_token: activeSession.access_token,
    data: data || {},
    aes_key: activeSession.aes,
    user_id: activeSession.user_id,
    files: files || []
  });

  const encryptedRequestPacket = await statefulPacket.encryptAES();

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(encryptedRequestPacket)
  });

  let encryptedResponsePacket;
  try {
    encryptedResponsePacket = await response.json();
  } catch {
    const text = await response.text();
    throw new Error(`sendStateful: HTTP ${response.status}. Respuesta no JSON: ${text}`);
  }

  if (!response.ok) {
    const errorMessage =
      encryptedResponsePacket?.detail ||
      encryptedResponsePacket?.error ||
      encryptedResponsePacket?.message ||
      `sendStateful: HTTP ${response.status}`;
    throw new Error(errorMessage);
  }

  const decryptedResponse = await Packet.decryptAES(
    encryptedResponsePacket,
    activeSession.aes
  );

  return decryptedResponse;
}

export async function sendStateless(url, data = {}, files = []) {
  const activeSession = getSessionOrNull();

  const perRequestAesKey = generateAES();

  // payload cifrado con AES (refresh/access/data/files)
  const encryptedPayloadOnly = await auth._encryptPayloadOnly({
    aeskey: perRequestAesKey,
    refresh_token: activeSession ? activeSession.refresh_token : "",
    access_token: activeSession ? activeSession.access_token : "",
    data: data || {}
  });

  // AES cifrada con RSA
  const rsaEncryptedAesKey = await auth._rsaEncryptJsonB64u({ aeskey: perRequestAesKey });

  // estructura stateless segun tu spec: aes siempre presente
  const statelessRequestPacket = {
    user_id: "0",
    iv: encryptedPayloadOnly.iv,
    ciphertext: encryptedPayloadOnly.ciphertext,
    aes: {
      iv: "AAAAAAAAAA",
      ciphertext: rsaEncryptedAesKey
    }
  };

  if (files && files.length > 0) {
    statelessRequestPacket.files = await encryptFiles(files, perRequestAesKey);
  }

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(statelessRequestPacket)
  });

  let encryptedResponsePacket;
  try {
    encryptedResponsePacket = await response.json();
  } catch {
    const text = await response.text();
    throw new Error(`sendStateless: HTTP ${response.status}. Respuesta no JSON: ${text}`);
  }

  if (!response.ok) {
    const errorMessage =
      encryptedResponsePacket?.detail ||
      encryptedResponsePacket?.error ||
      encryptedResponsePacket?.message ||
      `sendStateless: HTTP ${response.status}`;
    throw new Error(errorMessage);
  }

  // Si el server responde stateless "aes" como RSA, NO es AES-en-AES. Lo sacamos antes de decryptAES.
  const responsePacketForDecrypt = { ...encryptedResponsePacket };
  if (
    responsePacketForDecrypt.aes &&
    typeof responsePacketForDecrypt.aes === "object" &&
    responsePacketForDecrypt.aes.iv === "AAAAAAAAAA" &&
    typeof responsePacketForDecrypt.aes.ciphertext === "string"
  ) {
    delete responsePacketForDecrypt.aes;
  }

  const decryptedResponse = await Packet.decryptAES(
    responsePacketForDecrypt,
    perRequestAesKey
  );

  return decryptedResponse;
}

/* TESTING */
async function test() {
  // AES "de prueba": en serio, en prod debe ser random y guardada por usuario/sesion.
  const aeskey = "12345678901234567890123456789012"; // 32 chars

  const email = "supertransman@hotmail.com";
  const username = email.split("@")[0];
  const password = "1234";

  //console.log("Registrando:", { email, username, password });

  //const reg = await auth.register({
  //  email,
  //  username,
  //  password,
  //  aeskey
  //});

  //console.log("REGISTER DEC:", reg);

  const login = await auth.login({
    emailOrUsername: email,
    password: password,
    aeskey
  });
  console.log("LOGIN DEC:", login);
  setSessionFromDecoded(login)

  alert("wait para ver");

  let session = getSessionOrNull();
  let aes = session.aes;
  let userid = session.user_id;
  let acces = session.access_token;
  let refreshToken = session.refresh_token;

  console.log(session);
  console.log(aes);

  const refresh = await auth.refreshStateful({
    user_id: userid,
    aes_old: aes,
    refresh_token: refreshToken
  });
  console.log("REFRESH DEC:", refresh);
  setSessionFromDecoded(refresh)

  session = getSessionOrNull();
  aes = session.aes;
  console.log("aes: " + aes);
  userid = session.user_id;
  acces = session.access_token;
  refreshToken = session.refresh_token;

  const unlog = await logout({
    user_id: userid,
    aes_old: aes,
    refresh_token: refreshToken,
  });
  console.log(unlog);

  clearSession(refresh)
};
