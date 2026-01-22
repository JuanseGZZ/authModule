// Api.js
import { AUTH_BASE_URL } from "./Env.js";

export const LOGIN_PATH = "/v1/auth/login";
export const REGISTER_PATH = "/v1/auth/register";
export const REFRESH_PATH = "/v1/auth/refresh";
export const UNLOGIN_PATH = "/v1/auth/unlogin";

async function postJson(path, body) {
  const url = AUTH_BASE_URL + path;

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {})
  });

  let data;
  try {
    data = await res.json();
  } catch {
    const text = await res.text();
    throw new Error(`Error HTTP ${res.status}. Respuesta no JSON: ${text}`);
  }

  if (!res.ok) {
    const msg = data?.detail || data?.error || data?.message || `Error HTTP ${res.status}`;
    const err = new Error(msg);
    err.status = res.status;
    err.payload = data;
    throw err;
  }

  return data;
}

export function loginFetch(body)    { return postJson(LOGIN_PATH, body); }
export function registerFetch(body) { return postJson(REGISTER_PATH, body); }
export function refreshFetch(body)  { return postJson(REFRESH_PATH, body); }
export function unloginFetch(body)  { return postJson(UNLOGIN_PATH, body); }
