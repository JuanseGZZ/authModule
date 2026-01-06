// crypto/Base64Url.js

// Base64 URL-safe SIN padding '='
// Compatible 1:1 con base64.urlsafe_b64encode(...).rstrip("=")

export function b64uEncode(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error("b64uEncode: bytes debe ser Uint8Array");
  }

  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  let base64 = btoa(binary);

  // url-safe + sin padding
  return base64
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function b64uDecode(str) {
  if (typeof str !== "string") {
    throw new Error("b64uDecode: input debe ser string");
  }

  // revertir url-safe
  let base64 = str
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  // restaurar padding
  const pad = base64.length % 4;
  if (pad !== 0) {
    base64 += "=".repeat(4 - pad);
  }

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}
