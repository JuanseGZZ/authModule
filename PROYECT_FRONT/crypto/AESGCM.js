// crypto/AESGCM.js

// AES-GCM 256 bits
// keyBytes: Uint8Array(32)
// iv: Uint8Array(12)
// plaintext / ciphertext: Uint8Array

async function importAesKey(keyBytes) {
  if (!(keyBytes instanceof Uint8Array) || keyBytes.length !== 32) {
    throw new Error("AESGCM: keyBytes debe ser Uint8Array(32)");
  }

  return crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function aesGcmEncrypt(keyBytes, iv, plaintext) {
  if (!(iv instanceof Uint8Array) || iv.length !== 12) {
    throw new Error("aesGcmEncrypt: iv debe ser Uint8Array(12)");
  }
  if (!(plaintext instanceof Uint8Array)) {
    throw new Error("aesGcmEncrypt: plaintext debe ser Uint8Array");
  }

  const key = await importAesKey(keyBytes);

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
      tagLength: 128,
    },
    key,
    plaintext
  );

  return new Uint8Array(ciphertext);
}

export async function aesGcmDecrypt(keyBytes, iv, ciphertext) {
  if (!(iv instanceof Uint8Array) || iv.length !== 12) {
    throw new Error("aesGcmDecrypt: iv debe ser Uint8Array(12)");
  }
  if (!(ciphertext instanceof Uint8Array)) {
    throw new Error("aesGcmDecrypt: ciphertext debe ser Uint8Array");
  }

  const key = await importAesKey(keyBytes);

  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
      tagLength: 128,
    },
    key,
    ciphertext
  );

  return new Uint8Array(plaintext);
}
